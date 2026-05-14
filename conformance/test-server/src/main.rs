use std::{
    net::{IpAddr, SocketAddr},
    sync::OnceLock,
};

use anyhow::Context;
use anyhow::Result;
use async_trait::async_trait;
use clap::{Parser, Subcommand, ValueEnum};
use futures::{StreamExt, future};
use hickory_net::{DnsStreamHandle, runtime::iocompat::AsyncIoTokioAsStd, tcp::TcpStream};
use hickory_proto::{
    op::{Message, SerialMessage},
    rr::{Name, RecordType},
    serialize::binary::{BinEncodable, BinEncoder},
};
use tokio::net::{TcpListener, UdpSocket};

mod handlers;
use handlers::{
    BogusNoDataInsteadOfCname, DropRrsetHandler, bad_case_handler, bad_txid_handler,
    bailiwick_handler, base_handler, cname_loop_handler, empty_response_handler,
    nsec3_nocover_handler, packet_loss_handler, parent_ns_in_authority_handler,
    qr_not_response_force_tcp_handler, qr_not_response_handler, truncated_response_handler,
};
mod zone_file;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let transport = args.transport;
    let handler = args.handler.into_handler();

    let mut handles = vec![];
    if transport == TransportArg::Tcp || transport == TransportArg::Both {
        let tcp = TcpServer::new(([0, 0, 0, 0], args.port).into()).await?;
        handles.push(tokio::spawn(async move { tcp.run(handler).await }));
    }
    if transport == TransportArg::Udp || transport == TransportArg::Both {
        let udp = UdpServer::new(([0, 0, 0, 0], args.port).into()).await?;
        handles.push(tokio::spawn(async move { udp.run(handler).await }));
    }

    println!("TEST SERVER STARTED");
    let _ = future::join_all(handles).await;

    Ok(())
}

#[derive(Parser)]
#[clap(name = "Message responder test DNS server")]
struct Args {
    #[clap(default_value = "53", long = "port")]
    port: u16,
    #[clap(default_value = "both", long = "transport")]
    transport: TransportArg,
    #[clap(subcommand)]
    handler: HandlerArg,
}

#[derive(Clone, PartialEq, Eq, ValueEnum)]
enum TransportArg {
    Tcp,
    Udp,
    Both,
}

#[derive(Clone, Subcommand)]
#[clap(rename_all = "snake_case")]
enum HandlerArg {
    Bailiwick,
    Base,
    BadCase,
    BadTxid,
    CnameLoop,
    EmptyResponse,
    Nsec3Nocover,
    ParentNsInAuthority,
    PacketLoss,
    TruncatedResponse,
    QrNotResponse,
    QrNotResponseForceTcp,
    DropRrset {
        ip_address: IpAddr,
        name: Name,
        record_type: RecordType,
    },
    BogusNoDataInsteadOfCname {
        ip_address: IpAddr,
    },
}

impl HandlerArg {
    fn into_handler(self) -> &'static dyn Handler {
        match self {
            Self::Bailiwick => &(bailiwick_handler as HandlerMessageFnPtr),
            Self::Base => &(base_handler as HandlerMessageFnPtr),
            Self::BadCase => &(bad_case_handler as HandlerMessageFnPtr),
            Self::BadTxid => &(bad_txid_handler as HandlerMessageFnPtr),
            Self::CnameLoop => &(cname_loop_handler as HandlerMessageFnPtr),
            Self::EmptyResponse => &(empty_response_handler as HandlerMessageFnPtr),
            Self::Nsec3Nocover => &(nsec3_nocover_handler as HandlerMessageFnPtr),
            Self::ParentNsInAuthority => &(parent_ns_in_authority_handler as HandlerMessageFnPtr),
            Self::PacketLoss => &(packet_loss_handler as HandlerBytesFnPtr),
            Self::TruncatedResponse => &(truncated_response_handler as HandlerMessageFnPtr),
            Self::QrNotResponse => &(qr_not_response_handler as HandlerMessageFnPtr),
            Self::QrNotResponseForceTcp => {
                &(qr_not_response_force_tcp_handler as HandlerMessageFnPtr)
            }
            Self::DropRrset {
                ip_address,
                name,
                record_type,
            } => DROP_HANDLER.get_or_init(|| DropRrsetHandler::new(ip_address, name, record_type)),
            Self::BogusNoDataInsteadOfCname { ip_address } => BOGUS_NO_DATA_CNAME_HANDLER
                .get_or_init(|| BogusNoDataInsteadOfCname::new(ip_address)),
        }
    }
}

static DROP_HANDLER: OnceLock<DropRrsetHandler> = OnceLock::new();
static BOGUS_NO_DATA_CNAME_HANDLER: OnceLock<BogusNoDataInsteadOfCname> = OnceLock::new();

struct UdpServer {
    udp: UdpSocket,
}

impl UdpServer {
    async fn new(bind_addr: SocketAddr) -> Result<Self> {
        Ok(Self {
            udp: UdpSocket::bind(bind_addr).await?,
        })
    }

    async fn run(self, handler: &'static dyn Handler) -> Result<()> {
        loop {
            let mut read_buf = [0u8; 4096];
            let (len, to) = match self.udp.recv_from(&mut read_buf).await {
                Ok((len, to)) => (len, to),
                Err(e) => {
                    println!("read error: {e:?}");
                    continue;
                }
            };

            println!(
                "client request from udp/{to}: {:?}",
                Message::from_vec(&read_buf),
            );

            match handler.handle(&read_buf[0..len], Transport::Udp).await {
                Ok(Some(resp)) => {
                    println!(
                        "handler response to udp/{to}: {:?}",
                        Message::from_vec(&resp),
                    );
                    if let Err(e) = self.udp.send_to(&resp[..], to).await {
                        println!("error sending response: {e:?}");
                    }
                }
                Ok(None) => {
                    println!("no response returned from handler for request from {to}");
                }
                Err(e) => {
                    println!("error {e:?} returned from read handler for request from {to}");
                }
            };
        }
    }

    #[cfg(test)]
    fn addr(&self) -> Result<SocketAddr> {
        self.udp
            .local_addr()
            .with_context(|| "unable to get local address".to_string())
    }
}

struct TcpServer {
    tcp: TcpListener,
}

impl TcpServer {
    async fn new(bind_addr: SocketAddr) -> Result<Self> {
        Ok(Self {
            tcp: TcpListener::bind(bind_addr).await?,
        })
    }

    async fn run(self, handler: &'static dyn Handler) -> Result<()> {
        loop {
            let (stream, peer) = self.tcp.accept().await?;
            tokio::spawn(async move {
                let (mut stream, mut sender) =
                    TcpStream::from_stream(AsyncIoTokioAsStd(stream), peer);

                while let Some(Ok(msg)) = stream.next().await {
                    println!(
                        "client request from tcp/{peer}: {:?}",
                        Message::from_vec(msg.bytes())
                    );

                    let resp = match handler.handle(msg.bytes(), Transport::Tcp).await {
                        Ok(Some(resp)) => resp,
                        Ok(None) => {
                            println!("no response returned from handler for request from {peer}");
                            continue;
                        }
                        Err(e) => {
                            println!(
                                "error {e:?} returned from read handler for request from {peer}"
                            );
                            break;
                        }
                    };

                    println!(
                        "handler response to tcp/{peer}: {:?}",
                        Message::from_vec(&resp)
                    );

                    if let Err(e) = sender.send(SerialMessage::new(resp.to_vec(), peer)) {
                        println!("error sending response to {peer}: {e:?}");
                    }
                }
            });
        }
    }

    #[cfg(test)]
    fn addr(&self) -> Result<SocketAddr> {
        self.tcp
            .local_addr()
            .with_context(|| "unable to get local address".to_string())
    }
}

#[derive(Debug, Clone, Copy)]
enum Transport {
    Tcp,
    Udp,
}

#[async_trait]
trait Handler: Send + Sync {
    async fn handle(&self, bytes: &[u8], transport: Transport) -> Result<Option<Vec<u8>>>;
}

/// Synchronous handler function that operates on byte arrays.
type HandlerBytesFnPtr = fn(&[u8], Transport) -> Result<Option<Vec<u8>>>;

/// Implementation for function pointers using raw byte arrays.
///
/// This allows for maximal flexibility, including improperly encoded messages, direct control over
/// the truncation flag, and failing to respond to queries. Asynchronous operations are not
/// supported, so this cannot be used to proxy requests to another server.
#[async_trait]
impl Handler for HandlerBytesFnPtr {
    async fn handle(&self, bytes: &[u8], transport: Transport) -> Result<Option<Vec<u8>>> {
        self(bytes, transport)
    }
}

/// Synchronous handler function that operates on messages.
type HandlerMessageFnPtr = fn(Message, Transport) -> Result<Message>;

/// Implementation for function pointers using [`Message`] structs.
///
/// This handles common message decoding and encoding before and after calling the function,
/// including setting the truncation flag when necessary.
#[async_trait]
impl Handler for HandlerMessageFnPtr {
    async fn handle(&self, bytes: &[u8], transport: Transport) -> Result<Option<Vec<u8>>> {
        let request = Message::from_vec(bytes)?;
        let max_message_size = max_message_size(&request, transport);
        let response_msg = self(request, transport)?;
        Ok(Some(encode_response(&response_msg, max_message_size)?))
    }
}

/// Chooses the maximum message size based on the EDNS(0) OPT pseudo-record and the transport
/// protocol.
fn max_message_size(message: &Message, transport: Transport) -> u16 {
    match (transport, &message.edns) {
        (Transport::Tcp, _) => u16::MAX,
        (Transport::Udp, Some(edns)) => edns.max_payload(),
        (Transport::Udp, None) => 512,
    }
}

/// Serialize a message, with the given size limit.
fn encode_response(message: &Message, max_message_size: u16) -> Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(max_message_size as usize);
    let mut encoder = BinEncoder::new(&mut buffer);
    encoder.set_max_size(max_message_size);
    message
        .emit(&mut encoder)
        .context("could not serialize Message")?;
    Ok(buffer)
}

#[cfg(test)]
mod test {
    use std::{
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        str::FromStr,
    };

    use anyhow::Result;
    use hickory_net::{
        client::{Client, ClientHandle},
        runtime::TokioRuntimeProvider,
        tcp::TcpClientStream,
        udp::UdpClientStream,
    };
    use hickory_proto::rr::{DNSClass, RData, RecordType, domain::Name, rdata};

    use crate::{HandlerArg, Transport};

    #[tokio::test]
    async fn tcp_msg() -> Result<()> {
        basic_test((Ipv4Addr::LOCALHOST, 0).into(), Transport::Tcp).await
    }

    #[tokio::test]
    async fn ipv6_tcp_msg() -> Result<()> {
        basic_test((Ipv6Addr::LOCALHOST, 0).into(), Transport::Tcp).await
    }

    #[tokio::test]
    async fn udp_msg() -> Result<()> {
        basic_test((Ipv4Addr::LOCALHOST, 0).into(), Transport::Udp).await
    }

    #[tokio::test]
    async fn ipv6_udp_msg() -> Result<()> {
        basic_test((Ipv6Addr::LOCALHOST, 0).into(), Transport::Udp).await
    }

    #[tokio::test]
    async fn multiple_tcp_msg() -> Result<()> {
        let tcp = super::TcpServer::new((Ipv4Addr::LOCALHOST, 0).into()).await?;
        let tcp_peer = tcp.addr()?;
        let _handle = tokio::spawn(tcp.run(HandlerArg::Base.into_handler()));

        let (future, sender) =
            TcpClientStream::new(tcp_peer, None, None, TokioRuntimeProvider::new());

        let (mut client, bg) = Client::<TokioRuntimeProvider>::new(future.await?, sender);
        let _handle = tokio::spawn(bg);

        let query = client.query(
            Name::from_str("foo.example.com.").unwrap(),
            DNSClass::IN,
            RecordType::A,
        );

        let response = query.await.unwrap();
        if let RData::A(addr) = response.answers[0].data {
            assert_eq!(addr, rdata::A::new(192, 0, 2, 1));
        }

        let query = client.query(
            Name::from_str("bar.example.com.").unwrap(),
            DNSClass::IN,
            RecordType::A,
        );

        let response = query.await.unwrap();
        if let RData::A(addr) = response.answers[0].data {
            assert_eq!(addr, rdata::A::new(192, 0, 2, 1));
        }

        Ok(())
    }

    async fn basic_test(socket: SocketAddr, transport: Transport) -> Result<()> {
        let mut client = match transport {
            Transport::Tcp => {
                let tcp = super::TcpServer::new(socket).await?;
                let tcp_peer = tcp.addr()?;
                let _handle = tokio::spawn(tcp.run(HandlerArg::Base.into_handler()));
                let (future, sender) =
                    TcpClientStream::new(tcp_peer, None, None, TokioRuntimeProvider::new());
                let (client, bg) = Client::<TokioRuntimeProvider>::new(future.await?, sender);
                let _handle = tokio::spawn(bg);
                client
            }
            Transport::Udp => {
                let udp = super::UdpServer::new(socket).await?;
                let udp_peer = udp.addr()?;
                let _handle = tokio::spawn(udp.run(HandlerArg::Base.into_handler()));
                let conn = UdpClientStream::builder(udp_peer, TokioRuntimeProvider::new()).build();
                let (client, bg) = Client::from_sender(conn);
                let _handle = tokio::spawn(bg);
                client
            }
        };

        let query = client.query(
            Name::from_str("foo.example.com.").unwrap(),
            DNSClass::IN,
            RecordType::A,
        );

        let response = query.await.unwrap();
        if let RData::A(addr) = response.answers[0].data {
            assert_eq!(addr, rdata::A::new(192, 0, 2, 1));
        }

        Ok(())
    }
}
