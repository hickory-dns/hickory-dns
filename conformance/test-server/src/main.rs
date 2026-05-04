use std::{
    net::{IpAddr, SocketAddr},
    sync::OnceLock,
};

#[cfg(test)]
use anyhow::Context;
use anyhow::Result;
use async_trait::async_trait;
use clap::{Parser, Subcommand, ValueEnum};
use futures::{StreamExt, future};
use hickory_net::{DnsStreamHandle, runtime::iocompat::AsyncIoTokioAsStd, tcp::TcpStream};
use hickory_proto::{
    op::{Message, SerialMessage},
    rr::{Name, RecordType},
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
            Self::Bailiwick => &bailiwick_handler,
            Self::Base => &base_handler,
            Self::BadCase => &bad_case_handler,
            Self::BadTxid => &bad_txid_handler,
            Self::CnameLoop => &cname_loop_handler,
            Self::EmptyResponse => &empty_response_handler,
            Self::Nsec3Nocover => &nsec3_nocover_handler,
            Self::ParentNsInAuthority => &parent_ns_in_authority_handler,
            Self::PacketLoss => &packet_loss_handler,
            Self::TruncatedResponse => &truncated_response_handler,
            Self::QrNotResponse => &qr_not_response_handler,
            Self::QrNotResponseForceTcp => &qr_not_response_force_tcp_handler,
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

#[derive(Debug)]
enum Transport {
    Tcp,
    Udp,
}

#[async_trait]
trait Handler: Send + Sync {
    async fn handle(&self, bytes: &[u8], transport: Transport) -> Result<Option<Vec<u8>>>;
}

#[async_trait]
impl<T> Handler for T
where
    T: (Fn(&[u8], Transport) -> Result<Option<Vec<u8>>>) + Send + Sync + 'static,
{
    async fn handle(&self, bytes: &[u8], transport: Transport) -> Result<Option<Vec<u8>>> {
        self(bytes, transport)
    }
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

    use crate::{Transport, base_handler};

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
        let _handle = tokio::spawn(tcp.run(&base_handler));

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
                let _handle = tokio::spawn(tcp.run(&base_handler));
                let (future, sender) =
                    TcpClientStream::new(tcp_peer, None, None, TokioRuntimeProvider::new());
                let (client, bg) = Client::<TokioRuntimeProvider>::new(future.await?, sender);
                let _handle = tokio::spawn(bg);
                client
            }
            Transport::Udp => {
                let udp = super::UdpServer::new(socket).await?;
                let udp_peer = udp.addr()?;
                let _handle = tokio::spawn(udp.run(&base_handler));
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
