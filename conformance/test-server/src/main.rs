use std::{net::SocketAddr, sync::Arc};

#[cfg(test)]
use anyhow::Context;
use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use futures::{StreamExt, future};
use hickory_net::{DnsStreamHandle, runtime::iocompat::AsyncIoTokioAsStd, tcp::TcpStream};
use hickory_proto::op::{Message, SerialMessage};
use tokio::net::{TcpListener, UdpSocket};

mod handlers;
mod zone_file;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let transport = args.transport;
    let handler: Arc<dyn HandlerFn> = match args.handler {
        Handler::Bailiwick => Arc::new(handlers::bailiwick_handler),
        Handler::Base => Arc::new(handlers::base_handler),
        Handler::BadCase => Arc::new(handlers::bad_case_handler),
        Handler::BadTxid => Arc::new(handlers::bad_txid_handler),
        Handler::CnameLoop => Arc::new(handlers::cname_loop_handler),
        Handler::EmptyResponse => Arc::new(handlers::empty_response_handler),
        Handler::Nsec3Nocover => Arc::new(handlers::nsec3_nocover_handler),
        Handler::ParentNsInAuthority => Arc::new(handlers::parent_ns_in_authority_handler),
        Handler::PacketLoss => Arc::new(handlers::packet_loss_handler),
        Handler::TruncatedResponse => Arc::new(handlers::truncated_response_handler),
        Handler::QrNotResponse => Arc::new(handlers::qr_not_response_handler),
        Handler::QrNotResponseForceTcp => Arc::new(handlers::qr_not_response_force_tcp_handler),
    };

    let mut handles = vec![];
    if transport == TransportArg::Tcp || transport == TransportArg::Both {
        let tcp = TcpServer::new(([0, 0, 0, 0], args.port).into()).await?;
        let handler = handler.clone();
        handles.push(tokio::task::spawn(async move { tcp.run(handler).await }));
    }
    if transport == TransportArg::Udp || transport == TransportArg::Both {
        let udp = UdpServer::new(([0, 0, 0, 0], args.port).into()).await?;
        handles.push(tokio::task::spawn(async move { udp.run(handler).await }));
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
    handler: Handler,
}

#[derive(Clone, PartialEq, Eq, ValueEnum)]
enum TransportArg {
    Tcp,
    Udp,
    Both,
}

#[derive(Clone, Subcommand)]
#[clap(rename_all = "snake_case")]
enum Handler {
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
}

struct UdpServer {
    udp: UdpSocket,
}

impl UdpServer {
    async fn new(bind_addr: SocketAddr) -> Result<Self> {
        Ok(Self {
            udp: UdpSocket::bind(bind_addr).await?,
        })
    }

    async fn run(self, handler: Arc<dyn HandlerFn>) -> Result<()> {
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

            match handler(&read_buf[0..len], Transport::Udp) {
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

    async fn run(self, handler: Arc<dyn HandlerFn>) -> Result<()> {
        loop {
            let (stream, peer) = self.tcp.accept().await?;
            let handler = handler.clone();
            tokio::task::spawn(async move {
                let (mut stream, mut sender) =
                    TcpStream::from_stream(AsyncIoTokioAsStd(stream), peer);

                while let Some(Ok(msg)) = stream.next().await {
                    println!(
                        "client request from tcp/{peer}: {:?}",
                        Message::from_vec(msg.bytes())
                    );

                    let resp = match handler(msg.bytes(), Transport::Tcp) {
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

trait HandlerFn: (Fn(&[u8], Transport) -> Result<Option<Vec<u8>>>) + Send + Sync + 'static {}

impl<T> HandlerFn for T where
    T: (Fn(&[u8], Transport) -> Result<Option<Vec<u8>>>) + Send + Sync + 'static
{
}

#[cfg(test)]
mod test {
    use std::{
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        str::FromStr,
        sync::Arc,
    };

    use anyhow::Result;
    use hickory_net::{
        client::{Client, ClientHandle},
        runtime::TokioRuntimeProvider,
        tcp::TcpClientStream,
        udp::UdpClientStream,
    };
    use hickory_proto::rr::{DNSClass, RData, RecordType, domain::Name, rdata};

    use crate::{Transport, handlers::base_handler};

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
        let _handle = tokio::task::spawn(tcp.run(Arc::new(base_handler)));

        let (future, sender) =
            TcpClientStream::new(tcp_peer, None, None, TokioRuntimeProvider::new());

        let (mut client, bg) = Client::<TokioRuntimeProvider>::new(future.await?, sender);
        let _handle = tokio::task::spawn(bg);

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
                let _handle = tokio::task::spawn(tcp.run(Arc::new(base_handler)));
                let (future, sender) =
                    TcpClientStream::new(tcp_peer, None, None, TokioRuntimeProvider::new());
                let (client, bg) = Client::<TokioRuntimeProvider>::new(future.await?, sender);
                let _handle = tokio::task::spawn(bg);
                client
            }
            Transport::Udp => {
                let udp = super::UdpServer::new(socket).await?;
                let udp_peer = udp.addr()?;
                let _handle = tokio::task::spawn(udp.run(Arc::new(base_handler)));
                let conn = UdpClientStream::builder(udp_peer, TokioRuntimeProvider::new()).build();
                let (client, bg) = Client::from_sender(conn);
                let _handle = tokio::task::spawn(bg);
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
