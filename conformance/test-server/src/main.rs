use std::net::SocketAddr;

#[cfg(test)]
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use futures::{StreamExt, future};
use hickory_proto::{
    DnsStreamHandle,
    op::{Message, SerialMessage},
    runtime::iocompat::AsyncIoTokioAsStd,
    tcp::TcpStream,
};
use tokio::net::{TcpListener, UdpSocket};

mod handlers;
mod zone_file;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let transport = args.transport;
    let handler = match &args.handler[..] {
        "bailiwick" => handlers::bailiwick_handler,
        "base" => handlers::base_handler,
        "bad_case" => handlers::bad_case_handler,
        "bad_txid" => handlers::bad_txid_handler,
        "cname_loop" => handlers::cname_loop_handler,
        "empty_response" => handlers::empty_response_handler,
        "nsec3_nocover" => handlers::nsec3_nocover_handler,
        "packet_loss" => handlers::packet_loss_handler,
        "truncated_response" => handlers::truncated_response_handler,
        _ => {
            return Err(anyhow::Error::msg("unknown handler"));
        }
    };

    let mut handles = vec![];
    if transport == "tcp" || transport == "both" {
        let tcp = TcpServer::new(([0, 0, 0, 0], args.port).into()).await?;
        handles.push(tokio::task::spawn(async move { tcp.run(handler).await }));
    }
    if transport == "udp" || transport == "both" {
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
    #[clap(default_value = "base", long = "handler")]
    handler: String,
    #[clap(default_value = "53", long = "port")]
    port: u16,
    #[clap(default_value = "both", long = "transport")]
    transport: String,
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

    async fn run(self, handler: HandlerFn) -> Result<()> {
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

    async fn run(self, handler: HandlerFn) -> Result<()> {
        loop {
            let (stream, peer) = self.tcp.accept().await?;
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

type HandlerFn = fn(&[u8], Transport) -> Result<Option<Vec<u8>>>;

#[cfg(test)]
mod test {
    use std::{
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        str::FromStr,
    };

    use anyhow::Result;
    use hickory_client::client::{Client, ClientHandle};
    use hickory_proto::{
        rr::{DNSClass, RData, RecordType, domain::Name, rdata},
        runtime::TokioRuntimeProvider,
        tcp::TcpClientStream,
        udp::UdpClientStream,
    };

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
        let _handle = tokio::task::spawn(tcp.run(base_handler));

        let (stream, sender) =
            TcpClientStream::new(tcp_peer, None, None, TokioRuntimeProvider::new());

        let client = Client::<TokioRuntimeProvider>::new(stream, sender, None);
        let (mut client, bg) = client.await?;

        let _handle = tokio::task::spawn(bg);

        let query = client.query(
            Name::from_str("foo.example.com.").unwrap(),
            DNSClass::IN,
            RecordType::A,
        );

        let response = query.await.unwrap();
        if let RData::A(addr) = response.answers()[0].data() {
            assert_eq!(*addr, rdata::A::new(192, 0, 2, 1));
        }

        let query = client.query(
            Name::from_str("bar.example.com.").unwrap(),
            DNSClass::IN,
            RecordType::A,
        );

        let response = query.await.unwrap();
        if let RData::A(addr) = response.answers()[0].data() {
            assert_eq!(*addr, rdata::A::new(192, 0, 2, 1));
        }

        Ok(())
    }

    async fn basic_test(socket: SocketAddr, transport: Transport) -> Result<()> {
        let mut client = match transport {
            Transport::Tcp => {
                let tcp = super::TcpServer::new(socket).await?;
                let tcp_peer = tcp.addr()?;
                let _handle = tokio::task::spawn(tcp.run(base_handler));
                let (stream, sender) =
                    TcpClientStream::new(tcp_peer, None, None, TokioRuntimeProvider::new());
                let (client, bg) =
                    Client::<TokioRuntimeProvider>::new(stream, sender, None).await?;
                let _handle = tokio::task::spawn(bg);
                client
            }
            Transport::Udp => {
                let udp = super::UdpServer::new(socket).await?;
                let udp_peer = udp.addr()?;
                let _handle = tokio::task::spawn(udp.run(base_handler));
                let conn = UdpClientStream::builder(udp_peer, TokioRuntimeProvider::new()).build();
                let (client, bg) = Client::connect(conn).await?;
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
        if let RData::A(addr) = response.answers()[0].data() {
            assert_eq!(*addr, rdata::A::new(192, 0, 2, 1));
        }

        Ok(())
    }
}
