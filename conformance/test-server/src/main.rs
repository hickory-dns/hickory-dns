use std::{net::SocketAddr, process::exit};

use clap::Parser;
use futures::future;
use hickory_proto::ProtoError;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
};

mod handlers;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let transport = args.transport;
    let handler = match &args.handler[..] {
        "base" => handlers::base_handler,
        "bad_txid" => handlers::bad_txid_handler,
        "empty_response" => handlers::empty_response_handler,
        "truncated_response" => handlers::truncated_response_handler,
        _ => {
            eprintln!("unknown handler");
            exit(1);
        }
    };

    let mut handles = vec![];
    if transport == "tcp" || transport == "both" {
        let (_, tcp_handle) = tcp_server(([0, 0, 0, 0], args.port).into(), handler).await?;
        handles.push(tcp_handle);
    }
    if transport == "udp" || transport == "both" {
        let (_, udp_handle) = udp_server(([0, 0, 0, 0], args.port).into(), handler).await?;
        handles.push(udp_handle);
    }
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

async fn udp_server(
    bind_addr: SocketAddr,
    handler: HandlerFn,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let udp = UdpSocket::bind(bind_addr).await?;
    let peer = udp.local_addr()?;
    let handle = tokio::task::spawn(async move {
        loop {
            let mut buf = [0u8; 4096];
            let to = match udp.recv_from(&mut buf).await {
                Ok((_, to)) => to,
                Err(_) => continue,
            };

            let _ = match handler(&buf, Transport::Udp) {
                Ok(Some(resp)) => udp.send_to(&resp[..], to).await,
                Ok(None) | Err(_) => continue,
            };
        }
    });

    Ok((peer, handle))
}

async fn tcp_server(
    bind_addr: SocketAddr,
    handler: HandlerFn,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let tcp = TcpListener::bind(bind_addr).await?;
    let peer = tcp.local_addr()?;
    let handle = tokio::task::spawn(async move {
        loop {
            let (mut stream, _) = tcp.accept().await.unwrap();
            tokio::task::spawn(async move {
                loop {
                    let mut len = [0u8; 2];
                    match stream.read(&mut len).await {
                        Ok(..) => {}
                        Err(e) => {
                            println!("read error: {e:?}");
                            break;
                        }
                    }
                    let len = u16::from_be_bytes(len) as usize;
                    let mut read_buf = vec![0u8; len];

                    if len == 0 {
                        println!("no message");
                        break;
                    }

                    match stream.read_exact(&mut read_buf).await {
                        Ok(..) => {}
                        Err(e) => {
                            println!("read error: {e:?}");
                            break;
                        }
                    }

                    let resp = match handler(&read_buf, Transport::Tcp) {
                        Ok(Some(resp)) => resp,
                        Ok(None) | Err(_) => break,
                    };

                    let resp_len = (resp.len() as u16).to_be_bytes();

                    match stream.write(&resp_len).await {
                        Ok(_) => {}
                        Err(_) => break,
                    }

                    match stream.write(&resp).await {
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            });
        }
    });
    Ok((peer, handle))
}

enum Transport {
    Tcp,
    Udp,
}

type HandlerFn = fn(&[u8], Transport) -> Result<Option<Vec<u8>>, ProtoError>;

#[cfg(test)]
mod test {
    use hickory_client::client::{Client, ClientHandle};
    use hickory_proto::{
        rr::{DNSClass, RData, RecordType, domain::Name, rdata},
        runtime::TokioRuntimeProvider,
        tcp::TcpClientStream,
        udp::UdpClientStream,
    };

    use std::{
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        str::FromStr,
    };

    use crate::{Transport, handlers::base_handler};

    #[tokio::test]
    async fn tcp_msg() -> std::io::Result<()> {
        basic_test((Ipv4Addr::LOCALHOST, 0).into(), Transport::Tcp).await
    }

    #[tokio::test]
    async fn ipv6_tcp_msg() -> std::io::Result<()> {
        basic_test((Ipv6Addr::LOCALHOST, 0).into(), Transport::Tcp).await
    }

    #[tokio::test]
    async fn udp_msg() -> std::io::Result<()> {
        basic_test((Ipv4Addr::LOCALHOST, 0).into(), Transport::Udp).await
    }

    #[tokio::test]
    async fn ipv6_udp_msg() -> std::io::Result<()> {
        basic_test((Ipv6Addr::LOCALHOST, 0).into(), Transport::Udp).await
    }

    #[tokio::test]
    async fn multiple_tcp_msg() -> std::io::Result<()> {
        let (tcp_peer, _) =
            super::tcp_server((Ipv4Addr::LOCALHOST, 0).into(), base_handler).await?;

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

    async fn basic_test(socket: SocketAddr, transport: Transport) -> std::io::Result<()> {
        let mut client = match transport {
            Transport::Tcp => {
                let (tcp_peer, _) = super::tcp_server(socket, base_handler).await?;
                let (stream, sender) =
                    TcpClientStream::new(tcp_peer, None, None, TokioRuntimeProvider::new());
                let (client, bg) =
                    Client::<TokioRuntimeProvider>::new(stream, sender, None).await?;
                let _handle = tokio::task::spawn(bg);
                client
            }
            Transport::Udp => {
                let (udp_peer, _) = super::udp_server(socket, base_handler).await?;
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
