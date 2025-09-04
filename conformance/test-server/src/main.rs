use std::net::SocketAddr;

use anyhow::Result;
use clap::Parser;
use futures::future;
use hickory_proto::op::Message;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
};

mod handlers;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let transport = args.transport;
    let handler = match &args.handler[..] {
        "base" => handlers::base_handler,
        "bad_case" => handlers::bad_case_handler,
        "bad_txid" => handlers::bad_txid_handler,
        "cname_loop" => handlers::cname_loop_handler,
        "empty_response" => handlers::empty_response_handler,
        "packet_loss" => handlers::packet_loss_handler,
        "truncated_response" => handlers::truncated_response_handler,
        _ => {
            return Err(anyhow::Error::msg("unknown handler"));
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
) -> Result<(SocketAddr, JoinHandle<()>)> {
    let udp = UdpSocket::bind(bind_addr).await?;
    let addr = udp.local_addr()?;
    let handle = tokio::task::spawn(async move {
        loop {
            let mut read_buf = [0u8; 4096];
            let to = match udp.recv_from(&mut read_buf).await {
                Ok((_, to)) => to,
                Err(e) => {
                    println!("read error: {e:?}");
                    continue;
                }
            };

            println!(
                "client request from udp/{}: {:?}",
                to,
                Message::from_vec(&read_buf)
            );

            match handler(&read_buf, Transport::Udp) {
                Ok(Some(resp)) => {
                    println!(
                        "handler response to udp/{}: {:?}",
                        to,
                        Message::from_vec(&resp),
                    );
                    if let Err(e) = udp.send_to(&resp[..], to).await {
                        println!("error sending response: {e:?}");
                    }
                }
                Ok(None) => {
                    println!("no response returned from handler; aborting");
                }
                Err(e) => {
                    println!("error {e:?} returned from read handler; aborting");
                }
            };
        }
    });

    Ok((addr, handle))
}

async fn tcp_server(
    bind_addr: SocketAddr,
    handler: HandlerFn,
) -> Result<(SocketAddr, JoinHandle<()>)> {
    let tcp = TcpListener::bind(bind_addr).await?;
    let addr = tcp.local_addr()?;
    let handle = tokio::task::spawn(async move {
        loop {
            let (mut stream, peer) = tcp.accept().await.unwrap();
            tokio::task::spawn(async move {
                loop {
                    let mut len = [0u8; 2];
                    match stream.read_exact(&mut len).await {
                        Ok(..) => {}
                        Err(e) if e.kind() != std::io::ErrorKind::UnexpectedEof => {
                            println!("read error: {e:?}");
                            break;
                        }
                        Err(_) => break,
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

                    println!(
                        "client request from tcp/{}: {:?}",
                        peer,
                        Message::from_vec(&read_buf)
                    );

                    let resp = match handler(&read_buf, Transport::Tcp) {
                        Ok(Some(resp)) => resp,
                        Ok(None) => {
                            println!("no response returned from handler");
                            break;
                        }
                        Err(e) => {
                            println!("error {e:?} returned from read handler");
                            break;
                        }
                    };

                    println!(
                        "handler response to tcp/{}: {:?}",
                        peer,
                        Message::from_vec(&resp)
                    );

                    let resp_len = (resp.len() as u16).to_be_bytes();

                    match stream.write_all(&resp_len).await {
                        Ok(_) => {}
                        Err(e) => {
                            println!("error writing response length: {e:?}");
                            break;
                        }
                    }

                    match stream.write_all(&resp).await {
                        Ok(_) => {}
                        Err(e) => {
                            println!("error writing main response: {e:?}");
                            break;
                        }
                    }
                }
            });
        }
    });
    Ok((addr, handle))
}

enum Transport {
    Tcp,
    Udp,
}

type HandlerFn = fn(&[u8], Transport) -> Result<Option<Vec<u8>>>;

#[cfg(test)]
mod test {
    use anyhow::Result;
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

    async fn basic_test(socket: SocketAddr, transport: Transport) -> Result<()> {
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
