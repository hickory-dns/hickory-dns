#![cfg(feature = "mdns")]

#[macro_use]
extern crate lazy_static;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread::JoinHandle;
use std::time::Duration;

use futures::future::Either;
use futures::{future, StreamExt};
use tokio::runtime::Runtime;

use trust_dns_client::client::{AsyncClient, ClientHandle};
use trust_dns_client::multicast::MdnsQueryType;
use trust_dns_client::multicast::{MdnsClientStream, MdnsStream};
use trust_dns_client::op::Message;
use trust_dns_client::rr::{DNSClass, Name, RecordType};
use trust_dns_client::serialize::binary::BinDecodable;
use trust_dns_proto::xfer::SerialMessage;

const MDNS_PORT: u16 = 5363;

lazy_static! {
    /// 250 appears to be unused/unregistered
    static ref TEST_MDNS_IPV4: IpAddr = Ipv4Addr::new(224,0,0,249).into();
    /// FA appears to be unused/unregistered
    static ref TEST_MDNS_IPV6: IpAddr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x00F9).into();
}

fn mdns_responsder(
    test_name: &'static str,
    client_done: Arc<AtomicBool>,
    mdns_addr: SocketAddr,
) -> JoinHandle<()> {
    let server = Arc::new(Barrier::new(2));
    let client = Arc::clone(&server);

    let join_handle = std::thread::Builder::new()
        .name(format!("{}:server", test_name))
        .spawn(move || {
            let io_loop = Runtime::new().unwrap();

            // a max time for the test to run
            let mut timeout = Box::pin(tokio::time::sleep(Duration::from_millis(100)));

            // TODO: ipv6 if is hardcoded, need a different strategy
            let (mdns_stream, mut mdns_handle) = MdnsStream::new(
                mdns_addr,
                MdnsQueryType::OneShotJoin,
                Some(1),
                None,
                Some(5),
            );

            let mut stream = io_loop
                .block_on(mdns_stream)
                .expect("failed to create server stream")
                .into_future();

            server.wait();

            while !client_done.load(std::sync::atomic::Ordering::Relaxed) {
                match io_loop.block_on(future::select(stream, timeout)) {
                    Either::Left((data_src_stream_tmp, timeout_tmp)) => {
                        let (data_src, stream_tmp) = data_src_stream_tmp;
                        let (data, src) = data_src
                            .expect("no buffer received")
                            .expect("error receiving buffer")
                            .into_parts();

                        stream = stream_tmp.into_future();
                        timeout = timeout_tmp;

                        let message = Message::from_bytes(&data).expect("message decode failed");

                        // we're just going to bounce this message back

                        mdns_handle
                            .send(SerialMessage::new(
                                message.to_vec().expect("message encode failed"),
                                src,
                            ))
                            .unwrap();
                    }
                    Either::Right(((), data_src_stream_tmp)) => {
                        stream = data_src_stream_tmp;
                        timeout = Box::pin(tokio::time::sleep(Duration::from_millis(100)));
                    }
                }
            }
        })
        .unwrap();

    client.wait();
    println!("server started");

    join_handle
}

// FIXME: reenable after breakage in async/await
#[ignore]
#[test]
fn test_query_mdns_ipv4() {
    let addr = SocketAddr::new(*TEST_MDNS_IPV4, MDNS_PORT + 1);
    let client_done = Arc::new(AtomicBool::new(false));
    let _server_thread = mdns_responsder("test_query_mdns_ipv4", client_done.clone(), addr);

    // Check that the server is ready before sending...
    let io_loop = Runtime::new().unwrap();
    //let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();

    // not using MdnsClientConnection here, b/c we need to change the IP for testing.
    let (stream, sender) = MdnsClientStream::new(addr, MdnsQueryType::OneShot, None, None, None);
    let client = AsyncClient::new(stream, sender, None);
    let (mut client, bg) = io_loop.block_on(client).expect("failed to connect mDNS");
    trust_dns_proto::spawn_bg(&io_loop, bg);

    // A PTR request is the DNS-SD method for doing a directory listing...
    let name = Name::from_ascii("_dns._udp.local.").unwrap();
    let message = io_loop.block_on(client.query(name, DNSClass::IN, RecordType::PTR));

    client_done.store(true, Ordering::Relaxed);

    println!("client message: {:#?}", message);
}

#[test]
#[ignore]
fn test_query_mdns_ipv6() {
    let addr = SocketAddr::new(*TEST_MDNS_IPV6, MDNS_PORT + 2);
    let client_done = Arc::new(AtomicBool::new(false));
    let _server_thread = mdns_responsder("test_query_mdns_ipv4", client_done.clone(), addr);
    let io_loop = Runtime::new().unwrap();

    // not using MdnsClientConnection here, b/c we need to change the IP for testing.
    // FIXME: ipv6 if is hardcoded...
    let (stream, sender) = MdnsClientStream::new(addr, MdnsQueryType::OneShot, None, None, Some(5));
    let client = AsyncClient::new(stream, sender, None);
    let (mut client, bg) = io_loop.block_on(client).expect("failed to connect client");
    trust_dns_proto::spawn_bg(&io_loop, bg);

    // A PTR request is the DNS-SD method for doing a directory listing...
    let name = Name::from_ascii("_dns._udp.local.").unwrap();
    let message = io_loop.block_on(client.query(name, DNSClass::IN, RecordType::PTR));

    client_done.store(true, Ordering::Relaxed);

    println!("client message: {:#?}", message);
}
