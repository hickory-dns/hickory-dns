extern crate chrono;
extern crate futures;
#[macro_use]
extern crate lazy_static;
extern crate log;
extern crate openssl;
extern crate tokio_core;
extern crate trust_dns;
extern crate trust_dns_integration;
extern crate trust_dns_server;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use futures::{Future, Stream};
use futures::future::Either;
use tokio_core::reactor::{Core, Timeout};

use trust_dns::error::*;
use trust_dns::client::{ClientFuture, ClientHandle};
use trust_dns::multicast::{MdnsStream, MdnsClientStream};
use trust_dns::multicast::MdnsQueryType;
use trust_dns::op::Message;
use trust_dns::rr::{DNSClass, Name, RecordType};
use trust_dns::serialize::binary::BinDecodable;

const MDNS_PORT: u16 = 5353; 

lazy_static! {
    /// 250 appears to be unused/unregistered
    static ref TEST_MDNS_IPV4: SocketAddr = SocketAddr::new(Ipv4Addr::new(224,0,0,249).into(), MDNS_PORT);
    /// FA appears to be unused/unregistered
    static ref TEST_MDNS_IPV6: SocketAddr = SocketAddr::new(Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x00F9).into(), MDNS_PORT);
}


fn mdns_responsder(test_name: &'static str, client_done: Arc<AtomicBool>) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name(format!("{}:server", test_name))
        .spawn(move || {
            let mut io_loop = Core::new().unwrap();
            let loop_handle = io_loop.handle();
            
            // a max time for the test to run
            let mut timeout = Timeout::new(Duration::from_millis(100), &io_loop.handle()).expect("failed to register timeout");
            
            let (mdns_stream, mdns_handle) = MdnsStream::new::<ClientError>(
                *TEST_MDNS_IPV4,
                MdnsQueryType::OneShotJoin,
                Some(0),
                &io_loop.handle(),
            );

            let mut stream = io_loop.run(mdns_stream).ok().expect("failed to create server stream").into_future();

            while !client_done.load(std::sync::atomic::Ordering::Relaxed) {
                 match io_loop.run(stream.select2(timeout)).ok().expect("server stream closed") {
                    Either::A((data_src_stream_tmp, timeout_tmp)) => {
                        let (data_src, stream_tmp) = data_src_stream_tmp;
                        let (data, src) = data_src.expect("no buffer received");

                        stream = stream_tmp.into_future();
                        timeout = timeout_tmp;
                     
                        let message = Message::from_bytes(&data).expect("message decode failed");

                        // we're just going to bounce this message back

                        mdns_handle
                            .unbounded_send((message.to_vec().expect("message encode failed"), src))
                            .unwrap();
                    }
                    Either::B(((), data_src_stream_tmp)) => {
                        stream = data_src_stream_tmp;
                        timeout = Timeout::new(Duration::from_millis(100), &loop_handle).expect("failed to register timeout");
                    }
                }
            }
        })
        .unwrap()
}

#[test]
fn test_query_mdns_ipv4() {
    let client_done = Arc::new(AtomicBool::new(false));
    let _server_thread = mdns_responsder("test_query_mdns_ipv4", client_done.clone());
    let mut io_loop = Core::new().unwrap();
    //let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = MdnsClientStream::new(*TEST_MDNS_IPV4, MdnsQueryType::OneShot, None, &io_loop.handle());
    let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

    // A PTR request is the DNS-SD method for doing a directory listing...
    let name = Name::from_ascii("_dns._udp.local.").unwrap();
    let future = client.query(name.clone(), DNSClass::IN, RecordType::PTR);

    let message = io_loop.run(future).expect("mdns query failed");
    
    client_done.store(true, Ordering::Relaxed);
    
    println!("message: {:#?}", message);
}