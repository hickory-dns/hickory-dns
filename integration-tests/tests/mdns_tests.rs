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
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use futures::{Future, Stream};
use tokio_core::reactor::Core;

use trust_dns::error::*;
use trust_dns::client::{BasicClientHandle, ClientFuture, ClientHandle};
use trust_dns::multicast::{MdnsStream, MdnsClientStream};
use trust_dns::multicast::MdnsQueryType;
use trust_dns::op::{Message, ResponseCode};
use trust_dns::rr::{DNSClass, IntoRecordSet, Name, RData, Record, RecordSet, RecordType};
use trust_dns::rr::dnssec::{Algorithm, KeyPair, Signer};
use trust_dns::rr::rdata::{DNSSECRData, DNSSECRecordType};
use trust_dns::serialize::binary::BinDecodable;
use trust_dns::tcp::TcpClientStream;
use trust_dns::udp::UdpClientStream;
use trust_dns_server::authority::Catalog;

const MDNS_PORT: u16 = 5353; 

lazy_static! {
    /// 250 appears to be unused/unregistered
    static ref TEST_MDNS_IPV4: SocketAddr = SocketAddr::new(Ipv4Addr::new(224,0,0,249).into(), MDNS_PORT);
    /// FA appears to be unused/unregistered
    static ref TEST_MDNS_IPV6: SocketAddr = SocketAddr::new(Ipv6Addr::new(0xFF, 0x02, 0, 0, 0, 0, 0, 0xF9).into(), MDNS_PORT);
}


fn mdns_responsder(test_name: &'static str, client_done: Arc<Mutex<bool>>) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name(format!("{}:server", test_name))
        .spawn(move || {
            let mut io_loop = Core::new().unwrap();
            let (mdns_stream, mdns_handle) = MdnsStream::new::<ClientError>(
                *TEST_MDNS_IPV4,
                MdnsQueryType::OneShotJoin,
                Some(0),
                &io_loop.handle(),
            );

            let mut stream: MdnsStream = io_loop.run(mdns_stream).ok().expect("failed to create server stream");

            let guard = client_done.lock().expect("poisoned");
            let mut stop = *guard;
            drop(guard);
            while !stop {
                let (data_src, stream_tmp) = io_loop.run(stream.into_future()).ok().expect("no data recieved");
                let (data, src) = data_src.expect("no buffer received");
                stream = stream_tmp;
                let message = Message::from_bytes(&data).expect("message decode failed");

                // we're just going to bounce this message back

                mdns_handle
                .unbounded_send((message.to_vec().expect("message encode failed"), src))
                .unwrap();

                io_loop.turn(Some(Duration::from_millis(100))); // turn for a while before looping... let the client run

                let stop = *client_done.lock().expect("poisoned");
            }
        })
        .unwrap()
}

#[test]
fn test_query_mdns_ipv4() {
    let client_done = Arc::new(Mutex::new(false));
    let server_thread = mdns_responsder("test_query_mdns_ipv4", client_done.clone());
    let mut io_loop = Core::new().unwrap();
    //let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = MdnsClientStream::new(*TEST_MDNS_IPV4, MdnsQueryType::OneShot, None, &io_loop.handle());
    let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

    // A PTR request is the DNS-SD method for doing a directory listing...
    let name = Name::from_ascii("_dns._udp.local.").unwrap();
    let future = client.query(name.clone(), DNSClass::IN, RecordType::PTR);

    let message = io_loop.run(future).expect("mdns query failed");
    // FIXME: validate result

    let mut done = client_done.lock().expect("poisoned");
    *done = true;

    println!("message: {:#?}", message);
}