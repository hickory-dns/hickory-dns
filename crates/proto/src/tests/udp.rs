use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use futures::stream::StreamExt;
use log::debug;

use crate::udp::{UdpClientStream, UdpSocket, UdpStream};
use crate::{Executor, Time};

/// Test next random udpsocket.
pub fn next_random_socket_test<S: UdpSocket + Send + 'static, E: Executor>(mut exec: E) {
    let (stream, _) =
        UdpStream::<S>::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 52));
    drop(
        exec.block_on(stream)
            .expect("failed to get next socket address"),
    );
}

/// Test udp_stream.
pub fn udp_stream_test<S: UdpSocket + Send + 'static, E: Executor>(
    server_addr: IpAddr,
    mut exec: E,
) {
    use crate::xfer::SerialMessage;
    use std::net::ToSocketAddrs;

    let succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let succeeded_clone = succeeded.clone();
    std::thread::Builder::new()
        .name("thread_killer".to_string())
        .spawn(move || {
            let succeeded = succeeded_clone;
            for _ in 0..15 {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if succeeded.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
            }

            panic!("timeout");
        })
        .unwrap();

    let server = std::net::UdpSocket::bind(SocketAddr::new(server_addr, 0)).unwrap();
    server
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap(); // should receive something within 5 seconds...
    server
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap(); // should receive something within 5 seconds...
    let server_addr = server.local_addr().unwrap();

    let test_bytes: &'static [u8; 8] = b"DEADBEEF";
    let send_recv_times = 4;

    // an in and out server
    let server_handle = std::thread::Builder::new()
        .name("test_udp_stream_ipv4:server".to_string())
        .spawn(move || {
            let mut buffer = [0_u8; 512];

            for _ in 0..send_recv_times {
                // wait for some bytes...
                let (len, addr) = server.recv_from(&mut buffer).expect("receive failed");

                assert_eq!(&buffer[0..len], test_bytes);

                // bounce them right back...
                assert_eq!(
                    server.send_to(&buffer[0..len], addr).expect("send failed"),
                    len
                );
            }
        })
        .unwrap();

    // setup the client, which is going to run on the testing thread...
    // the tests should run within 5 seconds... right?
    // TODO: add timeout here, so that test never hangs...
    let client_addr = match server_addr {
        std::net::SocketAddr::V4(_) => "127.0.0.1:0",
        std::net::SocketAddr::V6(_) => "[::1]:0",
    };

    let socket = exec
        .block_on(S::bind(
            &client_addr.to_socket_addrs().unwrap().next().unwrap(),
        ))
        .expect("could not create socket"); // some random address...
    let (mut stream, sender) = UdpStream::<S>::with_bound(socket);

    for _ in 0..send_recv_times {
        // test once
        sender
            .unbounded_send(SerialMessage::new(test_bytes.to_vec(), server_addr))
            .unwrap();
        let (buffer_and_addr, stream_tmp) = exec.block_on(stream.into_future());
        stream = stream_tmp;
        let message = buffer_and_addr
            .expect("no buffer received")
            .expect("error receiving buffer");
        assert_eq!(message.bytes(), test_bytes);
        assert_eq!(message.addr(), server_addr);
    }

    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    server_handle.join().expect("server thread failed");
}

/// Test udp_client_stream.
#[allow(clippy::print_stdout)]
pub fn udp_client_stream_test<S: UdpSocket + Send + 'static, E: Executor, TE: Time>(
    server_addr: IpAddr,
    mut exec: E,
) {
    use crate::op::{Message, Query};
    use crate::rr::rdata::NULL;
    use crate::rr::{Name, RData, Record, RecordType};
    use crate::xfer::{DnsRequest, DnsRequestSender};
    use futures::future;
    use std::str::FromStr;
    use std::time::Duration;

    // use env_logger;
    // env_logger::try_init().ok();

    let succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let succeeded_clone = succeeded.clone();
    std::thread::Builder::new()
        .name("thread_killer".to_string())
        .spawn(move || {
            let succeeded = succeeded_clone;
            for _ in 0..15 {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if succeeded.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
            }

            panic!("timeout");
        })
        .unwrap();

    let server = std::net::UdpSocket::bind(SocketAddr::new(server_addr, 0)).unwrap();
    server
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap(); // should receive something within 5 seconds...
    server
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap(); // should receive something within 5 seconds...
    let server_addr = server.local_addr().unwrap();

    let mut query = Message::new();
    let test_name = Name::from_str("dead.beef").unwrap();
    query.add_query(Query::query(test_name.clone(), RecordType::NULL));
    let test_bytes: &'static [u8; 8] = b"DEADBEEF";
    let send_recv_times = 4;

    let test_name_server = test_name;
    // an in and out server
    let server_handle = std::thread::Builder::new()
        .name("test_udp_client_stream_ipv4:server".to_string())
        .spawn(move || {
            let mut buffer = [0_u8; 512];

            for i in 0..send_recv_times {
                // wait for some bytes...
                debug!("server receiving request {}", i);
                let (len, addr) = server.recv_from(&mut buffer).expect("receive failed");
                debug!("server received request {} from: {}", i, addr);

                let request = Message::from_vec(&buffer[0..len]).expect("failed parse of request");
                assert_eq!(*request.queries()[0].name(), test_name_server.clone());
                assert_eq!(request.queries()[0].query_type(), RecordType::NULL);

                let mut message = Message::new();
                message.set_id(request.id());
                message.add_queries(request.queries().to_vec());
                message.add_answer(Record::from_rdata(
                    test_name_server.clone(),
                    0,
                    RData::NULL(NULL::with(test_bytes.to_vec())),
                ));

                // bounce them right back...
                let bytes = message.to_vec().unwrap();
                debug!("server sending response {} to: {}", i, addr);
                assert_eq!(
                    server.send_to(&bytes, addr).expect("send failed"),
                    bytes.len()
                );
                debug!("server sent response {}", i);
                std::thread::yield_now();
            }
        })
        .unwrap();

    // setup the client, which is going to run on the testing thread...

    // the tests should run within 5 seconds... right?
    // TODO: add timeout here, so that test never hangs...
    // let timeout = Timeout::new(Duration::from_secs(5));
    let stream = UdpClientStream::with_timeout(server_addr, Duration::from_millis(500));
    let mut stream: UdpClientStream<S> = exec.block_on(stream).ok().unwrap();
    let mut worked_once = false;

    for i in 0..send_recv_times {
        // test once
        let response_future = exec.block_on(future::lazy(|cx| {
            stream.send_message::<TE>(DnsRequest::new(query.clone(), Default::default()), cx)
        }));
        println!("client sending request {}", i);
        let response = match exec.block_on(response_future) {
            Ok(response) => response,
            Err(err) => {
                println!("failed to get message: {}", err);
                continue;
            }
        };
        println!("client got response {}", i);

        let response = Message::from(response);
        if let RData::NULL(null) = response.answers()[0].rdata() {
            assert_eq!(null.anything().expect("no bytes in NULL"), test_bytes);
        } else {
            panic!("not a NULL response");
        }

        worked_once = true;
    }

    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    server_handle.join().expect("server thread failed");

    assert!(worked_once);
}
