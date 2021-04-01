use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::{atomic::AtomicBool, Arc};

use futures_util::stream::StreamExt;

use crate::error::ProtoError;
use crate::tcp::{Connect, TcpClientStream, TcpStream};
use crate::xfer::dns_handle::DnsStreamHandle;
use crate::xfer::SerialMessage;
use crate::{Executor, Time};

const TEST_BYTES: &[u8; 8] = b"DEADBEEF";
const TEST_BYTES_LEN: usize = 8;
const SEND_RECV_TIMES: usize = 4;

fn tcp_server_setup(
    server_name: &str,
    server_addr: IpAddr,
) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>, SocketAddr) {
    let succeeded = Arc::new(AtomicBool::new(false));
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

            println!("Thread Killer has been awoken, killing process");
            std::process::exit(-1);
        })
        .unwrap();

    // TODO: need a timeout on listen
    let server = std::net::TcpListener::bind(SocketAddr::new(server_addr, 0)).unwrap();
    let server_addr = server.local_addr().unwrap();

    // an in and out server
    let server_handle = std::thread::Builder::new()
        .name(server_name.to_string())
        .spawn(move || {
            let (mut socket, _) = server.accept().expect("accept failed");

            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap(); // should receive something within 5 seconds...
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap(); // should receive something within 5 seconds...

            for _ in 0..SEND_RECV_TIMES {
                // wait for some bytes...
                let mut len_bytes = [0_u8; 2];
                socket
                    .read_exact(&mut len_bytes)
                    .expect("SERVER: receive failed");
                let length =
                    u16::from(len_bytes[0]) << 8 & 0xFF00 | u16::from(len_bytes[1]) & 0x00FF;
                assert_eq!(length as usize, TEST_BYTES_LEN);

                let mut buffer = [0_u8; TEST_BYTES_LEN];
                socket.read_exact(&mut buffer).unwrap();

                // println!("read bytes iter: {}", i);
                assert_eq!(&buffer, TEST_BYTES);

                // bounce them right back...
                socket
                    .write_all(&len_bytes)
                    .expect("SERVER: send length failed");
                socket
                    .write_all(&buffer)
                    .expect("SERVER: send buffer failed");
                // println!("wrote bytes iter: {}", i);
                std::thread::yield_now();
            }
        })
        .unwrap();
    (succeeded, server_handle, server_addr)
}

/// Test tcp_stream.
pub fn tcp_stream_test<S: Connect, E: Executor, TE: Time>(server_addr: IpAddr, mut exec: E) {
    let (succeeded, server_handle, server_addr) =
        tcp_server_setup("test_tcp_stream:server", server_addr);

    // setup the client, which is going to run on the testing thread...

    // the tests should run within 5 seconds... right?
    // TODO: add timeout here, so that test never hangs...
    // let timeout = Timeout::new(Duration::from_secs(5));
    let (stream, mut sender) = TcpStream::<S>::new::<ProtoError>(server_addr);

    let mut stream = exec.block_on(stream).expect("run failed to get stream");

    for _ in 0..SEND_RECV_TIMES {
        // test once
        sender
            .send(SerialMessage::new(TEST_BYTES.to_vec(), server_addr))
            .expect("send failed");

        let (buffer, stream_tmp) = exec.block_on(stream.into_future());
        stream = stream_tmp;
        let message = buffer
            .expect("no buffer received")
            .expect("error receiving buffer");
        assert_eq!(message.bytes(), TEST_BYTES);
    }

    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    server_handle.join().expect("server thread failed");
}

/// Test tcp_client_stream.
pub fn tcp_client_stream_test<S: Connect, E: Executor, TE: Time + 'static>(
    server_addr: IpAddr,
    mut exec: E,
) {
    let (succeeded, server_handle, server_addr) =
        tcp_server_setup("test_tcp_client_stream:server", server_addr);

    // setup the client, which is going to run on the testing thread...

    // the tests should run within 5 seconds... right?
    // TODO: add timeout here, so that test never hangs...
    // let timeout = Timeout::new(Duration::from_secs(5));
    let (stream, mut sender) = TcpClientStream::<S>::new(server_addr);

    let mut stream = exec.block_on(stream).expect("run failed to get stream");

    for _ in 0..SEND_RECV_TIMES {
        // test once
        sender
            .send(SerialMessage::new(TEST_BYTES.to_vec(), server_addr))
            .expect("send failed");
        let (buffer, stream_tmp) = exec.block_on(stream.into_future());
        stream = stream_tmp;
        let buffer = buffer
            .expect("no buffer received")
            .expect("error receiving buffer");
        assert_eq!(buffer.bytes(), TEST_BYTES);
    }

    succeeded.store(true, std::sync::atomic::Ordering::Relaxed);
    server_handle.join().expect("server thread failed");
}
