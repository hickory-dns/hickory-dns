use alloc::string::ToString;
use alloc::sync::Arc;
use core::sync::atomic::AtomicBool;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::println;

use futures_util::stream::StreamExt;

use crate::runtime::RuntimeProvider;
use crate::tcp::TcpStream;
use crate::xfer::SerialMessage;
use crate::xfer::dns_handle::DnsStreamHandle;

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
                std::thread::sleep(core::time::Duration::from_secs(1));
                if succeeded.load(core::sync::atomic::Ordering::Relaxed) {
                    return;
                }
            }

            println!("Thread Killer has been awoken, killing process");
            std::process::exit(-1);
        })
        .expect("Thread spawning failed");

    // TODO: need a timeout on listen
    let server = std::net::TcpListener::bind(SocketAddr::new(server_addr, 0))
        .expect("Unable to bind a TCP socket");
    let server_addr = server.local_addr().unwrap();

    // an in and out server
    let server_handle = std::thread::Builder::new()
        .name(server_name.to_string())
        .spawn(move || {
            let (mut socket, _) = server.accept().expect("accept failed");

            socket
                .set_read_timeout(Some(core::time::Duration::from_secs(5)))
                .unwrap(); // should receive something within 5 seconds...
            socket
                .set_write_timeout(Some(core::time::Duration::from_secs(5)))
                .unwrap(); // should receive something within 5 seconds...

            for _ in 0..SEND_RECV_TIMES {
                // wait for some bytes...
                let mut len_bytes = [0_u8; 2];
                socket
                    .read_exact(&mut len_bytes)
                    .expect("SERVER: receive failed");
                let length =
                    (u16::from(len_bytes[0]) << 8) & 0xFF00 | u16::from(len_bytes[1]) & 0x00FF;
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
pub async fn tcp_stream_test(server_addr: IpAddr, provider: impl RuntimeProvider) {
    let (succeeded, server_handle, server_addr) =
        tcp_server_setup("test_tcp_stream:server", server_addr);

    // setup the client, which is going to run on the testing thread...

    let tcp = provider
        .connect_tcp(server_addr, None, None)
        .await
        .expect("connect failed");
    let (mut stream, mut sender) = TcpStream::from_stream(tcp, server_addr);

    for _ in 0..SEND_RECV_TIMES {
        // test once
        sender
            .send(SerialMessage::new(TEST_BYTES.to_vec(), server_addr))
            .expect("send failed");

        let (buffer, stream_tmp) = stream.into_future().await;
        stream = stream_tmp;
        let message = buffer
            .expect("no buffer received")
            .expect("error receiving buffer");
        assert_eq!(message.bytes(), TEST_BYTES);
    }

    succeeded.store(true, core::sync::atomic::Ordering::Relaxed);
    server_handle.join().expect("server thread failed");
}

/// Test tcp_client_stream.
pub async fn tcp_client_stream_test(server_addr: IpAddr, provider: impl RuntimeProvider) {
    let (succeeded, server_handle, server_addr) =
        tcp_server_setup("test_tcp_client_stream:server", server_addr);

    // setup the client, which is going to run on the testing thread...

    let tcp = provider
        .connect_tcp(server_addr, None, None)
        .await
        .expect("connect failed");
    let (mut stream, mut sender) = TcpStream::from_stream(tcp, server_addr);

    for _ in 0..SEND_RECV_TIMES {
        // test once
        sender
            .send(SerialMessage::new(TEST_BYTES.to_vec(), server_addr))
            .expect("send failed");
        let (buffer, stream_tmp) = stream.into_future().await;
        stream = stream_tmp;
        let buffer = buffer
            .expect("no buffer received")
            .expect("error receiving buffer");
        assert_eq!(buffer.bytes(), TEST_BYTES);
    }

    succeeded.store(true, core::sync::atomic::Ordering::Relaxed);
    server_handle.join().expect("server thread failed");
}
