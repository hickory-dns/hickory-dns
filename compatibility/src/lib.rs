
use std::io::{BufRead, BufReader, Read, stdout, Write};
use std::process::Child;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

mod bind;
mod none;

#[cfg(feature = "bind")]
pub use bind::named_process;

#[cfg(feature = "none")]
pub use none::named_process;

fn find_test_port() -> u16 {
    let server = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
    let server_addr = server.local_addr().unwrap();
    server_addr.port()
}

pub struct NamedProcess {
    named: Child,
    thread_notice: Arc<AtomicBool>,
}

impl Drop for NamedProcess {
    fn drop(&mut self) {
        self.named.kill().expect("could not kill process");
        self.named.wait().expect("waiting failed");

        self.thread_notice.store(true, Ordering::Relaxed);
    }
}

fn wrap_process<R>(named: Child, io: R, started_str: &str) -> NamedProcess
    where R: Read + Send + 'static
{
    let mut named_out = BufReader::new(io);

    // we should get the correct output before 1000 lines...
    let mut output = String::new();
    let mut found = false;

    println!("TEST: waiting for server to start");
    for _ in 0..1000 {
        output.clear();
        named_out
            .read_line(&mut output)
            .expect("could not read stdout");

        if !output.is_empty() {
            print!("SRV: {}", output);
        }

        if output.ends_with(started_str) {
            found = true;
            break;
        }
    }

    stdout().flush().unwrap();
    assert!(found, "server did not startup...");

    let thread_notice = Arc::new(AtomicBool::new(false));
    let thread_notice_clone = thread_notice.clone();

    thread::Builder::new()
        .name("named stdout".into())
        .spawn(move || {
            let thread_notice = thread_notice_clone;
            while !thread_notice.load(std::sync::atomic::Ordering::Relaxed) {
                output.clear();
                named_out
                    .read_line(&mut output)
                    .expect("could not read stdout");
                // stdout().write(b"SRV: ").unwrap();
                // stdout().write(output.as_bytes()).unwrap();
            }
        })
        .expect("no thread available");

    // return handle to child process
    NamedProcess {
        named: named,
        thread_notice: thread_notice,
    }
}