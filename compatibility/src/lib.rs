// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(dead_code)]

extern crate data_encoding;
extern crate rand;

use std::env;
use std::fs;
use std::fs::DirBuilder;
use std::io::{BufRead, BufReader, Read, stdout, Write};
use std::path::Path;
use std::process::Child;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use data_encoding::base32;

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
    working_dir: String,
    named: Child,
    thread_notice: Arc<AtomicBool>,
}

impl Drop for NamedProcess {
    fn drop(&mut self) {
        self.named.kill().expect("could not kill process");
        self.named.wait().expect("waiting failed");

        self.thread_notice.store(true, Ordering::Relaxed);

        println!("----> cleanup work dir: {}", self.working_dir);
        fs::remove_dir_all(&self.working_dir).ok();
    }
}

fn new_working_dir() -> String {
    let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or(".".to_owned());

    let rand = rand::random::<u32>();
    let rand = base32::encode(&[rand as u8,
                                (rand >> 8) as u8,
                                (rand >> 16) as u8,
                                (rand >> 24) as u8]);
    let working_dir = format!("{}/../target/bind_pwd_{}", server_path, rand);

    if !Path::new(&working_dir).exists() {
        DirBuilder::new()
            .recursive(true)
            .create(&working_dir)
            .expect("failed to create dir");
    }

    working_dir
}

fn wrap_process<R>(working_dir: String, named: Child, io: R, started_str: &str) -> NamedProcess
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
        working_dir: working_dir,
        named: named,
        thread_notice: thread_notice,
    }
}