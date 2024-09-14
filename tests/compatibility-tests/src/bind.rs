// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::env;
use std::process::{Command, Stdio};

use super::*;

// downloaded from https://www.isc.org/downloads/file/bind-9-11-0-p1/
// cd bind-9-11-0-p1
// .configure
// make
// export TDNS_BIND_PATH=${PWD}/bin/named/named
pub fn named_process() -> (NamedProcess, u16) {
    let test_port = find_test_port();

    let bind_path = env::var("TDNS_BIND_PATH").expect("TDNS_BIND_PATH not set");
    let bind_path = format!("{bind_path}/sbin/named");

    println!(
        "Path to BIND '{bind_path}' this can be changed with the TDNS_BIND_PATH environment variable"
    );

    let working_dir = new_working_dir();
    println!("---> BIND working directory: {working_dir}");

    // start up bind
    println!("---> starting BIND: {bind_path}");
    let mut named = Command::new(bind_path)
        .current_dir(&working_dir)
        .stderr(Stdio::piped())
        // from the root target directory...
        .arg("-c")
        .arg("../../tests/compatibility-tests/tests/conf/bind-example.conf")
        //.arg("-d").arg("0") // uncomment for debugging information
        .arg("-D")
        .arg("Hickory DNS compatibility")
        .arg("-g")
        .arg("-p")
        .arg(format!("{test_port}"))
        .spawn()
        .expect("failed to start named");

    //
    let stderr = named.stderr.take().unwrap();
    let process = wrap_process(working_dir, named, stderr, "running\n");
    (process, test_port)
}
