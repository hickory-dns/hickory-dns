use std::fs::DirBuilder;
use std::env;
use std::mem;
use std::path::Path;
use std::process::{Command, Stdio};

use data_encoding::base32;
use rand;

use super::*;

// downloaded from https://www.isc.org/downloads/file/bind-9-11-0-p1/
// cd bind-9-11-0-p1
// .configure
// make
// export TDNS_BIND_PATH=${PWD}/bin/named/named
pub fn named_process() -> (NamedProcess, u16) {
    let test_port = find_test_port();

    let bind_path = env::var("TDNS_BIND_PATH").unwrap_or("named".to_owned());
    let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or(".".to_owned());

    println!("Path to BIND '{}' this can be changed with the TDNS_BIND_PATH environment variable",
             bind_path);

    // create the work directory
    let rand = rand::random::<u32>();
    let rand = base32::encode(&[rand as u8,
                                (rand >> 8) as u8,
                                (rand >> 16) as u8,
                                (rand >> 24) as u8]);
    let working_dir = format!("{}/../target/bind_pwd_{}", server_path, rand);
    println!("BIND working directory: {}", working_dir);
    if !Path::new(&working_dir).exists() {
        DirBuilder::new()
            .recursive(true)
            .create(&working_dir)
            .expect("failed to create dir");
    }

    println!("starting BIND: {}", bind_path);
    let mut named = Command::new(bind_path)
                      .current_dir(&working_dir)
                      .stderr(Stdio::piped())
                      .arg("-c").arg(&format!("../../compatibility/tests/conf/bind-example.conf"))
                      //.arg("-d").arg("0") // uncomment for debugging information
                      .arg("-D").arg("TRust-DNS compatibility")
                      .arg("-g")
                      .arg("-p").arg(&format!("{}", test_port))
                      .spawn()
                      .expect("failed to start named");

    //
    let stderr = mem::replace(&mut named.stderr, None).unwrap();
    let process = wrap_process(named, stderr, "running\n");
    (process, test_port)
}