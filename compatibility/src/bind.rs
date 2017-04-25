use std::fs::DirBuilder;
use std::env;
use std::mem;
use std::path::Path;
use std::process::{Command, Stdio};

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

    // create the work directory
    let working_dir = format!("{}/../target/bind_pwd", server_path);
    if !Path::new(&working_dir).exists() {
        DirBuilder::new()
            .create(&working_dir)
            .expect("failed to create dir");
    }

    let mut named = Command::new(bind_path)
                      .current_dir(&working_dir)
                      .stderr(Stdio::piped())
                      .arg("-c").arg(&format!("../../compatibility/tests/conf/bind-example.conf"))
                      //.arg("-d").arg("0")
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