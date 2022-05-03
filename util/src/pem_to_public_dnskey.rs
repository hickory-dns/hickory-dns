// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The pem_to_public_dnskey program

// BINARY WARNINGS
#![warn(
    clippy::default_trait_access,
    clippy::dbg_macro,
    clippy::unimplemented,
    missing_copy_implementations,
    missing_docs,
    non_snake_case,
    non_upper_case_globals,
    rust_2018_idioms,
    unreachable_pub
)]

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};

use clap::{Arg, ArgMatches, Command};
use openssl::pkey::PKey;
use tracing::info;

use trust_dns_client::rr::dnssec::{KeyPair, Public};

fn args() -> ArgMatches {
    Command::new("Trust-DNS pem-to-public-dnskey")
        .version(trust_dns_client::version())
        .author("Benjamin Fry <benjaminfry@me.com>")
        .about(
            "Converts a PEM formatted public key into a raw public dnskey (not the inverse of dnskey-to-pem). This can be used to create a dnskey in the TrustAnchor internal format in Trust-DNS.",
        )
        .arg(
            Arg::new("key")
                .value_name("PEM_KEY_FILE")
                .help("Input PEM FILE from which to read the public key")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("output")
                .value_name("OUTPUT_FILE")
                .long("output")
                .short('o')
                .takes_value(true)
                .help("Output FILE to write to")
                .default_value("out.dnskey"),
        )
        .get_matches()
}

/// Run the pem_to_public_dnskey program
pub fn main() {
    trust_dns_util::logger(env!("CARGO_BIN_NAME"), Some(tracing::Level::INFO));

    let matches = args();

    let key_path = matches.value_of("key").unwrap();
    let output_path = matches.value_of("output").unwrap();

    info!("Reading key from pem: {}", key_path);

    let mut key_file = File::open(key_path).expect("private key file could not be opened");

    let pkey = read_pem(&mut key_file);
    let key_pair = into_key_pair(pkey);

    let public_key = key_pair
        .to_public_bytes()
        .expect("failed to convert to public key");

    let mut public_key_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .expect("could not open public_key file for writing");

    public_key_file
        .write_all(&public_key)
        .expect("failed to write public_key to file");
}

fn into_key_pair(pkey: PKey<Public>) -> KeyPair<Public> {
    let rsa = pkey.rsa();
    if let Ok(rsa) = rsa {
        return KeyPair::from_rsa(rsa).expect("failed to convert to rsa");
    }

    let ec = pkey.ec_key();
    if let Ok(ec) = ec {
        return KeyPair::from_ec_key(ec).expect("failed to convert to ec");
    }

    panic!("unsupported pkey");
}

fn read_pem<R: Read>(reader: &mut R) -> PKey<Public> {
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::<u8>::new();

    reader
        .read_to_end(&mut buf)
        .expect("failed to read pem file");
    PKey::public_key_from_pem(&buf).expect("failed to detect PKey in PEM data")
}

#[cfg(test)]
mod test {
    use std::env;
    use std::fs::File;
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn read_pem_into_key_pair() {
        let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "..".to_owned());

        let path = [&server_path, "tests", "test-data", "ca.pubkey"]
            .iter()
            .collect::<PathBuf>();
        let mut pem = File::open(path).unwrap();

        let pkey = read_pem(&mut pem);
        let keypair = into_key_pair(pkey);

        keypair
            .to_public_bytes()
            .expect("failed to get public bytes");
    }
}
