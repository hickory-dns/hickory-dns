// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
// Copyright 2017 Google LLC.
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The bind_dnskey_to_pem program

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
use std::io::{BufRead, BufReader, Lines, Write};
use std::str::FromStr;

use clap::{Arg, ArgMatches, Command};
use data_encoding::BASE64;
use openssl::bn::BigNum;
use openssl::rsa::Rsa;
use tracing::{info, warn, Level};

use trust_dns_client::rr::dnssec::Algorithm;

fn args() -> ArgMatches {
    Command::new("Trust-DNS dnskey-to-pem")
        .version(trust_dns_client::version())
        .author("Benjamin Fry <benjaminfry@me.com>")
        .about("Converts a dnskey, as generated from BIND's dnssec-keygen, into pem format")
        .arg(
            Arg::new("key")
                .value_name("PRIVATE_KEY_FILE")
                .help("Input FILE from which to read the DNSSec private key")
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
                .default_value("out.pem"),
        )
        .get_matches()
}

/// Run the bind_dnskey_to_pem program
pub fn main() {
    trust_dns_util::logger(env!("CARGO_BIN_NAME"), Some(Level::INFO));

    let matches = args();

    let key_path = matches.value_of("key").unwrap();
    let output_path = matches.value_of("output").unwrap();

    tracing::info!("Reading private key: {}", key_path);

    let key_file = File::open(key_path).expect("private key file could not be opened");

    let mut lines = BufReader::new(key_file).lines();

    // private key format expected to be first
    let next_line = lines
        .next()
        .expect("missing Private-key-format line")
        .unwrap();

    let (key, value) = split_field_value(&next_line);
    if "Private-key-format" != key {
        panic!("Private-key-format line not found: {}", next_line);
    }
    if "v1.2" != value {
        warn!("WARNING: un-tested version {:?}", value);
    }

    // algorithm
    let next_line = lines.next().expect("missing Algorithm line").unwrap();

    let (key, value) = split_field_value(&next_line);
    if key != "Algorithm" {
        panic!("Algorithm line not found: {}", next_line)
    }
    let algorithm_num = u8::from_str(
        value
            .split(' ')
            .next()
            .unwrap_or_else(|| panic!("bad algorithm format, expected '# STR': {}", next_line)),
    )
    .unwrap_or_else(|_| panic!("bad algorithm format, expected '# STR': {}", next_line));

    let algorithm = match Algorithm::from_u8(algorithm_num) {
        Algorithm::Unknown(v) => panic!("unsupported algorithm {}: {}", v, next_line),
        a => a,
    };

    let pem_bytes = match algorithm {
        Algorithm::RSASHA256 => read_rsa(lines),
        _ => panic!("Algorithm currently not supported: {:?}", algorithm),
    };

    info!("Writing private key to pem: {}", output_path);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output_path)
        .unwrap_or_else(|_| panic!("could not create file: {}", output_path));

    file.write_all(&pem_bytes)
        .unwrap_or_else(|_| panic!("could not write to file: {}", output_path));
}

fn split_field_value(line: &str) -> (&str, &str) {
    let mut split = line.split(": ");
    let field: &str = split
        .next()
        .unwrap_or_else(|| panic!("missing field: {}", line));
    let value: &str = split
        .next()
        .unwrap_or_else(|| panic!("missing value: {}", line));

    (field, value)
}

fn read_rsa<B: BufRead>(lines: Lines<B>) -> Vec<u8> {
    let mut modulus = Option::None::<BigNum>;
    let mut public_exponent = Option::None::<BigNum>;
    let mut private_exponent = Option::None::<BigNum>;
    let mut prime1 = Option::None::<BigNum>;
    let mut prime2 = Option::None::<BigNum>;
    let mut exponent1 = Option::None::<BigNum>;
    let mut exponent2 = Option::None::<BigNum>;
    let mut coefficient = Option::None::<BigNum>;

    // collect the various lines
    for line in lines {
        let line = line.expect("error reading private key file");
        let (field, value) = split_field_value(&line);

        let num = Some(
            BigNum::from_slice(
                &BASE64
                    .decode(value.as_bytes())
                    .unwrap_or_else(|_| panic!("badly formatted line, expected base64: {}", line)),
            )
            .unwrap(),
        );

        match field {
            "Modulus" => modulus = num,
            "PublicExponent" => public_exponent = num,
            "PrivateExponent" => private_exponent = num,
            "Prime1" => prime1 = num,
            "Prime2" => prime2 = num,
            "Exponent1" => exponent1 = num,
            "Exponent2" => exponent2 = num,
            "Coefficient" => coefficient = num,
            _ => panic!("unrecognized field: {}", field),
        }
    }

    let rsa = Rsa::from_private_components(
        modulus.expect("Missing Modulus"),
        public_exponent.expect("Missing PublicExponent"),
        private_exponent.expect("Missing PrivateExponent"),
        prime1.expect("Missing Prime1"),
        prime2.expect("Missing Prime2"),
        exponent1.expect("Missing Exponent1"),
        exponent2.expect("Missing Exponent2"),
        coefficient.expect("Missing Coefficient"),
    )
    .unwrap();

    rsa.private_key_to_pem().unwrap()
}
