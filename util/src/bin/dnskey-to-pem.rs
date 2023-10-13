// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
// Copyright 2017 Google LLC.
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
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
use std::path::PathBuf;
use std::str::FromStr;

use clap::Parser;
use data_encoding::BASE64;
use openssl::bn::BigNum;
use openssl::rsa::Rsa;
use tracing::{info, warn, Level};

use hickory_proto::rr::dnssec::Algorithm;

/// Cli struct for all options managed with clap derive api.
#[derive(Debug, Parser)]
#[clap(
    name = "Hickory DNS dnskey-to-pem",
    version,
    about = "Converts a dnskey, as generated from BIND's dnssec-keygen, into pem format",
    author = "Benjamin Fry <benjaminfry@me.com>"
)]
struct Cli {
    /// Input FILE from which to read the DNSSEC private key
    #[arg(
        long = "key",
        value_name = "PRIVATE_KEY_FILE",
        value_hint=clap::ValueHint::FilePath,
    )]
    pub(crate) key: PathBuf,

    /// Output FILE to write to default `out.pem`
    #[arg(
        short = 'o',
        long = "output",
        default_value = "out.pem",
        value_name = "OUTPUT_FILE",
        value_hint=clap::ValueHint::FilePath,
    )]
    pub(crate) output: PathBuf,
}

/// Run the bind_dnskey_to_pem program
pub fn main() {
    hickory_util::logger(env!("CARGO_BIN_NAME"), Some(Level::INFO));

    let args = Cli::parse();
    let key_path = args.key;
    let output_path = args.output;

    tracing::info!("Reading private key: {}", key_path.display());

    let key_file = File::open(&key_path).unwrap_or_else(|_| {
        panic!(
            "private key file <{}> could not be opened",
            key_path.display()
        )
    });

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

    info!("Writing private key to pem: {}", output_path.display());
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&output_path)
        .unwrap_or_else(|_| panic!("could not create file: {}", output_path.display()));

    file.write_all(&pem_bytes)
        .unwrap_or_else(|_| panic!("could not write to file: {}", output_path.display()));
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
