// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
// Copyright 2017 Google LLC.
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
extern crate clap;
extern crate data_encoding;
extern crate env_logger;
#[macro_use]
extern crate log;
extern crate openssl;
extern crate trust_dns;

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Lines, Write};
use std::str::FromStr;

use clap::{App, Arg, ArgMatches};
use data_encoding::BASE64;
use openssl::bn::BigNum;
use openssl::rsa::Rsa;

use trust_dns::rr::dnssec::Algorithm;

fn args<'a>() -> ArgMatches<'a> {
    App::new("TRust-DNS dnskey-to-pem")
        .version(trust_dns::version())
        .author("Benjamin Fry <benjaminfry@me.com>")
        .about("Converts a dnskey, as generated from BIND's dnssec-keygen, into pem format")
        .arg(
            Arg::with_name("key")
                .value_name("PRIVATE_KEY_FILE")
                .help("Input FILE from which to read the DNSSec private key")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("output")
                .value_name("OUTPUT_FILE")
                .long("output")
                .short("o")
                .takes_value(true)
                .help("Output FILE to write to")
                .default_value("out.pem"),
        )
        .get_matches()
}

pub fn main() {
    env_logger::init().unwrap();
    let matches = args();

    let key_path = matches.value_of("key").unwrap();
    let output_path = matches.value_of("output").unwrap();

    info!("Reading private key: {}", key_path);

    let key_file = File::open(key_path).expect("private key file could not be opened");

    let mut lines = BufReader::new(key_file).lines();

    // private key format expected to be first
    let next_line = lines
        .next()
        .expect(&format!("missing Private-key-format line"))
        .unwrap();

    let (key, value) = split_field_value(&next_line);
    if "Private-key-format" != key {
        panic!("Private-key-format line not found: {}", next_line);
    }
    if "v1.2" != value {
        println!("WARNING: un-tested version {:?}", value);
    }

    // algorithm
    let next_line = lines
        .next()
        .expect(&format!("missing Algorithm line"))
        .unwrap();

    let (key, value) = split_field_value(&next_line);
    if key != "Algorithm" {
        panic!("Algorithm line not found: {}", next_line)
    }
    let algorithm_num = u8::from_str(value.split(" ").next().expect(&format!(
        "bad algorithm format, expected '# STR': {}",
        next_line
    ))).expect(&format!(
        "bad algorithm format, expected '# STR': {}",
        next_line
    ));

    let algorithm =
        Algorithm::from_u8(algorithm_num).expect(&format!("unsupported algorithm: {}", next_line));

    let pem_bytes = match algorithm {
        Algorithm::RSASHA256 => read_rsa(lines),
        _ => panic!("Algorithm currently not supported: {:?}", algorithm),
    };

    info!("Writing private key to pem: {}", output_path);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output_path)
        .expect(&format!("could not create file: {}", output_path));

    file.write_all(&pem_bytes)
        .expect(&format!("could not write to file: {}", output_path));
}

fn split_field_value(line: &str) -> (&str, &str) {
    let mut split = line.split(": ");
    let field: &str = split.next().expect(&format!("missing field: {}", line));
    let value: &str = split.next().expect(&format!("missing value: {}", line));

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
            BigNum::from_slice(&BASE64
                .decode(value.as_bytes())
                .expect(&format!("badly formated line, expected base64: {}", line)))
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
    ).unwrap();

    rsa.private_key_to_pem().unwrap()
}
