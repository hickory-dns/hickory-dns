// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
// Copyright 2017 Google LLC.
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#[macro_use]
extern crate clap;
extern crate data_encoding;
extern crate env_logger;
extern crate openssl;
extern crate trust_dns;
extern crate trust_dns_proto;
extern crate trust_dns_resolver;

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use clap::ArgMatches;

use trust_dns::rr::dnssec::Algorithm;
use trust_dns_proto::rr::dnssec::rdata::DNSSECRData;
use trust_dns_proto::rr::dnssec::rdata::DNSSECRecordType;
use trust_dns_proto::rr::record_data::RData;
use trust_dns_proto::rr::record_type::RecordType;
use trust_dns_resolver::Resolver;

fn args<'a>() -> ArgMatches<'a> {
    app_from_crate!().bin_name("get-root-ksk").get_matches()
}

pub fn main() {
    env_logger::init();
    let _matches = args();

    let resolver = Resolver::default().expect("coind not create resolver");
    let lookup = resolver
        .lookup(".", RecordType::DNSSEC(DNSSECRecordType::DNSKEY))
        .expect("query failed");

    for r in lookup.iter() {
        match r {
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) => {
                if !(dnskey.secure_entry_point() && dnskey.zone_key()) {
                    continue;
                }

                let key_tag = dnskey.calculate_key_tag().expect("key_tag failed");

                println!("found: tag: {} info: {:?}", key_tag, dnskey);
                let extension = match dnskey.algorithm() {
                    Algorithm::RSASHA1
                    | Algorithm::RSASHA1NSEC3SHA1
                    | Algorithm::RSASHA256
                    | Algorithm::RSASHA512 => "rsa",
                    Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => "ecdsa",
                    Algorithm::ED25519 => "ed25519",
                };

                let mut path = PathBuf::from("/tmp");
                path.push(format!("{}", key_tag));
                path.set_extension(extension);

                let mut file = OpenOptions::new();
                let mut file = file
                    .write(true)
                    .read(false)
                    .truncate(true)
                    .create(true)
                    .open(path)
                    .expect("couldn't open file for writing");

                file.write_all(dnskey.public_key())
                    .expect("failed to write to file");
            }
            _ => println!("unexpected response"),
        }
    }
}
