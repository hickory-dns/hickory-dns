// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use trust_dns::rr::Name;

#[derive(Debug, Eq, PartialEq)]
pub enum ConfigOption<'input> {
    /// BasicOptions are only list one per line
    Basic(BasicOption<'input>),
    /// Options are listed many per line...
    Advanced(Vec<AdvancedOption<'input>>),
}

#[derive(Debug, Eq, PartialEq)]
pub enum BasicOption<'input> {
    /// Name server IP address
    Nameserver(IpAddr),
    /// Local domain name
    Domain(Name),
    /// Search list for host-name lookup
    Search(Vec<Name>),
    /// Sort list for ordering ip addresses
    SortList(&'input str),
}

#[derive(Debug, Eq, PartialEq)]
pub enum AdvancedOption<'input> {
    /// Defaults to 1, where this number of dots is required before attempting the lookup as a FQDN.
    NumberOfDots(u8),
    /// Timeout in seconds
    Timeout(Duration),
    /// Number of attempts before giving up on requests
    Attempts(u8),
    /// Unsupported option, possibly "name" of "name:option"
    Unknown(&'input str, Option<&'input str>),
}

impl<'input> AdvancedOption<'input> {
    pub fn parse(option: &'input str) -> Self {
        let mut key_value = option.split(":");

        let key = key_value.next().expect(
            "check lalrpop for AdvancedOption case",
        );
        let value = key_value.next();
        match key {
            "ndots" => AdvancedOption::NumberOfDots(
                value.and_then(|s| u8::from_str(s).ok()).unwrap_or(1),
            ),
            "timeout" => AdvancedOption::Timeout(
                value
                    .and_then(|s| u64::from_str(s).ok())
                    .map(Duration::from_secs)
                    .unwrap_or(Duration::from_secs(5)),
            ),
            "attempts" => AdvancedOption::Attempts(
                value.and_then(|s| u8::from_str(s).ok()).unwrap_or(2),
            ),
            ref s => AdvancedOption::Unknown(s, value),
        }
    }
}

// #[derive(Debug, Eq, PartialEq)]
// pub struct IpAddrAndMask(pub IpAddr, pub Option<IpAddr>);

// impl IpAddrAndMask {
//     pub fn parse(input: &str) -> Self {
//         let mut ip_and_mask = input.split("/");

//         let ip = IpAddr::from_str(ip_and_mask.next().expect(
//             "check lalrpop for IpAddrAndMask case",
//         )).expect("bad ip addr");

//         let value = ip_and_mask.next().map(|s| IpAddr::from_str(s).expect("bad ip mask"));

//         IpAddrAndMask(ip, value)
//     }

//     pub fn unwrap_ip(self) -> IpAddr {
//         self.0
//     }
// }