// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::IpAddr;

use crate::rr::{Name, RData};

/// Types of this trait will can be attempted for conversion to an IP address
pub trait TryParseIp {
    /// Attempts to parse self into an RData::A or RData::AAAA, None is returned if not possible
    fn try_parse_ip(&self) -> Option<RData>;
}

impl TryParseIp for str {
    fn try_parse_ip(&self) -> Option<RData> {
        match self.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip4)) => Ok(RData::A(ip4)),
            Ok(IpAddr::V6(ip6)) => Ok(RData::AAAA(ip6)),
            Err(err) => Err(err),
        }
        .ok()
    }
}

impl TryParseIp for String {
    fn try_parse_ip(&self) -> Option<RData> {
        (self[..]).try_parse_ip()
    }
}

impl TryParseIp for Name {
    /// Always returns none for Name, it assumes something that is already a name, wants to be a name
    fn try_parse_ip(&self) -> Option<RData> {
        None
    }
}

impl<'a, T> TryParseIp for &'a T
where
    T: TryParseIp + ?Sized,
{
    fn try_parse_ip(&self) -> Option<RData> {
        TryParseIp::try_parse_ip(*self)
    }
}

#[test]
fn test_try_parse_ip() {
    use std::net::{Ipv4Addr, Ipv6Addr};

    assert_eq!(
        "127.0.0.1".try_parse_ip().expect("failed"),
        RData::A(Ipv4Addr::new(127, 0, 0, 1))
    );

    assert_eq!(
        "::1".try_parse_ip().expect("failed"),
        RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
    );

    assert!("example.com".try_parse_ip().is_none());
}
