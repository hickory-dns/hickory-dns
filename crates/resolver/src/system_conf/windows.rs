// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! System configuration loading for windows

use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use ipconfig::computer::{get_domain, get_search_list};
use ipconfig::get_adapters;

use crate::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use crate::proto::ProtoError;
use crate::proto::rr::Name;

pub fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), ProtoError> {
    let adapters = get_adapters().map_err(|e| format!("ipconfig::get_adapters() failed: {e}"))?;

    let servers = adapters
        .iter()
        // Only take interfaces whose OperStatus is Up
        .filter(|adapter| adapter.oper_status() == ipconfig::OperStatus::IfOperStatusUp)
        .flat_map(|adapter| adapter.dns_servers());

    let mut name_servers = vec![];
    for &ip in servers {
        if let IpAddr::V6(ip) = ip {
            if FORBIDDEN_ADDRS.contains(&ip) {
                continue;
            }
        }

        name_servers.push(NameServerConfig::udp_and_tcp(ip));
    }

    let search_list = get_search_list()
        .map_err(|e| format!("ipconfig::get_search_list() failed: {e}"))?
        .iter()
        .map(|x| Name::from_str(x))
        .collect::<Result<Vec<_>, _>>()?;

    let domain = match get_domain().map_err(|e| format!("ipconfig::get_domain() failed: {e}"))? {
        Some(domain) => Name::from_str(&domain)?,
        None => Name::root(),
    };

    Ok((
        ResolverConfig::from_parts(Some(domain), search_list, name_servers),
        ResolverOpts::default(),
    ))
}

// https://datatracker.ietf.org/doc/html/draft-ietf-ipv6-dns-discovery-07
// [RFC 3879](https://datatracker.ietf.org/doc/html/rfc3879)
const FORBIDDEN_ADDRS: [Ipv6Addr; 3] = [
    Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 1), // fec0:0:0:ffff::1
    Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 2), // fec0:0:0:ffff::2
    Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 3), // fec0:0:0:ffff::3
];
