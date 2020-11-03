// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! System configuration loading for windows

use std::net::SocketAddr;
use std::str::FromStr;

use ipconfig::computer::{get_domain, get_search_list, is_round_robin_enabled};
use ipconfig::get_adapters;

use proto::rr::Name;

use crate::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use crate::error::*;

/// Returns the name servers of the computer (of all adapters)
fn get_name_servers() -> ResolveResult<Vec<NameServerConfig>> {
    let adapters = get_adapters()?;
    let mut name_servers = vec![];

    for dns_server in adapters
        .iter()
        .flat_map(|adapter| adapter.dns_servers().iter())
    {
        let socket_addr = SocketAddr::new(*dns_server, 53);
        name_servers.push(NameServerConfig {
            socket_addr,
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_nx_responses: false,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
            bind_addr: None,
        });
        name_servers.push(NameServerConfig {
            socket_addr,
            protocol: Protocol::Tcp,
            tls_dns_name: None,
            trust_nx_responses: false,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
            bind_addr: None,
        });
    }
    Ok(name_servers)
}

pub fn read_system_conf() -> ResolveResult<(ResolverConfig, ResolverOpts)> {
    let name_servers = get_name_servers()?;

    let search_list: Vec<Name> = get_search_list()?
        .iter()
        .map(|x| Name::from_str(x))
        .collect::<Result<Vec<_>, _>>()?;

    let domain = match get_domain()? {
        Some(domain) => Name::from_str(&domain)?,
        None => Name::root(),
    };

    let config = ResolverConfig::from_parts(Some(domain), search_list, name_servers);

    let rotate = is_round_robin_enabled()?;

    let opts = ResolverOpts {
        rotate,
        ..Default::default()
    };
    Ok((config, opts))
}
