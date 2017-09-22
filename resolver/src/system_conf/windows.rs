// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! System configuration loading for windows

use std::io;
use std::str::FromStr;
use std::net::SocketAddr;

use ipconfig::get_adapters;
use ipconfig::computer::{get_search_list, get_domain, is_round_robin_enabled};

use trust_dns::rr::Name;
use config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol};


macro_rules! map_ipconfig_to_io_error {
    ($result:expr) => ($result.map_err(|e| io::Error::new(io::ErrorKind::Other, Box::new(e))));
}

/// Returns the name servers of the computer (of all adapters)
fn get_name_servers() -> io::Result<Vec<NameServerConfig>> {
    let adapters = map_ipconfig_to_io_error!(get_adapters())?;
    let mut name_servers = vec![];

    for dns_server in adapters.iter().flat_map(|adapter| adapter.dns_servers().iter()) {
        let socket_addr = SocketAddr::new(*dns_server, 53);
        name_servers.push(NameServerConfig {
            socket_addr,
            protocol: Protocol::Udp,
        });
        name_servers.push(NameServerConfig {
            socket_addr,
            protocol: Protocol::Tcp,
        });
    };
    Ok(name_servers)
}

pub(crate) fn read_system_conf() -> io::Result<(ResolverConfig, ResolverOpts)> {
    let name_servers = get_name_servers()?;

    let search_list: Vec<Name> = map_ipconfig_to_io_error!(get_search_list())?
        .iter()
        .map(|x| Name::from_str(x))
        .collect::<Result<Vec<_>, _>>()?;

    let domain = match map_ipconfig_to_io_error!(get_domain())? {
        Some(domain) => Name::from_str(&domain)?,
        None => Name::root(),
    };

    let config = ResolverConfig::from_parts(domain, search_list, name_servers);

    let rotate = map_ipconfig_to_io_error!(is_round_robin_enabled())?;

    let opts = ResolverOpts {
        rotate,
        ..Default::default()
    };
    Ok((config, opts))
}
