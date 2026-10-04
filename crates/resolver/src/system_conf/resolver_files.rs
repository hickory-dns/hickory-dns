//! Domain-specific macOS resolver files.

use std::{fs, io, net::IpAddr, path::Path};

use crate::{
    config::{DomainRoute, NameServerConfig},
    proto::{ProtoError, rr::Name},
};

pub(super) fn read_routes(directory: &Path) -> Result<Vec<DomainRoute>, ProtoError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("reading {}: {error}", directory.display()).into()),
    };
    let mut paths = entries
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ProtoError::from(format!("reading resolver directory: {error}")))?;
    paths.sort();
    let mut routes = Vec::new();
    for path in paths {
        let metadata = fs::metadata(&path).map_err(|error| {
            ProtoError::from(format!("reading {} metadata: {error}", path.display()))
        })?;
        if !metadata.is_file() {
            continue;
        }
        let domain = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("resolver filename is not UTF-8")?;
        let contents = fs::read_to_string(&path)
            .map_err(|error| ProtoError::from(format!("reading {}: {error}", path.display())))?;
        routes.push(parse_route(domain, &contents)?);
    }
    Ok(routes)
}

fn parse_route(filename: &str, contents: &str) -> Result<DomainRoute, ProtoError> {
    let mut domain = filename;
    let mut addresses = Vec::new();
    let mut port = 53;
    let mut search_order = 0;
    let mut use_tcp = false;
    for line in contents.lines() {
        let line = line.split(['#', ';']).next().unwrap_or_default();
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("domain") => domain = fields.next().ok_or("missing resolver domain")?,
            Some("nameserver") => {
                let address = fields.next().ok_or("missing resolver nameserver")?;
                let (ip, server_port) = match address.parse::<IpAddr>() {
                    Ok(ip) => (ip, None),
                    Err(_) => {
                        let (ip, server_port) = address
                            .rsplit_once('.')
                            .ok_or("invalid resolver nameserver")?;
                        let ip = ip.parse::<IpAddr>().map_err(|error| {
                            ProtoError::from(format!("invalid resolver nameserver: {error}"))
                        })?;
                        let server_port = server_port
                            .parse::<u16>()
                            .ok()
                            .filter(|port| *port != 0)
                            .ok_or("invalid nameserver port")?;
                        (ip, Some(server_port))
                    }
                };
                addresses.push((ip, server_port));
            }
            Some("port") => {
                port = fields
                    .next()
                    .ok_or("missing resolver port")?
                    .parse::<u16>()
                    .map_err(|error| ProtoError::from(format!("invalid resolver port: {error}")))?;
                if port == 0 {
                    return Err("resolver port must be nonzero".into());
                }
            }
            Some("search_order") => {
                search_order = fields
                    .next()
                    .ok_or("missing resolver search_order")?
                    .parse::<u32>()
                    .map_err(|error| {
                        ProtoError::from(format!("invalid resolver search_order: {error}"))
                    })?;
            }
            Some("options") => {
                for option in fields {
                    match option {
                        "mdns" => {
                            return Err("multicast DNS in /etc/resolver is not supported".into());
                        }
                        "usevc" => use_tcp = true,
                        _ => {}
                    }
                }
            }
            // Search expansion and query options remain controlled by ResolverOpts. This
            // loader imports domain routing, server addresses, ports, and search order.
            _ => {}
        }
    }
    if addresses.is_empty() {
        addresses.push((IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), None));
    }
    let name_servers = addresses
        .into_iter()
        .map(|(address, server_port)| {
            let mut server = if use_tcp {
                NameServerConfig::tcp(address)
            } else {
                NameServerConfig::udp_and_tcp(address)
            };
            for connection in &mut server.connections {
                connection.port = server_port.unwrap_or(port);
            }
            server
        })
        .collect();
    let mut route = DomainRoute::new(Name::from_ascii(domain)?, name_servers);
    route.domain.set_fqdn(true);
    route.search_order = search_order;
    Ok(route)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_sets_domain_and_both_transports() {
        let route = parse_route("corp.example", "nameserver 192.0.2.53 # LAN\n").unwrap();
        assert_eq!(route.domain, Name::from_ascii("corp.example.").unwrap());
        assert_eq!(route.name_servers.len(), 1);
        assert_eq!(route.name_servers[0].connections.len(), 2);
        assert!(
            route.name_servers[0]
                .connections
                .iter()
                .all(|connection| connection.port == 53)
        );
    }

    #[test]
    fn explicit_domain_port_and_order_override_defaults() {
        let route = parse_route("alias", "domain corp.example.\nport 5353\nsearch_order 200\nnameserver 192.0.2.53\nnameserver 2001:db8::53\n").unwrap();
        assert_eq!(route.domain, Name::from_ascii("corp.example.").unwrap());
        assert_eq!(route.search_order, 200);
        assert_eq!(route.name_servers.len(), 2);
        assert!(
            route
                .name_servers
                .iter()
                .flat_map(|server| &server.connections)
                .all(|connection| connection.port == 5353)
        );
    }

    #[test]
    fn invalid_routing_configuration_is_an_error() {
        for contents in [
            "nameserver invalid",
            "port 0",
            "port 70000",
            "search_order -1",
            "domain",
            "options mdns",
        ] {
            assert!(parse_route("corp.example", contents).is_err(), "{contents}");
        }
    }

    #[test]
    fn no_server_file_uses_localhost_as_documented() {
        assert_eq!(
            parse_route("corp.example", "# no servers")
                .unwrap()
                .name_servers[0]
                .ip,
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
    }
    #[test]
    fn per_server_ports_override_resolver_port_and_usevc_selects_tcp() {
        let route = parse_route(
            "corp.example",
            "port 5353\noptions usevc\nnameserver 192.0.2.53.54\nnameserver 2001:db8::53.55\n",
        )
        .unwrap();
        assert_eq!(route.name_servers[0].connections[0].port, 54);
        assert_eq!(route.name_servers[1].connections[0].port, 55);
        assert!(
            route
                .name_servers
                .iter()
                .all(|server| server.connections.len() == 1)
        );
    }
}
