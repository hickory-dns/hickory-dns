// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! System configuration loading
//!
//! This module is responsible for parsing and returning the configuration from
//!  the host system. It will read from the default location on each operating
//!  system, e.g. most Unixes have this written to `/etc/resolv.conf`

use std::fs::File;
use std::io;
use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use resolv_conf;

use crate::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use crate::proto::rr::Name;
use crate::proto::xfer::Protocol;
use crate::ResolveError;

const DEFAULT_PORT: u16 = 53;

pub fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), ResolveError> {
    read_resolv_conf("/etc/resolv.conf")
}

fn read_resolv_conf<P: AsRef<Path>>(
    path: P,
) -> Result<(ResolverConfig, ResolverOpts), ResolveError> {
    let mut data = String::new();
    let mut file = File::open(path)?;
    file.read_to_string(&mut data)?;
    parse_resolv_conf(&data)
}

pub fn parse_resolv_conf<T: AsRef<[u8]>>(
    data: T,
) -> Result<(ResolverConfig, ResolverOpts), ResolveError> {
    let parsed_conf = resolv_conf::Config::parse(&data).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Error parsing resolv.conf: {e}"),
        )
    })?;
    into_resolver_config(parsed_conf)
}

// TODO: use a custom parsing error type maybe?
fn into_resolver_config(
    parsed_config: resolv_conf::Config,
) -> Result<(ResolverConfig, ResolverOpts), ResolveError> {
    let domain = if let Some(domain) = parsed_config.get_system_domain() {
        // The system domain name maybe appear to be valid to the resolv_conf
        // crate but actually be invalid. For example, if the hostname is "matt.schulte's computer"
        // In order to prevent a hostname which macOS or Windows would consider
        // valid from returning an error here we turn parse errors to options
        Name::from_str(domain.as_str()).ok()
    } else {
        None
    };

    // nameservers
    let mut nameservers = Vec::<NameServerConfig>::with_capacity(parsed_config.nameservers.len());
    for ip in &parsed_config.nameservers {
        nameservers.push(NameServerConfig {
            socket_addr: SocketAddr::new(ip.into(), DEFAULT_PORT),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            http_endpoint: None,
            trust_negative_responses: false,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
            bind_addr: None,
        });
        nameservers.push(NameServerConfig {
            socket_addr: SocketAddr::new(ip.into(), DEFAULT_PORT),
            protocol: Protocol::Tcp,
            tls_dns_name: None,
            http_endpoint: None,
            trust_negative_responses: false,
            #[cfg(feature = "dns-over-rustls")]
            tls_config: None,
            bind_addr: None,
        });
    }
    if nameservers.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "no nameservers found in config",
        ))?;
    }

    // search
    let mut search = vec![];
    for search_domain in parsed_config.get_last_search_or_domain() {
        // Ignore invalid search domains
        if search_domain == "--" {
            continue;
        }

        search.push(Name::from_str_relaxed(search_domain).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Error parsing resolv.conf: {e}"),
            )
        })?);
    }

    let config = ResolverConfig::from_parts(domain, search, nameservers);

    let options = ResolverOpts {
        ndots: parsed_config.ndots as usize,
        timeout: Duration::from_secs(u64::from(parsed_config.timeout)),
        attempts: parsed_config.attempts as usize,
        ..ResolverOpts::default()
    };

    Ok((config, options))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::rr::Name;
    use std::env;
    use std::net::*;
    use std::str::FromStr;

    fn empty_config(name_servers: Vec<NameServerConfig>) -> ResolverConfig {
        ResolverConfig::from_parts(None, vec![], name_servers)
    }

    fn nameserver_config(ip: &str) -> [NameServerConfig; 2] {
        let addr = SocketAddr::new(IpAddr::from_str(ip).unwrap(), 53);
        [
            NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                http_endpoint: None,
                trust_negative_responses: false,
                #[cfg(feature = "dns-over-rustls")]
                tls_config: None,
                bind_addr: None,
            },
            NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::Tcp,
                tls_dns_name: None,
                http_endpoint: None,
                trust_negative_responses: false,
                #[cfg(feature = "dns-over-rustls")]
                tls_config: None,
                bind_addr: None,
            },
        ]
    }

    fn tests_dir() -> String {
        let server_path = env::var("TDNS_WORKSPACE_ROOT").unwrap_or_else(|_| "../..".to_owned());
        format!("{server_path}/crates/resolver/tests")
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn test_name_server() {
        let parsed = parse_resolv_conf("nameserver 127.0.0.1").expect("failed");
        let cfg = empty_config(nameserver_config("127.0.0.1").to_vec());
        assert_eq!(cfg.name_servers(), parsed.0.name_servers());
        is_default_opts(parsed.1);
    }

    #[test]
    fn test_search() {
        let parsed = parse_resolv_conf("search localnet.\nnameserver 127.0.0.1").expect("failed");
        let mut cfg = empty_config(nameserver_config("127.0.0.1").to_vec());
        cfg.add_search(Name::from_str("localnet.").unwrap());
        assert_eq!(cfg.search(), parsed.0.search());
        is_default_opts(parsed.1);
    }

    #[test]
    fn test_skips_invalid_search() {
        let parsed =
            parse_resolv_conf("\n\nnameserver 127.0.0.53\noptions edns0 trust-ad\nsearch -- lan\n")
                .expect("failed");
        let mut cfg = empty_config(nameserver_config("127.0.0.53").to_vec());

        {
            assert_eq!(cfg.name_servers(), parsed.0.name_servers());
            is_default_opts(parsed.1);
        }

        // This is the important part, that the invalid `--` is skipped during parsing
        {
            cfg.add_search(Name::from_str("lan").unwrap());
            assert_eq!(cfg.search(), parsed.0.search());
        }
    }

    #[test]
    fn test_underscore_in_search() {
        let parsed =
            parse_resolv_conf("search Speedport_000\nnameserver 127.0.0.1").expect("failed");
        let mut cfg = empty_config(nameserver_config("127.0.0.1").to_vec());
        cfg.add_search(Name::from_str_relaxed("Speedport_000.").unwrap());
        assert_eq!(cfg.search(), parsed.0.search());
        is_default_opts(parsed.1);
    }

    #[test]
    fn test_domain() {
        let parsed = parse_resolv_conf("domain example.com\nnameserver 127.0.0.1").expect("failed");
        let mut cfg = empty_config(nameserver_config("127.0.0.1").to_vec());
        cfg.set_domain(Name::from_str("example.com").unwrap());
        assert_eq!(cfg, parsed.0);
        is_default_opts(parsed.1);
    }

    #[test]
    fn test_read_resolv_conf() {
        read_resolv_conf(format!("{}/resolv.conf-simple", tests_dir())).expect("simple failed");
        read_resolv_conf(format!("{}/resolv.conf-macos", tests_dir())).expect("macos failed");
        read_resolv_conf(format!("{}/resolv.conf-linux", tests_dir())).expect("linux failed");
    }

    /// Validate that all options set in `into_resolver_config()` are at default values
    fn is_default_opts(opts: ResolverOpts) {
        assert_eq!(opts.ndots, 1);
        assert_eq!(opts.timeout, Duration::from_secs(5));
        assert_eq!(opts.attempts, 2);
    }
}
