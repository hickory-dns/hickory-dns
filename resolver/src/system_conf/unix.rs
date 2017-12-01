// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! System configuration loading
//!
//! This module is resposible for parsing and returning the configuration from
//!  the host system. It will read from the default location on each operating
//!  system, e.g. most Unixes have this written to `/etc/resolv.conf`

use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use resolv_conf;

use trust_dns_proto::rr::Name;
use config::*;


pub(crate) fn read_system_conf() -> io::Result<(ResolverConfig, ResolverOpts)> {
    read_resolv_conf("/etc/resolv.conf")
}

fn read_resolv_conf<P: AsRef<Path>>(path: P) -> io::Result<(ResolverConfig, ResolverOpts)> {
    let mut data = String::new();
    let mut file = File::open(path)?;
    file.read_to_string(&mut data)?;
    parse_resolv_conf(&data)
}

fn parse_resolv_conf<T: AsRef<[u8]>>(data: T) -> io::Result<(ResolverConfig, ResolverOpts)> {
    let parsed_conf = resolv_conf::Config::parse(&data).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Error parsing resolv.conf: {:?}", e),
        )
    })?;
    into_resolver_config(parsed_conf)
}

// FIXME: use a custom parsing error type maybe?
fn into_resolver_config(
    parsed_config: resolv_conf::Config,
) -> io::Result<(ResolverConfig, ResolverOpts)> {
    // domain (for now, resolv_conf does not separate domain from nameservers)
    let domain = Name::root();

    // nameservers
    let mut nameservers = Vec::<NameServerConfig>::with_capacity(parsed_config.nameservers.len());
    for ip in &parsed_config.nameservers {
        nameservers.push(NameServerConfig {
            socket_addr: SocketAddr::new(ip.into(), 53),
            protocol: Protocol::Udp,
        });
        nameservers.push(NameServerConfig {
            socket_addr: SocketAddr::new(ip.into(), 53),
            protocol: Protocol::Tcp,
        });
    }
    if nameservers.is_empty() {
        warn!("no nameservers found in config");
    }

    // search
    let mut search = Vec::with_capacity(parsed_config.search.len());
    for search_domain in &parsed_config.search {
        search.push(Name::from_str(&search_domain).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Error parsing resolv.conf: {:?}", e),
            )
        })?);
    }

    let config = ResolverConfig::from_parts(domain, search, nameservers);

    let mut options = ResolverOpts::default();
    options.ndots = parsed_config.ndots as usize;
    options.timeout = Duration::from_secs(parsed_config.timeout as u64);
    options.attempts = parsed_config.attempts as usize;

    Ok((config, options))
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs::File;
    use std::io::Read;
    use std::net::*;
    use std::str::FromStr;
    use std::time::Duration;
    use trust_dns_proto::rr::Name;
    use super::*;

    fn empty_config() -> ResolverConfig {
        ResolverConfig::from_parts(Name::root(), vec![], vec![])
    }

    fn nameserver_config(ip: &str) -> [NameServerConfig; 2] {
        let addr = SocketAddr::new(IpAddr::from_str(ip).unwrap(), 53);
        [
            NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::Udp,
            },
            NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::Tcp,
            },
        ]
    }

    fn tests_dir() -> String {
        let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or(".".to_owned());
        format!{"{}/../resolver/tests", server_path}
    }

    #[test]
    fn test_name_server() {
        let parsed = parse_resolv_conf("nameserver 127.0.0.1").expect("failed");
        let mut cfg = empty_config();
        let nameservers = nameserver_config("127.0.0.1");
        cfg.add_name_server(nameservers[0]);
        cfg.add_name_server(nameservers[1]);
        assert_eq!(cfg, parsed.0);
        assert_eq!(ResolverOpts::default(), parsed.1);
    }

    #[test]
    fn test_search() {
        let parsed = parse_resolv_conf("search localnet.").expect("failed");
        let mut cfg = empty_config();
        cfg.add_search(Name::from_str("localnet.").unwrap());
        assert_eq!(cfg, parsed.0);
        assert_eq!(ResolverOpts::default(), parsed.1);
    }

    #[test]
    fn test_domain() {
        // FIXME: We're not doing the right thing here...
        // Clearly, seach should be empty and domain should not be "."
        let parsed = parse_resolv_conf("domain example.com").expect("failed");
        let mut cfg = empty_config();
        cfg.add_search(Name::from_str("example.com").unwrap());
        assert_eq!(cfg, parsed.0);
        assert_eq!(ResolverOpts::default(), parsed.1);
    }

    #[test]
    fn test_read_resolv_conf() {
        read_resolv_conf(format!("{}/resolv.conf-simple", tests_dir())).expect("simple failed");
        read_resolv_conf(format!("{}/resolv.conf-macos", tests_dir())).expect("macos failed");
        read_resolv_conf(format!("{}/resolv.conf-linux", tests_dir())).expect("linux failed");
    }

    // #[test]
    // fn test_ip_addr() {
    //     let mut errors = Vec::new();
    //     assert_eq!(
    //         resolv_conf::parse_basic_option(&mut errors, "nameserver 127.0.0.1").expect("failed"),
    //         BasicOption::Nameserver(IpAddr::from_str("127.0.0.1").unwrap())
    //     );

    //     assert_eq!(
    //         resolv_conf::parse_basic_option(&mut errors, "nameserver ::1").expect("failed"),
    //         BasicOption::Nameserver(IpAddr::from_str("::1").unwrap())
    //     );

    //     assert_eq!(
    //         resolv_conf::parse_basic_option(
    //             &mut errors,
    //             "nameserver 2001:db8:85a3:8d3:1319:8a2e:370:7348",
    //         ).expect("failed"),
    //         BasicOption::Nameserver(
    //             IpAddr::from_str("2001:db8:85a3:8d3:1319:8a2e:370:7348").unwrap(),
    //         )
    //     );

    //     assert_eq!(
    //         resolv_conf::parse_basic_option(&mut errors, "nameserver ::ffff:192.0.2.128")
    //             .expect("failed"),
    //         BasicOption::Nameserver(IpAddr::from_str("::ffff:192.0.2.128").unwrap())
    //     );
    // }

    // #[test]
    // fn test_name() {
    //     let mut errors = Vec::new();
    //     assert_eq!(
    //         resolv_conf::parse_name(&mut errors, ".").unwrap(),
    //         Name::from_labels::<String>(vec![])
    //     );

    //     assert_eq!(
    //         resolv_conf::parse_name(&mut errors, "com.").unwrap(),
    //         Name::from_labels(vec!["com"])
    //     );

    //     assert_eq!(
    //         resolv_conf::parse_name(&mut errors, "example.com.").unwrap(),
    //         Name::from_labels(vec!["example", "com"])
    //     );
    // }

    // #[test]
    // fn test_config_line() {
    //     let mut errors = Vec::new();
    //     // no comment
    //     assert_eq!(
    //         resolv_conf::parse_config_line(&mut errors, "nameserver 127.0.0.1").expect("failed"),
    //         Some(ConfigOption::Basic(BasicOption::Nameserver(
    //             IpAddr::from_str("127.0.0.1").unwrap(),
    //         )))
    //     );

    //     assert_eq!(
    //         resolv_conf::parse_config_line(&mut errors, "nameserver 127.0.0.1; a comment")
    //             .expect("failed"),
    //         Some(ConfigOption::Basic(BasicOption::Nameserver(
    //             IpAddr::from_str("127.0.0.1").unwrap(),
    //         )))
    //     );

    //     assert_eq!(
    //         resolv_conf::parse_config_line(&mut errors, "nameserver 127.0.0.1# a comment")
    //             .expect("failed"),
    //         Some(ConfigOption::Basic(BasicOption::Nameserver(
    //             IpAddr::from_str("127.0.0.1").unwrap(),
    //         )))
    //     );

    //     assert_eq!(
    //         resolv_conf::parse_config_line(&mut errors, "nameserver 127.0.0.1 #a comment")
    //             .expect("failed"),
    //         Some(ConfigOption::Basic(BasicOption::Nameserver(
    //             IpAddr::from_str("127.0.0.1").unwrap(),
    //         )))
    //     );

    //     assert_eq!(
    //         resolv_conf::parse_config_line(&mut errors, "nameserver 127.0.0.1 # a comment")
    //             .expect("failed"),
    //         Some(ConfigOption::Basic(BasicOption::Nameserver(
    //             IpAddr::from_str("127.0.0.1").unwrap(),
    //         )))
    //     );

    //     assert_eq!(
    //         resolv_conf::parse_config_line(&mut errors, "options ndots:8 # a comment")
    //             .expect("failed"),
    //         Some(ConfigOption::Advanced(
    //             vec![AdvancedOption::NumberOfDots(8)],
    //         ))
    //     );

    //     // only comment
    //     assert_eq!(
    //         resolv_conf::parse_config_line(&mut errors, "# a comment").expect("failed"),
    //         None
    //     );
    // }

    // #[test]
    // fn test_advanced_option() {
    //     let mut errors = Vec::new();
    //     assert_eq!(
    //         resolv_conf::parse_advanced_option(&mut errors, "ndots:8").expect("failed"),
    //         AdvancedOption::NumberOfDots(8)
    //     );

    //     assert_eq!(
    //         resolv_conf::parse_advanced_option(&mut errors, "timeout:8").expect("failed"),
    //         AdvancedOption::Timeout(Duration::from_secs(8))
    //     );

    //     assert_eq!(
    //         resolv_conf::parse_advanced_option(&mut errors, "attempts:8").expect("failed"),
    //         AdvancedOption::Attempts(8)
    //     );
    // }

    // #[test]
    // fn test_advanced_options() {
    //     let mut errors = Vec::new();
    //     assert_eq!(
    //         resolv_conf::parse_advanced_options(
    //             &mut errors,
    //             "options ndots:8 timeout:8 attempts:8"
    //         ).expect("failed"),
    //         vec![
    //             AdvancedOption::NumberOfDots(8),
    //             AdvancedOption::Timeout(Duration::from_secs(8)),
    //             AdvancedOption::Attempts(8),
    //         ]
    //     );
    // }

    // #[test]
    // fn test_resolv_conf_macos() {
    //     let mut data = String::new();
    //     let mut file = File::open(format!("{}/resolv.conf-macos", tests_dir())).unwrap();
    //     file.read_to_string(&mut data).unwrap();

    //     let configuration = vec![
    //         ConfigOption::Advanced(vec![
    //             AdvancedOption::NumberOfDots(8),
    //             AdvancedOption::Timeout(Duration::from_secs(8)),
    //             AdvancedOption::Attempts(8),
    //         ]),
    //         ConfigOption::Basic(BasicOption::Domain(
    //             Name::from_labels(vec!["example", "com"]),
    //         )),
    //         ConfigOption::Basic(BasicOption::Search(vec![
    //             Name::from_labels(vec!["example", "com"]),
    //             Name::from_labels(vec!["sub", "example", "com"]),
    //         ])),
    //         ConfigOption::Basic(BasicOption::Nameserver(
    //             IpAddr::from_str("2001:4860:4860::8888").unwrap(),
    //         )),
    //         ConfigOption::Basic(BasicOption::Nameserver(
    //             IpAddr::from_str("2001:4860:4860::8844").unwrap(),
    //         )),
    //         ConfigOption::Basic(BasicOption::Nameserver(
    //             IpAddr::from_str("8.8.8.8").unwrap(),
    //         )),
    //         ConfigOption::Basic(BasicOption::Nameserver(
    //             IpAddr::from_str("8.8.4.4").unwrap(),
    //         )),
    //     ];

    //     let mut errors = Vec::new();
    //     assert_eq!(
    //         resolv_conf::parse_config(&mut errors, &data).expect("failed"),
    //         configuration
    //     );
    // }

    // #[test]
    // fn test_resolv_conf_linux() {
    //     let mut data = String::new();
    //     let mut file = File::open(format!("{}/resolv.conf-linux", tests_dir())).unwrap();
    //     file.read_to_string(&mut data).unwrap();

    //     let configuration = vec![
    //         ConfigOption::Advanced(vec![
    //             AdvancedOption::NumberOfDots(8),
    //             AdvancedOption::Timeout(Duration::from_secs(8)),
    //             AdvancedOption::Attempts(8),
    //         ]),
    //         ConfigOption::Basic(BasicOption::Domain(
    //             Name::from_labels(vec!["example", "com"]),
    //         )),
    //         ConfigOption::Basic(BasicOption::Search(vec![
    //             Name::from_labels(vec!["example", "com"]),
    //             Name::from_labels(vec!["sub", "example", "com"]),
    //         ])),
    //         ConfigOption::Basic(BasicOption::Nameserver(
    //             IpAddr::from_str("2001:4860:4860::8888").unwrap(),
    //         )),
    //         ConfigOption::Basic(BasicOption::Nameserver(
    //             IpAddr::from_str("2001:4860:4860::8844").unwrap(),
    //         )),
    //         ConfigOption::Basic(BasicOption::Nameserver(
    //             IpAddr::from_str("8.8.8.8").unwrap(),
    //         )),
    //         ConfigOption::Basic(BasicOption::Nameserver(
    //             IpAddr::from_str("8.8.4.4").unwrap(),
    //         )),
    //         ConfigOption::Advanced(vec![AdvancedOption::Unknown("rotate", None)]),
    //         ConfigOption::Advanced(vec![
    //             AdvancedOption::Unknown("inet6", None),
    //             AdvancedOption::Unknown("no-tld-query", None),
    //         ]),
    //         ConfigOption::Basic(BasicOption::SortList(
    //             vec!["130.155.160.0/255.255.240.0", "130.155.0.0"],
    //         )),
    //     ];

    //     let mut errors = Vec::new();
    //     assert_eq!(
    //         resolv_conf::parse_config(&mut errors, &data).expect("failed"),
    //         configuration
    //     );
    // }
}
