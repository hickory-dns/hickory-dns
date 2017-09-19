//! Hosts result from a configuration of `/etc/hosts`

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader};
use std::fs::File;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::path::Path;

use trust_dns::rr::{Name, RData};

/// Configuration for the local `/etc/hosts`
#[derive(Debug, Default, Clone)]
pub struct Hosts {
    /// Name -> RDatas map
    by_name: HashMap<Name, Vec<RData>>,
}

impl Hosts {
    /// Creates a new configuration from /etc/hosts, only works for unix like OSes,
    /// others will return empty configuration
    pub fn new() -> Hosts {
        read_hosts_conf("/etc/hosts").unwrap_or_default()
    }

    // lookup_static_host looks up the addresses for the given host from /etc/hosts.
    pub fn lookup_static_host(&self, name: &Name) -> Option<Vec<RData>> {
        if self.by_name.len() > 0 {
            if let Some(val) = self.by_name.get(name) {
                return Some(val.to_vec());
            }
        }
        None
    }
}

#[cfg(unix)]
pub fn read_hosts_conf<P: AsRef<Path>>(path: P) -> io::Result<Hosts> {
    let mut hosts = Hosts {
        by_name: HashMap::new(),
    };

    let file = File::open(path)?;

    for line in BufReader::new(file).lines() {
        let line = line.unwrap_or_default();
        let line = if let Some(pos) = line.find('#') {
            String::from(line.split_at(pos).0)
        } else {
            line
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let fields: Vec<String> = line.split_whitespace().map(|s| s.to_string()).collect();
        if fields.len() < 2 {
            continue;
        }
        let addr = if let Some(a) = parse_literal_ip(&fields[0]) {
            a
        } else {
            continue;
        };

        for i in 1..fields.len() {
            let domain = fields[i].to_lowercase();
            if let Ok(name) = Name::from_str(&domain) {
                hosts
                    .by_name
                    .entry(name)
                    .or_insert(vec![])
                    .push(addr.clone());
            };
        }
    }

    Ok(hosts)
}

#[cfg(not(unix))]
pub fn read_hosts_conf<P: AsRef<Path>>(path: P) -> io::Result<Hosts> {
    Err(io::Error::new(
        io::ErrorKind::Other,
        "Non-Posix systems currently not supported".to_string(),
    ))
}

/// parse &str to RData::A or RData::AAAA
pub fn parse_literal_ip(addr: &str) -> Option<RData> {
    if let Ok(ip4) = addr.parse::<Ipv4Addr>() {
        return Some(RData::A(ip4));
    }
    if let Ok(ip6) = addr.parse::<Ipv6Addr>() {
        return Some(RData::AAAA(ip6));
    }

    None
}

#[cfg(unix)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn tests_dir() -> String {
        let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or(".".to_owned());
        format!{"{}/../resolver/tests", server_path}
    }

    #[test]
    fn test_parse_literal_ip() {
        assert_eq!(
            parse_literal_ip("127.0.0.1").expect("failed"),
            RData::A(Ipv4Addr::new(127, 0, 0, 1))
        );

        assert_eq!(
            parse_literal_ip("::1").expect("failed"),
            RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
        );

        assert!(parse_literal_ip("example.com").is_none());
    }

    #[test]
    fn test_read_hosts_conf() {
        let path = format!("{}/hosts", tests_dir());
        let hosts = read_hosts_conf(&path).unwrap();

        let name = Name::from_str("localhost").unwrap();
        assert_eq!(
            hosts.lookup_static_host(&name),
            Some(vec![
                RData::A(Ipv4Addr::new(127, 0, 0, 1)),
                RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ])
        );

        let name = Name::from_str("broadcasthost").unwrap();
        assert_eq!(
            hosts.lookup_static_host(&name),
            Some(vec![RData::A(Ipv4Addr::new(255, 255, 255, 255))])
        );

        let name = Name::from_str("example.com").unwrap();
        assert_eq!(
            hosts.lookup_static_host(&name),
            Some(vec![RData::A(Ipv4Addr::new(10, 0, 1, 102))])
        );

        let name = Name::from_str("a.example.com").unwrap();
        assert_eq!(
            hosts.lookup_static_host(&name),
            Some(vec![RData::A(Ipv4Addr::new(10, 0, 1, 111))])
        );

        let name = Name::from_str("b.example.com").unwrap();
        assert_eq!(
            hosts.lookup_static_host(&name),
            Some(vec![RData::A(Ipv4Addr::new(10, 0, 1, 111))])
        );
    }
}
