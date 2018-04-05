//! Hosts result from a configuration of `/etc/hosts`

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use lookup::Lookup;
use trust_dns_proto::op::Query;
use trust_dns_proto::rr::domain::TryParseIp;
use trust_dns_proto::rr::{Name, RData, RecordType};

#[derive(Debug, Default)]
struct LookupType {
    /// represents the A record type
    a: Option<Lookup>,
    /// represents the AAAA record type
    aaaa: Option<Lookup>,
}

/// Configuration for the local `/etc/hosts`
#[derive(Debug, Default)]
pub struct Hosts {
    /// Name -> RDatas map
    by_name: HashMap<Name, LookupType>,
}

impl Hosts {
    /// Creates a new configuration from /etc/hosts, only works for unix like OSes,
    /// others will return empty configuration
    pub fn new() -> Hosts {
        read_hosts_conf("/etc/hosts").unwrap_or_default()
    }

    /// lookup_static_host looks up the addresses for the given host from /etc/hosts.
    pub fn lookup_static_host(&self, query: &Query) -> Option<Lookup> {
        if !self.by_name.is_empty() {
            if let Some(val) = self.by_name.get(query.name()) {
                let result = match query.query_type() {
                    RecordType::A => val.a.clone(),
                    RecordType::AAAA => val.aaaa.clone(),
                    _ => None,
                };

                return result;
            }
        }
        None
    }

    /// Insert a new Lookup for the associated `Name` and `RecordType`
    pub fn insert(&mut self, name: Name, record_type: RecordType, lookup: Lookup) {
        assert!(record_type == RecordType::A || record_type == RecordType::AAAA);

        let lookup_type = self.by_name
            .entry(name.clone())
            .or_insert_with(|| LookupType::default());

        let new_lookup = {
            let mut old_lookup = match &record_type {
                &RecordType::A => lookup_type
                    .a
                    .get_or_insert_with(|| Lookup::new(Arc::new(vec![]))),
                &RecordType::AAAA => lookup_type
                    .aaaa
                    .get_or_insert_with(|| Lookup::new(Arc::new(vec![]))),
                _ => {
                    warn!("unsupported IP type from Hosts file: {:#?}", record_type);
                    return;
                }
            };

            old_lookup.append(lookup)
        };

        // replace the appended version
        match &record_type {
            &RecordType::A => lookup_type.a = Some(new_lookup),
            &RecordType::AAAA => lookup_type.aaaa = Some(new_lookup),
            _ => warn!("unsupported IP type from Hosts file"),
        }
    }
}

/// parse configuration from `/etc/hosts`
#[cfg(unix)]
pub fn read_hosts_conf<P: AsRef<Path>>(path: P) -> io::Result<Hosts> {
    let mut hosts = Hosts {
        by_name: HashMap::new(),
    };

    // lines in the file should have the form `addr host1 host2 host3 ...`
    // line starts with `#` will be regarded with comments and ignored,
    // also empty line also will be ignored,
    // if line only include `addr` without `host` will be ignored,
    // file will parsed to map in the form `Name -> LookUp`.
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
        let addr = if let Some(a) = fields[0].try_parse_ip() {
            a
        } else {
            warn!("could not parse an IP from hosts file");
            continue;
        };

        for domain in fields.iter().skip(1).map(|domain| domain.to_lowercase()) {
            if let Ok(name) = Name::from_str(&domain) {
                let lookup = Lookup::new(Arc::new(vec![addr.clone()]));
                match &addr {
                    &RData::A(..) => hosts.insert(name.clone(), RecordType::A, lookup),
                    &RData::AAAA(..) => hosts.insert(name.clone(), RecordType::AAAA, lookup),
                    _ => {
                        warn!("unsupported IP type from Hosts file: {:#?}", addr);
                        continue;
                    }
                };

                // TODO: insert reverse lookup as well.
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

#[cfg(unix)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn tests_dir() -> String {
        let server_path = env::var("TDNS_SERVER_SRC_ROOT").unwrap_or(".".to_owned());
        format!{"{}/../resolver/tests", server_path}
    }

    #[test]
    fn test_read_hosts_conf() {
        let path = format!("{}/hosts", tests_dir());
        let hosts = read_hosts_conf(&path).unwrap();

        let name = Name::from_str("localhost").unwrap();
        let rdatas = hosts
            .lookup_static_host(&Query::query(name.clone(), RecordType::A))
            .unwrap()
            .iter()
            .map(|r| r.to_owned())
            .collect::<Vec<RData>>();

        assert_eq!(rdatas, vec![RData::A(Ipv4Addr::new(127, 0, 0, 1))]);

        let rdatas = hosts
            .lookup_static_host(&Query::query(name.clone(), RecordType::AAAA))
            .unwrap()
            .iter()
            .map(|r| r.to_owned())
            .collect::<Vec<RData>>();

        assert_eq!(
            rdatas,
            vec![RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]
        );

        let name = Name::from_str("broadcasthost").unwrap();
        let rdatas = hosts
            .lookup_static_host(&Query::query(name.clone(), RecordType::A))
            .unwrap()
            .iter()
            .map(|r| r.to_owned())
            .collect::<Vec<RData>>();
        assert_eq!(rdatas, vec![RData::A(Ipv4Addr::new(255, 255, 255, 255))]);

        let name = Name::from_str("example.com").unwrap();
        let rdatas = hosts
            .lookup_static_host(&Query::query(name.clone(), RecordType::A))
            .unwrap()
            .iter()
            .map(|r| r.to_owned())
            .collect::<Vec<RData>>();
        assert_eq!(rdatas, vec![RData::A(Ipv4Addr::new(10, 0, 1, 102))]);

        let name = Name::from_str("a.example.com").unwrap();
        let rdatas = hosts
            .lookup_static_host(&Query::query(name.clone(), RecordType::A))
            .unwrap()
            .iter()
            .map(|r| r.to_owned())
            .collect::<Vec<RData>>();
        assert_eq!(rdatas, vec![RData::A(Ipv4Addr::new(10, 0, 1, 111))]);

        let name = Name::from_str("b.example.com").unwrap();
        let rdatas = hosts
            .lookup_static_host(&Query::query(name.clone(), RecordType::A))
            .unwrap()
            .iter()
            .map(|r| r.to_owned())
            .collect::<Vec<RData>>();
        assert_eq!(rdatas, vec![RData::A(Ipv4Addr::new(10, 0, 1, 111))]);
    }
}
