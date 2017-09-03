// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Structs for creating and using a ResolverFuture
use std::io;
use std::str::FromStr;

use tokio_core::reactor::Handle;
use trust_dns::client::{RetryClientHandle, SecureClientHandle};
use trust_dns::rr::Name;

use config::{ResolverConfig, ResolverOpts};
use lru::DnsLru;
use name_server_pool::NameServerPool;
use lookup_ip::{InnerLookupIpFuture, LookupIpEither, LookupIpFuture};
use system_conf;

/// A Resolver for DNS records.
pub struct ResolverFuture {
    config: ResolverConfig,
    options: ResolverOpts,
    client_cache: DnsLru<LookupIpEither>,
}

impl ResolverFuture {
    /// Construct a new ResolverFuture with the associated Client.
    pub fn new(config: ResolverConfig, options: ResolverOpts, reactor: &Handle) -> Self {
        let pool = NameServerPool::from_config(&config, &options, reactor);
        let either;
        let client = RetryClientHandle::new(pool.clone(), options.attempts);
        if options.validate {
            either = LookupIpEither::Secure(SecureClientHandle::new(client));
        } else {
            either = LookupIpEither::Retry(client);
        }

        ResolverFuture {
            config,
            options,
            client_cache: DnsLru::new(options.cache_size, either),
        }
    }

    /// Constructs a new Resolver with the given ClientConnection, see UdpClientConnection and/or TcpCLientConnection
    ///
    /// This will read the systems `/etc/cresolv.conf`. Only Unix like OSes are currently supported.
    pub fn from_system_conf(reactor: &Handle) -> io::Result<Self> {
        let (config, options) = system_conf::read_system_conf()?;
        Ok(Self::new(config, options, reactor))
    }

    /// Performs a DNS lookup for the IP for the given hostname.
    ///
    /// Based on the configuration and options passed in, this may do either a A or a AAAA lookup,
    ///  returning IpV4 or IpV6 addresses. (*Note*: current release only queries A, IPv4). For the least expensive query
    ///  a fully-qualified-domain-name, FQDN, which ends in a final `.`, e.g. `www.example.com.`, will only issue one query.
    ///  anything else will always incur the cost of querying the `ResolverConfig::domain` and `ResolverConfig::search`.
    ///
    /// # Arguments
    /// * `host` - string hostname, if this is an invalid hostname, an error will be returned from the returned future.
    pub fn lookup_ip(&mut self, host: &str) -> LookupIpFuture {
        let name = match Name::from_str(host) {
            Ok(name) => name,
            Err(err) => {
                return InnerLookupIpFuture::error(self.client_cache.clone(), err);
            }
        };

        // if it's fully qualified, we can short circuit the lookup logic
        let names = if name.is_fqdn() {
            vec![name]
        } else {
            // Otherwise we have to build the search list
            // Note: the vec is built in reverse order of precedence, for stack semantics
            let mut names =
                Vec::<Name>::with_capacity(1 /*FQDN*/ + 1 /*DOMAIN*/ + self.config.search().len());

            for search in self.config.search().iter().rev() {
                let name_search = name.clone().append_domain(search);
                Self::push_name(name_search, &mut names);
            }

            let domain = name.clone().append_domain(&self.config.domain());
            Self::push_name(domain, &mut names);

            // this is the direct name lookup
            // number of dots will always be one less than the number of labels
            if name.num_labels() as usize > self.options.ndots {
                // adding the name as though it's an FQDN for lookup
                names.push(name.clone());
            }

            names
        };

        LookupIpFuture::lookup(
            names,
            self.options.ip_strategy,
            &mut self.client_cache.clone(),
        )
    }

    fn push_name(name: Name, names: &mut Vec<Name>) {
        if !names.contains(&name) {
            names.push(name);
        }
    }

    // TODO: generic lookup
    // pub fn lookup(&mut self, host: &str) -> Lookup {

    // }
}



#[cfg(test)]
mod tests {
    extern crate tokio_core;

    use std::net::*;

    use self::tokio_core::reactor::Core;

    use config::{NameServerConfig, LookupIpStrategy};

    use super::*;

    #[test]
    fn test_lookup() {
        let mut io_loop = Core::new().unwrap();
        let mut resolver = ResolverFuture::new(
            ResolverConfig::default(),
            ResolverOpts::default(),
            &io_loop.handle(),
        );

        let response = io_loop.run(resolver.lookup_ip("www.example.com.")).expect(
            "failed to run lookup",
        );

        assert_eq!(response.iter().count(), 2);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(*address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                assert_eq!(
                    *address,
                    IpAddr::V6(Ipv6Addr::new(
                        0x2606,
                        0x2800,
                        0x220,
                        0x1,
                        0x248,
                        0x1893,
                        0x25c8,
                        0x1946,
                    ))
                );
            }
        }
    }

    #[test]
    #[ignore] // these appear to not work on travis
    fn test_sec_lookup() {
        let mut io_loop = Core::new().unwrap();
        let mut resolver = ResolverFuture::new(
            ResolverConfig::default(),
            ResolverOpts {
                validate: true,
                ..ResolverOpts::default()
            },
            &io_loop.handle(),
        );

        let response = io_loop.run(resolver.lookup_ip("www.example.com.")).expect(
            "failed to run lookup",
        );

        assert_eq!(response.iter().count(), 2);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(*address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                assert_eq!(
                    *address,
                    IpAddr::V6(Ipv6Addr::new(
                        0x2606,
                        0x2800,
                        0x220,
                        0x1,
                        0x248,
                        0x1893,
                        0x25c8,
                        0x1946,
                    ))
                );
            }
        }
    }

    #[test]
    #[ignore] // these appear to not work on travis
    fn test_sec_lookup_fails() {
        let mut io_loop = Core::new().unwrap();
        let mut resolver = ResolverFuture::new(
            ResolverConfig::default(),
            ResolverOpts {
                validate: true,
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
            &io_loop.handle(),
        );

        // needs to be a domain that exists, but is not signed (eventually this will be)
        let response = io_loop.run(resolver.lookup_ip("www.trust-dns.org."));

        assert!(response.is_err());
        let error = response.unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(
            format!("{}", error.into_inner().unwrap()),
            "ClientError: no RRSIGs available for validation: www.trust-dns.org., A"
        );
    }

    #[test]
    #[ignore]
    fn test_system_lookup() {
        let mut io_loop = Core::new().unwrap();
        let mut resolver = ResolverFuture::from_system_conf(&io_loop.handle()).unwrap();

        let response = io_loop.run(resolver.lookup_ip("www.example.com.")).expect(
            "failed to run lookup",
        );

        assert_eq!(response.iter().count(), 2);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(*address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                assert_eq!(
                    *address,
                    IpAddr::V6(Ipv6Addr::new(
                        0x2606,
                        0x2800,
                        0x220,
                        0x1,
                        0x248,
                        0x1893,
                        0x25c8,
                        0x1946,
                    ))
                );
            }
        }
    }

    #[test]
    fn test_fqdn() {
        let domain = Name::from_str("incorrect.example.com.").unwrap();
        let search = vec![
            Name::from_str("bad.example.com.").unwrap(),
            Name::from_str("wrong.example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let mut io_loop = Core::new().unwrap();
        let mut resolver = ResolverFuture::new(
            ResolverConfig::from_parts(domain, search, name_servers),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
            &io_loop.handle(),
        );

        let response = io_loop.run(resolver.lookup_ip("www.example.com.")).expect(
            "failed to run lookup",
        );

        assert_eq!(response.iter().count(), 1);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(*address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                assert!(false, "should only be looking up IPv4");
            }
        }
    }

    #[test]
    fn test_ndots() {
        let domain = Name::from_str("incorrect.example.com.").unwrap();
        let search = vec![
            Name::from_str("bad.example.com.").unwrap(),
            Name::from_str("wrong.example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let mut io_loop = Core::new().unwrap();
        let mut resolver = ResolverFuture::new(
            ResolverConfig::from_parts(domain, search, name_servers),
            ResolverOpts {
                // our name does have 2, the default should be fine, let's just narrow the test criteria a bit.
                ndots: 2,
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
            &io_loop.handle(),
        );

        // notice this is not a FQDN, no trailing dot.
        let response = io_loop.run(resolver.lookup_ip("www.example.com")).expect(
            "failed to run lookup",
        );

        assert_eq!(response.iter().count(), 1);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(*address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                assert!(false, "should only be looking up IPv4");
            }
        }
    }

    #[test]
    fn test_domain_search() {
        // domain is good now, shoudl be combined with the name to form www.example.com
        let domain = Name::from_str("example.com.").unwrap();
        let search = vec![
            Name::from_str("bad.example.com.").unwrap(),
            Name::from_str("wrong.example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let mut io_loop = Core::new().unwrap();
        let mut resolver = ResolverFuture::new(
            ResolverConfig::from_parts(domain, search, name_servers),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
            &io_loop.handle(),
        );

        // notice no dots, should not trigger ndots rule
        let response = io_loop.run(resolver.lookup_ip("www")).expect(
            "failed to run lookup",
        );

        assert_eq!(response.iter().count(), 1);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(*address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                assert!(false, "should only be looking up IPv4");
            }
        }
    }

    #[test]
    fn test_search_list() {
        let domain = Name::from_str("incorrect.example.com.").unwrap();
        let search = vec![
            // let's skip one search domain to test the loop...
            Name::from_str("bad.example.com.").unwrap(),
            // this should combine with the search name to form www.example.com
            Name::from_str("example.com.").unwrap(),
        ];
        let name_servers: Vec<NameServerConfig> =
            ResolverConfig::default().name_servers().to_owned();

        let mut io_loop = Core::new().unwrap();
        let mut resolver = ResolverFuture::new(
            ResolverConfig::from_parts(domain, search, name_servers),
            ResolverOpts {
                ip_strategy: LookupIpStrategy::Ipv4Only,
                ..ResolverOpts::default()
            },
            &io_loop.handle(),
        );

        // notice no dots, should not trigger ndots rule
        let response = io_loop.run(resolver.lookup_ip("www")).expect(
            "failed to run lookup",
        );

        assert_eq!(response.iter().count(), 1);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(*address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                assert!(false, "should only be looking up IPv4");
            }
        }
    }
}
