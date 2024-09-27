use std::fmt;
use std::iter::{IntoIterator, Iterator};
use std::slice::Iter;
use {grammar, Network, ParseError, ScopedIp};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const NAMESERVER_LIMIT:usize = 3;
const SEARCH_LIMIT:usize = 6;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum LastSearch {
    None,
    Domain,
    Search,
}


/// Represent a resolver configuration, as described in `man 5 resolv.conf`.
/// The options and defaults match those in the linux `man` page.
///
/// Note: while most fields in the structure are public the `search` and
/// `domain` fields must be accessed via methods. This is because there are
/// few different ways to treat `domain` field. In GNU libc `search` and
/// `domain` replace each other ([`get_last_search_or_domain`]).
/// In MacOS `/etc/resolve/*` files `domain` is treated in entirely different
/// way.
///
/// Also consider using [`glibc_normalize`] and [`get_system_domain`] to match
/// behavior of GNU libc. (latter requires ``system`` feature enabled)
///
/// ```rust
/// extern crate resolv_conf;
///
/// use std::net::Ipv4Addr;
/// use resolv_conf::{Config, ScopedIp};
///
/// fn main() {
///     // Create a new config
///     let mut config = Config::new();
///     config.nameservers.push(ScopedIp::V4(Ipv4Addr::new(8, 8, 8, 8)));
///     config.set_search(vec!["example.com".into()]);
///
///     // Parse a config
///     let parsed = Config::parse("nameserver 8.8.8.8\nsearch example.com").unwrap();
///     assert_eq!(parsed, config);
/// }
/// ```
///
/// [`glibc_normalize`]: #method.glibc_normalize
/// [`get_last_search_or_domain`]: #method.get_last_search_or_domain
/// [`get_system_domain`]: #method.get_system_domain
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// List of nameservers
    pub nameservers: Vec<ScopedIp>,
    /// Indicated whether the last line that has been parsed is a "domain" directive or a "search"
    /// directive. This is important for compatibility with glibc, since in glibc's implementation,
    /// "search" and "domain" are mutually exclusive, and only the last directive is taken into
    /// consideration.
    last_search: LastSearch,
    /// Domain to append to name when it doesn't contain ndots
    domain: Option<String>,
    /// List of suffixes to append to name when it doesn't contain ndots
    search: Option<Vec<String>>,
    /// List of preferred addresses
    pub sortlist: Vec<Network>,
    /// Enable DNS resolve debugging
    pub debug: bool,
    /// Number of dots in name to try absolute resolving first (default 1)
    pub ndots: u32,
    /// Dns query timeout (default 5 [sec])
    pub timeout: u32,
    /// Number of attempts to resolve name if server is inaccesible (default 2)
    pub attempts: u32,
    /// Round-robin selection of servers (default false)
    pub rotate: bool,
    /// Don't check names for validity (default false)
    pub no_check_names: bool,
    /// Try AAAA query before A
    pub inet6: bool,
    /// Use reverse lookup of ipv6 using bit-label format described instead
    /// of nibble format
    pub ip6_bytestring: bool,
    /// Do ipv6 reverse lookups in ip6.int zone instead of ip6.arpa
    /// (default false)
    pub ip6_dotint: bool,
    /// Enable dns extensions described in RFC 2671
    pub edns0: bool,
    /// Don't make ipv4 and ipv6 requests simultaneously
    pub single_request: bool,
    /// Use same socket for the A and AAAA requests
    pub single_request_reopen: bool,
    /// Don't resolve unqualified name as top level domain
    pub no_tld_query: bool,
    /// Force using TCP for DNS resolution
    pub use_vc: bool,
    /// Disable the automatic reloading of a changed configuration file
    pub no_reload: bool,
    /// Optionally send the AD (authenticated data) bit in queries
    pub trust_ad: bool,
    /// The order in which databases should be searched during a lookup
    /// **(openbsd-only)**
    pub lookup: Vec<Lookup>,
    /// The order in which internet protocol families should be prefered
    /// **(openbsd-only)**
    pub family: Vec<Family>,
}

impl Config {
    /// Create a new `Config` object with default values.
    ///
    /// ```rust
    /// # extern crate resolv_conf;
    /// use resolv_conf::Config;
    /// # fn main() {
    /// let config = Config::new();
    /// assert_eq!(config.nameservers, vec![]);
    /// assert!(config.get_domain().is_none());
    /// assert!(config.get_search().is_none());
    /// assert_eq!(config.sortlist, vec![]);
    /// assert_eq!(config.debug, false);
    /// assert_eq!(config.ndots, 1);
    /// assert_eq!(config.timeout, 5);
    /// assert_eq!(config.attempts, 2);
    /// assert_eq!(config.rotate, false);
    /// assert_eq!(config.no_check_names, false);
    /// assert_eq!(config.inet6, false);
    /// assert_eq!(config.ip6_bytestring, false);
    /// assert_eq!(config.ip6_dotint, false);
    /// assert_eq!(config.edns0, false);
    /// assert_eq!(config.single_request, false);
    /// assert_eq!(config.single_request_reopen, false);
    /// assert_eq!(config.no_tld_query, false);
    /// assert_eq!(config.use_vc, false);
    /// # }
    pub fn new() -> Config {
        Config {
            nameservers: Vec::new(),
            domain: None,
            search: None,
            last_search: LastSearch::None,
            sortlist: Vec::new(),
            debug: false,
            ndots: 1,
            timeout: 5,
            attempts: 2,
            rotate: false,
            no_check_names: false,
            inet6: false,
            ip6_bytestring: false,
            ip6_dotint: false,
            edns0: false,
            single_request: false,
            single_request_reopen: false,
            no_tld_query: false,
            use_vc: false,
            no_reload: false,
            trust_ad: false,
            lookup: Vec::new(),
            family: Vec::new(),
        }
    }

    /// Parse a buffer and return the corresponding `Config` object.
    ///
    /// ```rust
    /// # extern crate resolv_conf;
    /// use resolv_conf::{ScopedIp, Config};
    /// # fn main() {
    /// let config_str = "# /etc/resolv.conf
    /// nameserver  8.8.8.8
    /// nameserver  8.8.4.4
    /// search      example.com sub.example.com
    /// options     ndots:8 attempts:8";
    ///
    /// // Parse the config
    /// let parsed_config = Config::parse(&config_str).expect("Failed to parse config");
    ///
    /// // Print the config
    /// println!("{:?}", parsed_config);
    /// # }
    /// ```
    pub fn parse<T: AsRef<[u8]>>(buf: T) -> Result<Config, ParseError> {
        grammar::parse(buf.as_ref())
    }

    /// Return the suffixes declared in the last "domain" or "search" directive.
    ///
    /// ```rust
    /// # extern crate resolv_conf;
    /// use resolv_conf::{ScopedIp, Config};
    /// # fn main() {
    /// let config_str = "search example.com sub.example.com\ndomain localdomain";
    /// let parsed_config = Config::parse(&config_str).expect("Failed to parse config");
    /// let domains = parsed_config.get_last_search_or_domain()
    ///                            .map(|domain| domain.clone())
    ///                            .collect::<Vec<String>>();
    /// assert_eq!(domains, vec![String::from("localdomain")]);
    ///
    /// let config_str = "domain localdomain\nsearch example.com sub.example.com";
    /// let parsed_config = Config::parse(&config_str).expect("Failed to parse config");
    /// let domains = parsed_config.get_last_search_or_domain()
    ///                            .map(|domain| domain.clone())
    ///                            .collect::<Vec<String>>();
    /// assert_eq!(domains, vec![String::from("example.com"), String::from("sub.example.com")]);
    /// # }
    pub fn get_last_search_or_domain<'a>(&'a self) -> DomainIter<'a> {
        let domain_iter = match self.last_search {
            LastSearch::Search => DomainIterInternal::Search(
                self.get_search()
                    .and_then(|domains| Some(domains.into_iter())),
            ),
            LastSearch::Domain => DomainIterInternal::Domain(self.get_domain()),
            LastSearch::None => DomainIterInternal::None,
        };
        DomainIter(domain_iter)
    }

    /// Return the domain declared in the last "domain" directive.
    pub fn get_domain(&self) -> Option<&String> {
        self.domain.as_ref()
    }

    /// Return the domains declared in the last "search" directive.
    pub fn get_search(&self) -> Option<&Vec<String>> {
        self.search.as_ref()
    }

    /// Set the domain corresponding to the "domain" directive.
    pub fn set_domain(&mut self, domain: String) {
        self.domain = Some(domain);
        self.last_search = LastSearch::Domain;
    }

    /// Set the domains corresponding the "search" directive.
    pub fn set_search(&mut self, search: Vec<String>) {
        self.search = Some(search);
        self.last_search = LastSearch::Search;
    }

    /// Normalize config according to glibc rulees
    ///
    /// Currently this method does the following things:
    ///
    /// 1. Truncates list of nameservers to 3 at max
    /// 2. Truncates search list to 6 at max
    ///
    /// Other normalizations may be added in future as long as they hold true
    /// for a particular GNU libc implementation.
    ///
    /// Note: this method is not called after parsing, because we think it's
    /// not forward-compatible to rely on such small and ugly limits. Still,
    /// it's useful to keep implementation as close to glibc as possible.
    pub fn glibc_normalize(&mut self) {
        self.nameservers.truncate(NAMESERVER_LIMIT);
        self.search = self.search.take().map(|mut s| {
            s.truncate(SEARCH_LIMIT);
            s
        });
    }

    /// Get nameserver or on the local machine
    pub fn get_nameservers_or_local(&self) -> Vec<ScopedIp> {
        if self.nameservers.is_empty() {
            vec![
                ScopedIp::from(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                ScopedIp::from(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
            ]
        } else {
            self.nameservers.to_vec()
        }
    }

    /// Get domain from config or fallback to the suffix of a hostname
    ///
    /// This is how glibc finds out a hostname. This method requires
    /// ``system`` feature enabled.
    #[cfg(feature = "system")]
    pub fn get_system_domain(&self) -> Option<String> {
        if self.domain.is_some() {
            return self.domain.clone();
        }

        let hostname = match ::hostname::get().ok() {
            Some(name) => name.into_string().ok(),
            None => return None,
        };

        hostname.and_then(|s| {
            if let Some(pos) = s.find('.') {
                let hn = s[pos + 1..].to_string();
                if !hn.is_empty() {
                    return Some(hn)
                }
            };
            None
        })
    }
}

impl fmt::Display for Config {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        for nameserver in self.nameservers.iter() {
            writeln!(fmt, "nameserver {}", nameserver)?;
        }

        if self.last_search != LastSearch::Domain {
            if let Some(ref domain) = self.domain {
                writeln!(fmt, "domain {}", domain)?;
            }
        }

        if let Some(ref search) = self.search {
            if !search.is_empty() {
                write!(fmt, "search")?;
                for suffix in search.iter() {
                    write!(fmt, " {}", suffix)?;
                }
                writeln!(fmt)?;
            }
        }

        if self.last_search == LastSearch::Domain {
            if let Some(ref domain) = self.domain {
                writeln!(fmt, "domain {}", domain)?;
            }
        }

        if !self.sortlist.is_empty() {
            write!(fmt, "sortlist")?;
            for network in self.sortlist.iter() {
                write!(fmt, " {}", network)?;
            }
            writeln!(fmt)?;
        }

        if self.debug {
            writeln!(fmt, "options debug")?;
        }
        if self.ndots != 1 {
            writeln!(fmt, "options ndots:{}", self.ndots)?;
        }
        if self.timeout != 5 {
            writeln!(fmt, "options timeout:{}", self.timeout)?;
        }
        if self.attempts != 2 {
            writeln!(fmt, "options attempts:{}", self.attempts)?;
        }
        if self.rotate {
            writeln!(fmt, "options rotate")?;
        }
        if self.no_check_names {
            writeln!(fmt, "options no-check-names")?;
        }
        if self.inet6 {
            writeln!(fmt, "options inet6")?;
        }
        if self.ip6_bytestring {
            writeln!(fmt, "options ip6-bytestring")?;
        }
        if self.ip6_dotint {
            writeln!(fmt, "options ip6-dotint")?;
        }
        if self.edns0 {
            writeln!(fmt, "options edns0")?;
        }
        if self.single_request {
            writeln!(fmt, "options single-request")?;
        }
        if self.single_request_reopen {
            writeln!(fmt, "options single-request-reopen")?;
        }
        if self.no_tld_query {
            writeln!(fmt, "options no-tld-query")?;
        }
        if self.use_vc {
            writeln!(fmt, "options use-vc")?;
        }
        if self.no_reload {
            writeln!(fmt, "options no-reload")?;
        }
        if self.trust_ad {
            writeln!(fmt, "options trust-ad")?;
        }

        Ok(())
    }
}

/// An iterator returned by [`Config.get_last_search_or_domain`](struct.Config.html#method.get_last_search_or_domain)
#[derive(Debug, Clone)]
pub struct DomainIter<'a>(DomainIterInternal<'a>);

impl<'a> Iterator for DomainIter<'a> {
    type Item = &'a String;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

#[derive(Debug, Clone)]
enum DomainIterInternal<'a> {
    Search(Option<Iter<'a, String>>),
    Domain(Option<&'a String>),
    None,
}

impl<'a> Iterator for DomainIterInternal<'a> {
    type Item = &'a String;

    fn next(&mut self) -> Option<Self::Item> {
        match *self {
            DomainIterInternal::Search(Some(ref mut domains)) => domains.next(),
            DomainIterInternal::Domain(ref mut domain) => domain.take(),
            _ => None,
        }
    }
}

/// The databases that should be searched during a lookup.
/// This option is commonly found on openbsd.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// Search for entries in /etc/hosts
    File,
    /// Query a domain name server
    Bind,
    /// A database we don't know yet
    Extra(String),
}

/// The internet protocol family that is prefered.
/// This option is commonly found on openbsd.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Family {
    /// A A lookup for an ipv4 address
    Inet4,
    /// A AAAA lookup for an ipv6 address
    Inet6,
}
