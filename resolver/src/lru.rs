use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lookup_ip::LookupIp;
use lru_cache::LruCache;

use trust_dns::rr::Name;

/// Maximum TTL as defined in https://tools.ietf.org/html/rfc2181
const MAX_TTL: u32 = 2147483647_u32;

#[derive(Debug)]
struct LruValue {
    ips: LookupIp,
    ttl_until: Instant,
}

impl LruValue {
    /// Returns true if this set of ips is still valid
    fn is_current(&self, now: Instant) -> bool {
        now <= self.ttl_until
    }
}

#[derive(Debug)]
pub(crate) struct DnsLru(LruCache<Name, LruValue>);

impl DnsLru {
    pub(crate) fn new(max_size: usize) -> Self {
        DnsLru(LruCache::new(max_size))
    }

    pub(crate) fn insert(
        &mut self,
        name: Name,
        ips_and_ttl: Vec<(IpAddr, u32)>,
        now: Instant,
    ) -> LookupIp {
        let len = ips_and_ttl.len();
        // collapse the values, we're going to take the Minimum TTL as the correct one
        let (ips, ttl): (Vec<IpAddr>, u32) =
            ips_and_ttl.into_iter().fold(
                (Vec::with_capacity(len), MAX_TTL),
                |(mut ips, mut min_ttl),
                 (ip, ttl)| {
                    ips.push(ip);
                    min_ttl = if ttl < min_ttl { ttl } else { min_ttl };
                    (ips, min_ttl)
                },
            );

        let ttl = Duration::from_secs(ttl as u64);
        let ttl_until = now + ttl;

        // insert into the LRU
        let ips = LookupIp::new(Arc::new(ips));
        self.0.insert(name, LruValue { ips: ips.clone(), ttl_until });

        ips
    }

    /// This needs to be mut b/c it's an LRU, meaning the ordering of elements will potentially change on retrieval...
    pub(crate) fn get_mut(&mut self, name: &Name, now: Instant) -> Option<LookupIp> {
        let ips = self.0.get_mut(name).and_then(
            |value| if value.is_current(now) {
                Some(value.ips.clone())
            } else {
                None
            },
        );

        // in this case, we can preemtively remove out of data elements
        if ips.is_none() {
            self.0.remove(name);
        }

        ips
    }
}

#[test]
fn test_is_current() {
    let now = Instant::now();
    let not_the_future = now + Duration::from_secs(4);
    let future = now + Duration::from_secs(5);
    let past_the_future = now + Duration::from_secs(6);

    let value = LruValue {
        ips: LookupIp::new(Arc::new(vec![])),
        ttl_until: future,
    };

    assert!(value.is_current(now));
    assert!(value.is_current(not_the_future));
    assert!(value.is_current(future));
    assert!(!value.is_current(past_the_future));
}
