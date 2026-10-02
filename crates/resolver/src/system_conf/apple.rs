use std::{borrow::Cow, net::IpAddr, str::FromStr};

use hickory_proto::ProtoError;
use system_configuration::{
    core_foundation::{
        array::CFArray,
        base::{FromVoid, ItemRef, TCFType},
        dictionary::CFDictionary,
        number::CFNumber,
        string::CFString,
    },
    dynamic_store::SCDynamicStoreBuilder,
};
use tracing::warn;

use super::sanitize::parse_search_domains;
use crate::config::{NameServerConfig, ResolverConfig, ResolverOpts};

pub fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), ProtoError> {
    let sc = SCDynamicStoreBuilder::new("hickory-resolver").build();

    let dns_cfg = sc
        .ok_or("failed to access System Configuration dynamic store")?
        .get("State:/Network/Global/DNS")
        .ok_or("no DNS information in System Configuration")?
        .downcast_into::<CFDictionary>()
        .ok_or("DNS object in System Configuration is not a CFDictionary")?;

    // A local DNS proxy (as VPN clients install) may listen on a port other than 53.
    // https://developer.apple.com/documentation/systemconfiguration/kscpropnetdnsserverport
    let port = dns_cfg
        .find(CFString::from_static_string("ServerPort").as_CFTypeRef())
        .and_then(|port_cf| {
            let port_cf: ItemRef<'_, CFNumber> = unsafe { CFNumber::from_void(*port_cf) };
            match u16::try_from(port_cf.to_i64()?) {
                Ok(0) | Err(_) => None,
                Ok(port) => Some(port),
            }
        });

    let nameservers_cf = dns_cfg
        .find(CFString::from_static_string("ServerAddresses").as_CFTypeRef())
        .ok_or("no ServerAddresses key in DNS info")?;
    // CFArray, containing elements of type CFString.
    // https://developer.apple.com/documentation/systemconfiguration/kscpropnetdnsserveraddresses-swift.var
    let nameservers_cf: ItemRef<'_, CFArray<CFString>> =
        unsafe { CFArray::from_void(*nameservers_cf) };

    let mut nameservers = Vec::with_capacity(nameservers_cf.len() as usize);
    for n in &*nameservers_cf {
        let s = Cow::from(&*n);
        // macOS reports link-local nameservers with a zone id (e.g. `fe80::1%en0`),
        // which `IpAddr::from_str` cannot parse. Strip the zone and keep the base
        // address, matching the `resolv.conf` path (see `resolv_conf::ScopedIp`).
        let stripped = match s.split_once('%') {
            Some((addr, _zone)) => addr,
            None => &*s,
        };
        let addr = match IpAddr::from_str(stripped) {
            Ok(addr) => addr,
            Err(e) => {
                warn!(
                    nameserver = %s,
                    error = %e,
                    "ignoring unparseable nameserver"
                );
                continue;
            }
        };
        let mut nameserver = NameServerConfig::udp_and_tcp(addr);
        if let Some(port) = port {
            for connection in &mut nameserver.connections {
                connection.port = port;
            }
        }
        nameservers.push(nameserver);
    }

    let search_domains_cf =
        dns_cfg.find(CFString::from_static_string("SearchDomains").as_CFTypeRef());

    let search_domains = if let Some(search_domains_cf) = search_domains_cf {
        // CFArray, containing elements of type CFString.
        // https://developer.apple.com/documentation/systemconfiguration/kscpropnetdnssearchdomains-swift.var
        let search_domains_cf: ItemRef<'_, CFArray<CFString>> =
            unsafe { CFArray::from_void(*search_domains_cf) };

        let mut search_domains = Vec::with_capacity(search_domains_cf.len() as usize);
        for s in &*search_domains_cf {
            for domain in parse_search_domains(&Cow::from(&*s)) {
                search_domains.push(domain?);
            }
        }
        search_domains
    } else {
        vec![]
    };

    Ok((
        ResolverConfig::from_parts(None, search_domains, nameservers),
        ResolverOpts::default(),
    ))
}
