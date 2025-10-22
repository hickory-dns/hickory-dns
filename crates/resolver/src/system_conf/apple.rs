use std::{borrow::Cow, net::IpAddr, str::FromStr};

use hickory_proto::{ProtoError, rr::Name};
use system_configuration::{
    core_foundation::{
        array::CFArray,
        base::{FromVoid, ItemRef, TCFType},
        dictionary::CFDictionary,
        string::CFString,
    },
    dynamic_store::SCDynamicStoreBuilder,
};

use crate::config::{NameServerConfig, ResolverConfig, ResolverOpts};

pub fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), ProtoError> {
    let sc = SCDynamicStoreBuilder::new("hickory-resolver").build();

    let dns_cfg = sc
        .get("State:/Network/Global/DNS")
        .ok_or("no DNS information in System Configuration")?
        .downcast_into::<CFDictionary>()
        .ok_or("DNS object in System Configuration is not a CFDictionary")?;

    let nameservers_cf = dns_cfg
        .find(CFString::from_static_string("ServerAddresses").as_CFTypeRef())
        .ok_or("no ServerAddresses key in DNS info")?;
    // CFArray, containing elements of type CFString.
    // https://developer.apple.com/documentation/systemconfiguration/kscpropnetdnsserveraddresses-swift.var
    let nameservers_cf: ItemRef<'_, CFArray<CFString>> =
        unsafe { CFArray::from_void(*nameservers_cf) };

    let mut nameservers = Vec::with_capacity(nameservers_cf.len() as usize);
    for n in &*nameservers_cf {
        let addr = IpAddr::from_str(&Cow::from(&*n))
            .map_err(|e| format!("failed to parse nameserver address: {e}"))?;

        nameservers.push(NameServerConfig::udp_and_tcp(addr));
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
            search_domains.push(Name::from_str(&Cow::from(&*s))?);
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
