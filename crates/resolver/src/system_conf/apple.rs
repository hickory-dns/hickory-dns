use std::{borrow::Cow, net::IpAddr, str::FromStr};

use hickory_proto::ProtoError;
use system_configuration::{
    core_foundation::{
        array::CFArray,
        base::{CFType, FromVoid, ItemRef, TCFType},
        dictionary::CFDictionary,
        number::CFNumber,
        string::CFString,
    },
    dynamic_store::SCDynamicStoreBuilder,
};
use tracing::warn;

use super::sanitize::parse_search_domains;
use crate::{
    config::{DomainRoute, NameServerConfig, ResolverConfig, ResolverOpts},
    proto::rr::Name,
};

#[cfg(target_os = "macos")]
#[path = "resolver_files.rs"]
mod resolver_files;

pub fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), ProtoError> {
    let sc = SCDynamicStoreBuilder::new("hickory-resolver")
        .build()
        .ok_or("failed to access System Configuration dynamic store")?;

    let dns_cfg = sc
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

    let mut config = ResolverConfig::from_parts(None, search_domains, nameservers);
    let mut keys = sc
        .get_keys("^State:/Network/Service/[^/]+/DNS$")
        .ok_or("failed to enumerate DNS service configurations")?
        .iter()
        .map(|key| key.to_string())
        .collect::<Vec<_>>();
    keys.sort();
    for key in keys {
        let dictionary = sc
            .get(key.as_str())
            .and_then(|value| value.downcast_into::<CFDictionary>())
            .ok_or("DNS service configuration is not a dictionary")?;
        config
            .domain_routes
            .extend(supplemental_routes(&dictionary)?);
    }
    #[cfg(target_os = "macos")]
    config
        .domain_routes
        .extend(resolver_files::read_routes(std::path::Path::new(
            "/etc/resolver",
        ))?);

    Ok((config, ResolverOpts::default()))
}

fn value(dictionary: &CFDictionary, key: &'static str) -> Option<CFType> {
    dictionary
        .find(CFString::from_static_string(key).as_CFTypeRef())
        .map(|value| {
            // Values in an SCDynamicStore property-list dictionary are Core Foundation objects.
            // Retain the value before the dictionary or borrowed reference can be dropped.
            unsafe { CFType::wrap_under_get_rule(*value) }
        })
}

fn strings(
    dictionary: &CFDictionary,
    key: &'static str,
) -> Result<Option<Vec<String>>, ProtoError> {
    let Some(value) = value(dictionary, key) else {
        return Ok(None);
    };
    let array = value
        .downcast_into::<CFArray>()
        .ok_or("DNS value is not an array")?;
    let mut strings = Vec::with_capacity(array.len() as usize);
    for element in &array {
        // CFArray's elements are property-list objects. Check the element's type before use.
        let element = unsafe { CFType::wrap_under_get_rule(*element) };
        let string = element
            .downcast_into::<CFString>()
            .ok_or("DNS array value is not a string")?;
        strings.push(string.to_string());
    }
    Ok(Some(strings))
}

fn supplemental_routes(dictionary: &CFDictionary) -> Result<Vec<DomainRoute>, ProtoError> {
    let Some(domains) = strings(dictionary, "SupplementalMatchDomains")? else {
        return Ok(Vec::new());
    };
    let addresses = strings(dictionary, "ServerAddresses")?.unwrap_or_default();
    let port = match value(dictionary, "ServerPort") {
        Some(value) => value
            .downcast_into::<CFNumber>()
            .and_then(|number| number.to_i64())
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
            .ok_or("invalid supplemental DNS server port")?,
        None => 53,
    };
    let orders = match value(dictionary, "SupplementalMatchOrders") {
        Some(value) => {
            let array = value
                .downcast_into::<CFArray>()
                .ok_or("DNS match orders is not an array")?;
            let mut orders = Vec::new();
            for element in &array {
                let element = unsafe { CFType::wrap_under_get_rule(*element) };
                orders.push(
                    element
                        .downcast_into::<CFNumber>()
                        .and_then(|number| number.to_i64())
                        .and_then(|order| u32::try_from(order).ok())
                        .ok_or("invalid DNS match order")?,
                );
            }
            if orders.len() != domains.len() {
                return Err("DNS match domains and orders differ in length".into());
            }
            orders
        }
        None => vec![0; domains.len()],
    };
    let servers = addresses
        .into_iter()
        .map(|address| {
            let mut server =
                NameServerConfig::udp_and_tcp(address.parse::<IpAddr>().map_err(|error| {
                    ProtoError::from(format!("invalid supplemental DNS address: {error}"))
                })?);
            for connection in &mut server.connections {
                connection.port = port;
            }
            Ok(server)
        })
        .collect::<Result<Vec<_>, ProtoError>>()?;
    domains
        .into_iter()
        .zip(orders)
        .map(|(domain, search_order)| {
            let mut name = if domain.is_empty() {
                Name::root()
            } else {
                Name::from_ascii(&domain)?
            };
            name.set_fqdn(true);
            let mut route = DomainRoute::new(name, servers.clone());
            route.search_order = search_order;
            Ok(route)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dictionary(entries: Vec<(&str, CFType)>) -> CFDictionary {
        CFDictionary::from_CFType_pairs(
            &entries
                .into_iter()
                .map(|(key, value)| (CFString::new(key).as_CFType(), value))
                .collect::<Vec<_>>(),
        )
        .to_untyped()
    }

    fn array(values: &[&str]) -> CFType {
        CFArray::from_CFTypes(
            &values
                .iter()
                .map(|value| CFString::new(value))
                .collect::<Vec<_>>(),
        )
        .as_CFType()
    }

    #[test]
    fn supplemental_domains_include_root_with_ports_and_orders() {
        let orders = CFArray::from_CFTypes(&[CFNumber::from(200i64), CFNumber::from(100i64)]);
        let dictionary = dictionary(vec![
            ("SupplementalMatchDomains", array(&["corp.example", ""])),
            ("ServerAddresses", array(&["192.0.2.53", "2001:db8::53"])),
            ("ServerPort", CFNumber::from(5353i64).as_CFType()),
            ("SupplementalMatchOrders", orders.as_CFType()),
        ]);
        let routes = supplemental_routes(&dictionary).unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].domain, Name::from_ascii("corp.example.").unwrap());
        assert_eq!(routes[0].search_order, 200);
        assert_eq!(routes[1].domain, Name::root());
        assert_eq!(routes[1].search_order, 100);
        assert!(
            routes
                .iter()
                .flat_map(|route| &route.name_servers)
                .flat_map(|server| &server.connections)
                .all(|connection| connection.port == 5353)
        );
    }

    #[test]
    fn ordinary_service_dns_does_not_create_domain_routes() {
        let dictionary = dictionary(vec![
            ("DomainName", CFString::new("corp.example").as_CFType()),
            ("ServerAddresses", array(&["192.0.2.53"])),
        ]);
        assert!(supplemental_routes(&dictionary).unwrap().is_empty());
    }

    #[test]
    fn malformed_supplemental_properties_return_errors() {
        for invalid in [
            CFNumber::from(1i64).as_CFType(),
            CFArray::from_CFTypes(&[CFNumber::from(1i64)]).as_CFType(),
        ] {
            assert!(
                supplemental_routes(&dictionary(vec![("SupplementalMatchDomains", invalid)]))
                    .is_err()
            );
        }
        for (key, invalid) in [
            ("ServerAddresses", array(&["invalid"])),
            ("ServerPort", CFString::new("53").as_CFType()),
            ("ServerPort", CFNumber::from(0i64).as_CFType()),
            (
                "SupplementalMatchOrders",
                CFArray::from_CFTypes(&[CFNumber::from(1i64), CFNumber::from(2i64)]).as_CFType(),
            ),
        ] {
            assert!(
                supplemental_routes(&dictionary(vec![
                    ("SupplementalMatchDomains", array(&["corp.example"])),
                    (key, invalid)
                ]))
                .is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn missing_supplemental_servers_leave_an_empty_route() {
        let routes = supplemental_routes(&dictionary(vec![(
            "SupplementalMatchDomains",
            array(&["corp.example"]),
        )]))
        .unwrap();
        assert_eq!(routes.len(), 1);
        assert!(routes[0].name_servers.is_empty());
    }
}
