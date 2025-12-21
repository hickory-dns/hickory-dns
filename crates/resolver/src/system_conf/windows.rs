// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! System configuration loading for windows

use std::net::{IpAddr, Ipv6Addr};
use std::os::raw::c_ulong;
use std::ptr;
use std::str::FromStr;

use windows_registry::LOCAL_MACHINE;
use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_INVALID_PARAMETER, ERROR_NO_DATA, ERROR_NOT_ENOUGH_MEMORY,
    ERROR_SUCCESS,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
};

use crate::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use crate::proto::ProtoError;
use crate::proto::rr::Name;

pub fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), ProtoError> {
    // Preallocate 16K per Microsoft recommendation, see Remarks section
    // https://docs.microsoft.com/en-us/windows/desktop/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
    let mut buf_len = 16 * 1024u32;

    let mut buffer = vec![0u8; buf_len as usize];
    let result = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX,
            ptr::null_mut(), // Reserved, must be null
            buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut buf_len as *mut c_ulong,
        )
    };

    let name_servers = match result {
        ERROR_SUCCESS => name_servers(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH)?,
        ERROR_NO_DATA => vec![],
        ERROR_BUFFER_OVERFLOW => return Err("GetAdaptersAddresses: buffer overflow".into()),
        ERROR_INVALID_PARAMETER => return Err("GetAdaptersAddresses: invalid parameter".into()),
        ERROR_NOT_ENOUGH_MEMORY => return Err("GetAdaptersAddresses: not enough memory".into()),
        _ => return Err(format!("GetAdaptersAddresses: error {result}").into()),
    };

    let search_list = match LOCAL_MACHINE.get_string(SEARCH_LIST_PATH) {
        Ok(list) => list
            .split(',')
            .map(|x| Name::from_str(x.trim()))
            .collect::<Result<Vec<_>, _>>()?,
        Err(err) => return Err(format!("failed to read search list from registry: {err}").into()),
    };

    let domain = match LOCAL_MACHINE.get_string(DOMAIN_PATH) {
        Ok(domain) if !domain.is_empty() => Name::from_str(&domain)?,
        Ok(_) => Name::root(),
        Err(err) => return Err(format!("failed to read domain from registry: {err}").into()),
    };

    Ok((
        ResolverConfig::from_parts(Some(domain), search_list, name_servers),
        ResolverOpts::default(),
    ))
}

fn name_servers(
    mut next_adapter: *mut IP_ADAPTER_ADDRESSES_LH,
) -> Result<Vec<NameServerConfig>, ProtoError> {
    let mut name_servers = Vec::new();
    while let Some(adapter) = unsafe { next_adapter.as_mut() } {
        if adapter.OperStatus != IF_OPER_STATUS_UP {
            next_adapter = adapter.Next;
            continue;
        }

        let mut next_server = adapter.FirstDnsServerAddress;
        while let Some(dns_server) = unsafe { next_server.as_mut() } {
            let ip = socket_address_to_ip_addr(&dns_server.Address)?;
            if let IpAddr::V6(ip) = ip {
                if FORBIDDEN_ADDRS.contains(&ip) {
                    continue;
                }
            }

            name_servers.push(NameServerConfig::udp_and_tcp(ip));
            next_server = dns_server.Next;
        }

        next_adapter = adapter.Next;
    }

    Ok(name_servers)
}

/// Convert a Windows SOCKET_ADDRESS to an IpAddr
fn socket_address_to_ip_addr(socket_addr: &SOCKET_ADDRESS) -> Result<IpAddr, ProtoError> {
    let sock_addr = socket_addr.lpSockaddr as *const SOCKADDR;
    let family = unsafe { *sock_addr }.sa_family;

    match family {
        AF_INET => {
            let sock_addr_in = sock_addr as *const SOCKADDR_IN;
            let bytes = unsafe { (*sock_addr_in).sin_addr.S_un.S_addr }.to_ne_bytes();
            Ok(IpAddr::from(bytes))
        }
        AF_INET6 => {
            let sock_addr_in6 = sock_addr as *const SOCKADDR_IN6;
            let bytes = unsafe { (*sock_addr_in6).sin6_addr.u.Byte };
            Ok(IpAddr::from(bytes))
        }
        _ => Err(format!("unsupported address family: {family}").into()),
    }
}

// https://datatracker.ietf.org/doc/html/draft-ietf-ipv6-dns-discovery-07
// [RFC 3879](https://datatracker.ietf.org/doc/html/rfc3879)
const FORBIDDEN_ADDRS: [Ipv6Addr; 3] = [
    Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 1), // fec0:0:0:ffff::1
    Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 2), // fec0:0:0:ffff::2
    Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 3), // fec0:0:0:ffff::3
];

const SEARCH_LIST_PATH: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\SearchList";
const DOMAIN_PATH: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Domain";
const IF_OPER_STATUS_UP: i32 = 1;
