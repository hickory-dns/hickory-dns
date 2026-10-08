// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::{IpAddr, SocketAddr};

/// Checks if the IP address is safe for returning messages
///
/// Examples of unsafe addresses are any with a port of `0`
///
/// # Returns
///
/// Error if the address should not be used for returned requests
pub fn sanitize_src_address(src_addr: SocketAddr) -> Result<(), String> {
    if src_addr.port() == 0 {
        return Err(format!("cannot respond to src on port 0: {src_addr}"));
    }

    // TODO: add check for is_reserved when that stabilizes
    match src_addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            Err(format!("cannot respond to unspecified v4 addr: {ip}"))
        }
        IpAddr::V4(ip) if ip.is_broadcast() => {
            Err(format!("cannot respond to broadcast v4 addr: {ip}"))
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            Err(format!("cannot respond to unspecified v6 addr: {ip}"))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::sanitize_src_address;

    #[test]
    fn test_sanitize_src_addr() {
        // ipv4 tests
        assert!(sanitize_src_address(SocketAddr::from(([192, 168, 1, 1], 4_096))).is_ok());
        assert!(sanitize_src_address(SocketAddr::from(([127, 0, 0, 1], 53))).is_ok());

        assert!(sanitize_src_address(SocketAddr::from(([0, 0, 0, 0], 0))).is_err());
        assert!(sanitize_src_address(SocketAddr::from(([192, 168, 1, 1], 0))).is_err());
        assert!(sanitize_src_address(SocketAddr::from(([0, 0, 0, 0], 4_096))).is_err());
        assert!(sanitize_src_address(SocketAddr::from(([255, 255, 255, 255], 4_096))).is_err());

        // ipv6 tests
        assert!(
            sanitize_src_address(SocketAddr::from(([0x20, 0, 0, 0, 0, 0, 0, 0x1], 4_096))).is_ok()
        );
        assert!(sanitize_src_address(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 4_096))).is_ok());

        assert!(sanitize_src_address(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 4_096))).is_err());
        assert!(sanitize_src_address(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))).is_err());
        assert!(
            sanitize_src_address(SocketAddr::from(([0x20, 0, 0, 0, 0, 0, 0, 0x1], 0))).is_err()
        );
    }
}
