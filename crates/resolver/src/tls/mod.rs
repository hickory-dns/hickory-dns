// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(feature = "dns-over-tls")]

mod dns_over_native_tls;
mod dns_over_openssl;
mod dns_over_rustls;

cfg_if! {
    if #[cfg(feature = "dns-over-rustls")] {
        pub(crate) use self::dns_over_rustls::new_tls_stream;
        #[cfg(feature = "dns-over-https-rustls")]
        pub(crate) use self::dns_over_rustls::CLIENT_CONFIG;
    } else if #[cfg(feature = "dns-over-native-tls")] {
        pub(crate) use self::dns_over_native_tls::new_tls_stream;
    } else if #[cfg(feature = "dns-over-openssl")] {
        pub(crate) use self::dns_over_openssl::new_tls_stream;
    } else {
        compile_error!("One of the dns-over-rustls, dns-over-native-tls, or dns-over-openssl must be enabled for dns-over-tls features");
    }
}

#[cfg(any(feature = "dns-over-native-tls", feature = "dns-over-rustls"))]
#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use tokio::runtime::Runtime;

    use crate::config::{ResolverConfig, ResolverOpts};
    use crate::{TokioAsyncResolver, TokioHandle};

    fn tls_test(config: ResolverConfig) {
        let io_loop = Runtime::new().unwrap();

        let resolver = TokioAsyncResolver::new(
            config,
            ResolverOpts {
                try_tcp_on_error: true,
                ..ResolverOpts::default()
            },
            TokioHandle,
        )
        .expect("failed to create resolver");

        let response = io_loop
            .block_on(resolver.lookup_ip("www.example.com."))
            .expect("failed to run lookup");

        assert_eq!(response.iter().count(), 1);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                assert_eq!(
                    address,
                    IpAddr::V6(Ipv6Addr::new(
                        0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
                    ))
                );
            }
        }
    }

    #[test]
    #[cfg(not(windows))] // flakes on AppVeyor...
    fn test_cloudflare_tls() {
        tls_test(ResolverConfig::cloudflare_tls())
    }

    #[test]
    #[cfg(not(windows))] // flakes on AppVeyor...
    fn test_quad9_tls() {
        tls_test(ResolverConfig::quad9_tls())
    }
}
