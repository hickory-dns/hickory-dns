// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

mod dns_over_native_tls;
mod dns_over_openssl;
mod dns_over_rustls;

cfg_if! {
    if #[cfg(feature = "dns-over-rustls")] {
        pub(crate) use self::dns_over_rustls::new_tls_stream_with_future;
        #[cfg(any(feature = "dns-over-https-rustls", feature = "dns-over-quic", feature = "dns-over-h3"))]
        pub(crate) use self::dns_over_rustls::CLIENT_CONFIG;
    } else if #[cfg(feature = "dns-over-native-tls")] {
        pub(crate) use self::dns_over_native_tls::new_tls_stream_with_future;
    } else if #[cfg(feature = "dns-over-openssl")] {
        pub(crate) use self::dns_over_openssl::new_tls_stream_with_future;
    } else {
        compile_error!("One of the dns-over-rustls, dns-over-native-tls, or dns-over-openssl must be enabled for dns-over-tls features");
    }
}

#[cfg(any(feature = "dns-over-native-tls", feature = "dns-over-rustls"))]
#[cfg(any(feature = "webpki-roots", feature = "native-certs"))]
#[cfg(test)]
mod tests {
    use tokio::runtime::Runtime;

    use crate::config::{ResolverConfig, ResolverOpts};
    use crate::name_server::TokioConnectionProvider;
    use crate::TokioAsyncResolver;

    fn tls_test(config: ResolverConfig) {
        let io_loop = Runtime::new().unwrap();

        let resolver = TokioAsyncResolver::new(
            config,
            ResolverOpts {
                try_tcp_on_error: true,
                ..ResolverOpts::default()
            },
            TokioConnectionProvider::default(),
        );

        let response = io_loop
            .block_on(resolver.lookup_ip("www.example.com."))
            .expect("failed to run lookup");

        assert_ne!(response.iter().count(), 0);
    }

    #[test]
    #[cfg(not(windows))] // flakes on AppVeyor...
    fn test_google_tls() {
        tls_test(ResolverConfig::google_tls())
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
