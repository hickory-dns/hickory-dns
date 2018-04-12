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
    } else if #[cfg(feature = "dns-over-native-tls")] {
        pub(crate) use self::dns_over_native_tls::new_tls_stream;
    } else if #[cfg(feature = "dns-over-openssl")] {
        pub(crate) use self::dns_over_openssl::new_tls_stream;
    } else {
        compile_error!("One of the dns-over-rustls, dns-over-native-tls, or dns-over-openssl must be enabled for dns-over-tls features");
    }
}
