// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(feature = "dns-over-rustls")]
#![allow(dead_code)]

use std::future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use futures_util::future::Future;
use once_cell::sync::Lazy;
use rustls::{ClientConfig, RootCertStore};

use proto::error::ProtoError;
use proto::rustls::tls_client_stream::tls_client_connect_with_future;
use proto::rustls::TlsClientStream;
use proto::tcp::DnsTcpStream;
use proto::BufDnsStreamHandle;

use crate::config::TlsClientConfig;

pub(crate) static CLIENT_CONFIG: Lazy<Result<Arc<ClientConfig>, ProtoError>> = Lazy::new(|| {
    #[cfg_attr(
        not(any(feature = "native-certs", feature = "webpki-roots")),
        allow(unused_mut)
    )]
    let mut root_store = RootCertStore::empty();
    #[cfg(all(feature = "native-certs", not(feature = "webpki-roots")))]
    {
        use proto::error::ProtoErrorKind;

        let (added, ignored) =
            root_store.add_parsable_certificates(&rustls_native_certs::load_native_certs()?);

        if ignored > 0 {
            tracing::warn!(
                "failed to parse {} certificate(s) from the native root store",
                ignored,
            );
        }

        if added == 0 {
            return Err(ProtoErrorKind::NativeCerts.into());
        }
    }
    #[cfg(feature = "webpki-roots")]
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    // If by the time we reach this point the root store remains empty then
    // our feature config hasn't resulted in a populated root store. Return an
    // early error rather than trying to validate a peer certificate without any
    // trust anchors.
    if root_store.is_empty() {
        return Err(ProtoError::from(
         "no root certificates configured: you must enable the webpki-roots or native-certs feature".to_owned(),
        ));
    }

    let mut client_config = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // The port (853) of DOT is for dns dedicated, SNI is unnecessary. (ISP block by the SNI name)
    client_config.enable_sni = false;

    Ok(Arc::new(client_config))
});

#[allow(clippy::type_complexity)]
pub(crate) fn new_tls_stream_with_future<S, F>(
    future: F,
    socket_addr: SocketAddr,
    dns_name: String,
    client_config: Option<TlsClientConfig>,
) -> (
    Pin<Box<dyn Future<Output = Result<TlsClientStream<S>, ProtoError>> + Send>>,
    BufDnsStreamHandle,
)
where
    S: DnsTcpStream,
    F: Future<Output = io::Result<S>> + Send + Unpin + 'static,
{
    let client_config = if let Some(TlsClientConfig(client_config)) = client_config {
        client_config
    } else {
        match CLIENT_CONFIG.clone() {
            Ok(client_config) => client_config,
            Err(err) => {
                return (
                    Box::pin(future::ready(Err(err))),
                    BufDnsStreamHandle::new(socket_addr).0,
                )
            }
        }
    };
    let (stream, handle) =
        tls_client_connect_with_future(future, socket_addr, dns_name, client_config);
    (Box::pin(stream), handle)
}
