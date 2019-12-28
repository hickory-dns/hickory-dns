extern crate rustls;
extern crate webpki_roots;

use std::net::SocketAddr;

use crate::tls::CLIENT_CONFIG;

use proto::xfer::{DnsExchange, DnsExchangeConnect};
use proto::TokioTime;
use trust_dns_https::{
    HttpsClientConnect, HttpsClientResponse, HttpsClientStream, HttpsClientStreamBuilder,
};

use crate::config::TlsClientConfig;

#[allow(clippy::type_complexity)]
pub(crate) fn new_https_stream(
    socket_addr: SocketAddr,
    dns_name: String,
    client_config: Option<TlsClientConfig>,
) -> DnsExchangeConnect<HttpsClientConnect, HttpsClientStream, HttpsClientResponse, TokioTime> {
    let client_config = client_config.map_or_else(
        || CLIENT_CONFIG.clone(),
        |TlsClientConfig(client_config)| client_config,
    );

    let https_builder = HttpsClientStreamBuilder::with_client_config(client_config);
    DnsExchange::connect(https_builder.build(socket_addr, dns_name))
}

#[cfg(test)]
mod tests {
    extern crate env_logger;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use tokio::runtime::Runtime;

    use crate::config::{ResolverConfig, ResolverOpts};
    use crate::TokioAsyncResolver;

    fn https_test(config: ResolverConfig) {
        //env_logger::try_init().ok();
        let mut io_loop = Runtime::new().unwrap();

        let resolver =
            TokioAsyncResolver::new(config, ResolverOpts::default(), io_loop.handle().clone());
        let resolver = io_loop
            .block_on(resolver)
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
    fn test_cloudflare_https() {
        https_test(ResolverConfig::cloudflare_https())
    }
}
