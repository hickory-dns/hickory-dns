extern crate rustls;
extern crate webpki_roots;

use std::net::SocketAddr;

use self::rustls::{ClientConfig, ProtocolVersion, RootCertStore};

use futures::Future;

use proto::error::ProtoError;
use proto::xfer::{BufDnsRequestStreamHandle, DnsExchange};
use trust_dns_https::{HttpsClientStream, HttpsClientStreamBuilder, HttpsSerialResponse};

#[allow(clippy::type_complexity)]
pub(crate) fn new_https_stream(
    socket_addr: SocketAddr,
    dns_name: String,
) -> (
    Box<
        Future<Item = DnsExchange<HttpsClientStream, HttpsSerialResponse>, Error = ProtoError>
            + Send,
    >,
    BufDnsRequestStreamHandle<HttpsSerialResponse>,
) {
    // using the mozilla default root store
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(&self::webpki_roots::TLS_SERVER_ROOTS);
    let versions = vec![ProtocolVersion::TLSv1_2];

    let mut client_config = ClientConfig::new();
    client_config.root_store = root_store;
    client_config.versions = versions;

    let https_builder = HttpsClientStreamBuilder::with_client_config(client_config);
    let (stream, handle) = DnsExchange::connect(https_builder.build(socket_addr, dns_name));
    let handle = BufDnsRequestStreamHandle::new(handle);

    (Box::new(stream), handle)
}

#[cfg(test)]
mod tests {
    extern crate env_logger;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use tokio::runtime::current_thread::Runtime;

    use config::{ResolverConfig, ResolverOpts};
    use AsyncResolver;

    fn https_test(config: ResolverConfig) {
        env_logger::try_init().ok();
        let mut io_loop = Runtime::new().unwrap();

        let (resolver, bg) = AsyncResolver::new(config, ResolverOpts::default());
        io_loop.spawn(bg);

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
