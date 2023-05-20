#![recursion_limit = "128"]

#[cfg(feature = "tokio-runtime")]
use {
    std::future::Future,
    std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    std::pin::Pin,
    tokio::net::{TcpStream, UdpSocket},
    trust_dns_resolver::config::{ResolverConfig, ResolverOpts},
    trust_dns_resolver::name_server::{ConnectionProvider, GenericConnector, RuntimeProvider},
    trust_dns_resolver::proto::iocompat::AsyncIoTokioAsStd,
    trust_dns_resolver::proto::TokioTime,
    trust_dns_resolver::{AsyncResolver, TokioHandle},
};

#[cfg(feature = "tokio-runtime")]
#[derive(Clone, Default)]
struct PrintProvider {
    handle: TokioHandle,
}

#[cfg(feature = "tokio-runtime")]
impl RuntimeProvider for PrintProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>> {
        println!("Create tcp server_addr: {}", server_addr);
        Box::pin(async move {
            let tcp = TcpStream::connect(server_addr).await?;
            Ok(AsyncIoTokioAsStd(tcp))
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
        // The server_addr parameter is used only when you need to establish a tunnel or something similar.
        // For example, you try to use a http proxy and encapsulate UDP packets inside a TCP stream.
        println!(
            "Create udp local_addr: {}, server_addr: {}",
            local_addr, server_addr
        );
        Box::pin(UdpSocket::bind(local_addr))
    }
}

#[cfg(feature = "tokio-runtime")]
async fn lookup_test<R: ConnectionProvider>(resolver: AsyncResolver<R>) {
    let response = resolver.lookup_ip("www.example.com.").await.unwrap();

    // There can be many addresses associated with the name,
    //  this can return IPv4 and/or IPv6 addresses
    let address = response.iter().next().expect("no addresses returned!");
    if address.is_ipv4() {
        assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
    } else {
        assert_eq!(
            address,
            IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946
            ))
        );
    }
}

#[cfg(feature = "tokio-runtime")]
#[tokio::main]
async fn main() {
    let resolver = AsyncResolver::new(
        ResolverConfig::google(),
        ResolverOpts::default(),
        GenericConnector::new(PrintProvider::default()),
    );
    lookup_test(resolver).await;

    #[cfg(feature = "dns-over-https-rustls")]
    {
        let resolver2 = AsyncResolver::new(
            ResolverConfig::cloudflare_https(),
            ResolverOpts::default(),
            GenericConnector::new(PrintProvider::default()),
        );
        lookup_test(resolver2).await;
    }

    println!("Hello, world!");
}

#[cfg(not(feature = "tokio-runtime"))]
fn main() {
    println!("tokio-runtime feature must be enabled")
}

#[test]
fn test_custom_provider() {
    main()
}
