#![recursion_limit = "128"]

#[cfg(any(feature = "webpki-roots", feature = "native-certs"))]
use {
    hickory_resolver::{
        config::{ResolverConfig, ResolverOpts},
        name_server::{ConnectionProvider, GenericConnector},
        proto::runtime::{iocompat::AsyncIoTokioAsStd, RuntimeProvider, TokioHandle, TokioTime},
        Resolver,
    },
    std::future::Future,
    std::io,
    std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    std::pin::Pin,
    std::time::Duration,
    tokio::net::{TcpSocket, TcpStream, UdpSocket},
    tokio::time::timeout,
};

#[cfg(any(feature = "webpki-roots", feature = "native-certs"))]
#[derive(Clone, Default)]
struct PrintProvider {
    handle: TokioHandle,
}

#[cfg(any(feature = "webpki-roots", feature = "native-certs"))]
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
        bind_addr: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        Box::pin(async move {
            let socket = match server_addr {
                SocketAddr::V4(_) => TcpSocket::new_v4(),
                SocketAddr::V6(_) => TcpSocket::new_v6(),
            }?;

            if let Some(bind_addr) = bind_addr {
                socket.bind(bind_addr)?;
            }

            socket.set_nodelay(true)?;
            let future = socket.connect(server_addr);
            let wait_for = wait_for.unwrap_or_else(|| Duration::from_secs(5));
            match timeout(wait_for, future).await {
                Ok(Ok(socket)) => Ok(AsyncIoTokioAsStd(socket)),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connection to {server_addr:?} timed out after {wait_for:?}"),
                )),
            }
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

#[cfg(any(feature = "webpki-roots", feature = "native-certs"))]
async fn lookup_test<R: ConnectionProvider>(resolver: Resolver<R>) {
    let response = resolver.lookup_ip("www.example.com.").await.unwrap();

    // There can be many addresses associated with the name,
    //  this can return IPv4 and/or IPv6 addresses
    let address = response.iter().next().expect("no addresses returned!");
    if address.is_ipv4() {
        assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)));
    } else {
        assert_eq!(
            address,
            IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c
            ))
        );
    }
}

#[cfg(any(feature = "webpki-roots", feature = "native-certs"))]
#[tokio::main]
async fn main() {
    let resolver = Resolver::new(
        ResolverConfig::google(),
        ResolverOpts::default(),
        GenericConnector::new(PrintProvider::default()),
    );
    lookup_test(resolver).await;

    #[cfg(feature = "dns-over-https-rustls")]
    {
        let resolver2 = Resolver::new(
            ResolverConfig::cloudflare_https(),
            ResolverOpts::default(),
            GenericConnector::new(PrintProvider::default()),
        );
        lookup_test(resolver2).await;
    }

    println!("Hello, world!");
}

#[cfg(not(any(feature = "webpki-roots", feature = "native-certs")))]
fn main() {
    println!("either `webpki-roots` or `native-certs` feature must be enabled")
}

#[test]
fn test_custom_provider() {
    main()
}
