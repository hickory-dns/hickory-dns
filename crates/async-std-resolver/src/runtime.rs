// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use trust_dns_resolver::config::{NameServerConfig, ResolverOpts};

use trust_dns_resolver::proto::error::ProtoError;
use trust_dns_resolver::proto::Executor;

use trust_dns_resolver::name_server::{
    ConnectionProvider, GenericConnector, RuntimeProvider, Spawn,
};

use crate::net::{AsyncStdTcpStream, AsyncStdUdpSocket};
use crate::proto::tcp::Connect;
use crate::proto::udp::UdpSocket;
use crate::time::AsyncStdTime;

/// The async_std runtime.
///
/// The runtime provides an I/O [driver], task scheduler, [timer], and blocking
/// pool, necessary for running asynchronous tasks.
///
/// Instances of `AsyncStdRuntime` can be created using [`new`]. However, most
/// users will use the `#[async_std::main]` annotation on their entry point instead.
///
/// See [module level][mod] documentation for more details.
///
/// # Shutdown
///
/// Shutting down the runtime is done by dropping the value. The current thread
/// will block until the shut down operation has completed.
///
/// * Drain any scheduled work queues.
/// * Drop any futures that have not yet completed.
/// * Drop the reactor.
///
/// Once the reactor has dropped, any outstanding I/O resources bound to
/// that reactor will no longer function. Calling any method on them will
/// result in an error.
///
/// [driver]: crate::io::driver
/// [timer]: crate::time
/// [mod]: index.html
/// [`new`]: #method.new
#[derive(Clone, Copy, Default)]
pub struct AsyncStdRuntimeProvider;

impl Executor for AsyncStdRuntimeProvider {
    fn new() -> Self {
        Self {}
    }

    fn block_on<F: Future>(&mut self, future: F) -> F::Output {
        async_std::task::block_on(future)
    }
}

#[derive(Clone, Copy)]
pub struct AsyncStdRuntimeHandle;
impl Spawn for AsyncStdRuntimeHandle {
    fn spawn_bg<F>(&mut self, future: F)
    where
        F: Future<Output = Result<(), ProtoError>> + Send + 'static,
    {
        let _join = async_std::task::spawn(future);
    }
}

impl RuntimeProvider for AsyncStdRuntimeProvider {
    type Handle = AsyncStdRuntimeHandle;
    type Timer = AsyncStdTime;
    type Udp = AsyncStdUdpSocket;
    type Tcp = AsyncStdTcpStream;

    fn create_handle(&self) -> Self::Handle {
        AsyncStdRuntimeHandle {}
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>> {
        Box::pin(AsyncStdTcpStream::connect(server_addr))
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
        Box::pin(AsyncStdUdpSocket::bind(local_addr))
    }
}

#[derive(Clone, Default)]
pub struct AsyncStdConnectionProvider {
    runtime_provider: AsyncStdRuntimeProvider,
    connection_provider: GenericConnector<AsyncStdRuntimeProvider>,
}

impl Executor for AsyncStdConnectionProvider {
    fn new() -> Self {
        let p = AsyncStdRuntimeProvider::new();
        Self {
            runtime_provider: p,
            connection_provider: GenericConnector::new(p),
        }
    }

    fn block_on<F: Future>(&mut self, future: F) -> F::Output {
        self.runtime_provider.block_on(future)
    }
}

impl ConnectionProvider for AsyncStdConnectionProvider {
    type Conn = <GenericConnector<AsyncStdRuntimeProvider> as ConnectionProvider>::Conn;
    type FutureConn = <GenericConnector<AsyncStdRuntimeProvider> as ConnectionProvider>::FutureConn;
    type RuntimeProvider = AsyncStdRuntimeProvider;

    fn new_connection(
        &self,
        config: &NameServerConfig,
        options: &ResolverOpts,
    ) -> Self::FutureConn {
        self.connection_provider.new_connection(config, options)
    }
}
