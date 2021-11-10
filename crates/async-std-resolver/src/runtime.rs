// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::future::Future;
use std::io;
use std::pin::Pin;

use trust_dns_resolver::proto::error::ProtoError;
use trust_dns_resolver::proto::Executor;

use trust_dns_resolver::name_server::{
    GenericConnection, GenericConnectionProvider, RuntimeProvider,
};

use crate::net::{AsyncStdTcpStream, AsyncStdUdpSocket};
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
#[derive(Clone, Copy)]
pub struct AsyncStdRuntime;

impl Executor for AsyncStdRuntime {
    fn new() -> Self {
        AsyncStdRuntime {}
    }

    fn block_on<F: Future>(&mut self, future: F) -> F::Output {
        async_std::task::block_on(future)
    }
}

impl RuntimeProvider for AsyncStdRuntime {
    type UdpSocket = AsyncStdUdpSocket;
    type Time = AsyncStdTime;
    type TcpConnection = AsyncStdTcpStream;

    fn bind_udp(
        &self,
        addr: std::net::SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::UdpSocket>> + Send>> {
        Box::pin(async move {
            async_std::net::UdpSocket::bind(addr)
                .await
                .map(AsyncStdUdpSocket)
        })
    }

    fn connect_tcp(
        &self,
        addr: std::net::SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::TcpConnection>> + Send>> {
        Box::pin(async move {
            let stream = async_std::net::TcpStream::connect(addr).await?;
            stream.set_nodelay(true)?;
            Ok(AsyncStdTcpStream(stream))
        })
    }

    fn spawn_bg<F>(&self, future: F)
    where
        F: Future<Output = Result<(), ProtoError>> + Send + 'static,
    {
        let _join = async_std::task::spawn(future);
    }
}

/// AsyncStd default connection
pub type AsyncStdConnection = GenericConnection;

/// AsyncStd default connection provider
pub type AsyncStdConnectionProvider = GenericConnectionProvider<AsyncStdRuntime>;
