use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

use crate::proto::error::ProtoError;
use crate::proto::tcp::{Connect, DnsTcpStream, TcpClientStream, TcpStream};
use crate::proto::xfer::StreamReceiver;
use crate::proto::BufDnsStreamHandle;

use futures_util::future::TryFutureExt;

pub mod connect;

use connect::TlsConnect;

pub fn connect_with_bind_addr<S: Connect, TC: TlsConnect<S> + Send + 'static>(
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    tls_connector: TC,
) -> (
    Pin<
        Box<dyn Future<Output = Result<TcpClientStream<TC::TlsStream>, ProtoError>> + Send + Unpin>,
    >,
    BufDnsStreamHandle,
)
where
    TC::TlsStream: DnsTcpStream,
{
    let (stream_future, sender) = tls_connect_with_bind_addr(name_server, bind_addr, tls_connector);

    let new_future = Box::pin(
        stream_future
            .map_ok(TcpClientStream::from_stream)
            .map_err(ProtoError::from),
    );

    (new_future, sender)
}

pub fn tls_connect_with_bind_addr<S: Connect, TC: TlsConnect<S> + Send + 'static>(
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    tls_connector: TC,
) -> (
    Pin<Box<dyn Future<Output = Result<TcpStream<TC::TlsStream>, io::Error>> + Send>>,
    BufDnsStreamHandle,
)
where
    TC::TlsStream: DnsTcpStream,
{
    let (message_sender, outbound_messages) = BufDnsStreamHandle::new(name_server);

    // This set of futures collapses the next tcp socket into a stream which can be used for
    //  sending and receiving tcp packets.
    let stream = Box::pin(connect_tls(
        name_server,
        bind_addr,
        tls_connector,
        outbound_messages,
    ));

    (stream, message_sender)
}

async fn connect_tls<S: Connect, TC: TlsConnect<S> + Send + 'static>(
    name_server: SocketAddr,
    bind_addr: Option<SocketAddr>,
    tls_connector: TC,
    outbound_messages: StreamReceiver,
) -> io::Result<TcpStream<TC::TlsStream>>
where
    TC::TlsStream: DnsTcpStream,
{
    let stream = S::connect_with_bind(name_server, bind_addr).await?;
    let tls_stream = tls_connector.tls_connect(stream).await?;

    Ok(TcpStream::from_stream_with_receiver(
        tls_stream,
        name_server,
        outbound_messages,
    ))
}
