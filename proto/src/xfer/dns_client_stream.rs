use std::io;
use std::net::SocketAddr;

use futures::Stream;

use xfer::SerialMessage;

/// A non-multiplexed stream of Serialized DNS messages
pub trait DnsClientStream: Stream<Item = SerialMessage, Error = io::Error> + Send {
    /// The remote name server address
    fn name_server_addr(&self) -> SocketAddr;
}
