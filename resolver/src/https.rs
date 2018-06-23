extern crate rustls;
extern crate webpki_roots;

use std::io;
use std::net::SocketAddr;

use self::rustls::{ClientConfig, ProtocolVersion, RootCertStore};

use futures::{future, Future};

use trust_dns_https::{HttpsClientStream, HttpsClientStreamBuilder};
use trust_dns_proto::xfer::{DnsStream, DnsStreamHandle};
use trust_dns_rustls::{TlsClientStream, TlsClientStreamBuilder};

use error::*;

// pub(crate) fn new_https_stream(
//     socket_addr: SocketAddr,
//     dns_name: String,
// ) -> (
//     Box<Future<Item = DnsStream<HttpsClientStream>, Error = io::Error> + Send>,
//     Box<DnsStreamHandle<Error = ResolveError> + Send>,
// ) {
//     // using the mozilla default root store
//     let mut root_store = RootCertStore::empty();
//     root_store.add_server_trust_anchors(&self::webpki_roots::TLS_SERVER_ROOTS);
//     let versions = vec![ProtocolVersion::TLSv1_2];

//     let mut client_config = ClientConfig::new();
//     client_config.root_store = root_store;
//     client_config.versions = versions;

//     let https_builder = HttpsClientStreamBuilder::with_client_config(client_config);
//     let (stream, handle) =
//         DnsStream::connect(https_builder.build(socket_addr, dns_name), socket_addr);

//     (Box::new(stream), Box::new(handle))
// }
