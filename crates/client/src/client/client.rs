// Copyright (C) 2015 - 2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::sync::Arc;

use futures::Future;
use tokio::runtime::current_thread::Runtime;

use proto::error::ProtoError;
use proto::xfer::{DnsRequestSender, DnsResponse};

#[cfg(feature = "dnssec")]
use crate::client::SecureClientHandle;
use crate::client::{BasicClientHandle, ClientConnection, ClientFuture, ClientHandle};
use crate::error::*;
use crate::rr::dnssec::Signer;
#[cfg(feature = "dnssec")]
use crate::rr::dnssec::TrustAnchor;
use crate::rr::{DNSClass, Name, Record, RecordSet, RecordType};

/// Client trait which implements basic DNS Client operations.
///
/// As of 0.10.0, the Client is now a wrapper around the `ClientFuture`, which is a futures-rs
/// and tokio-rs based implementation. This trait implements synchronous functions for ease of use.
///
/// There was a strong attempt to make it backwards compatible, but making it a drop in replacement
/// for the old Client was not possible. This trait has two implementations, the `SyncClient` which
/// is a standard DNS Client, and the `SecureSyncClient` which is a wrapper on `SecureClientHandle`
/// providing DNSSec validation.
///
/// *note* When upgrading from previous usage, both `SyncClient` and `SecureSyncClient` have an
/// signer which can be optionally associated to the Client. This replaces the previous per-function
/// parameter, and it will sign all update requests (this matches the `ClientFuture` API).
pub trait Client {
    /// The result future that will resolve into a DnsResponse
    type Response: Future<Output = Result<DnsResponse, ProtoError>> + 'static + Send + Unpin;
    /// The actual DNS request sender, aka Connection
    type Sender: DnsRequestSender<DnsResponseFuture = Self::Response>;
    /// A future that resolves into the Sender after connection
    type SenderFuture: Future<Output = Result<Self::Sender, ProtoError>> + 'static + Send + Unpin;
    /// A handle to send messages to the Sender
    type Handle: ClientHandle;

    /// Return the inner Futures items
    ///
    /// Consumes the connection and allows for future based operations afterward.
    #[allow(clippy::type_complexity)]
    fn new_future(
        &self,
    ) -> (
        ClientFuture<Self::SenderFuture, Self::Sender, Self::Response>,
        Self::Handle,
    );

    /// A *classic* DNS query, i.e. does not perform any DNSSec operations
    ///
    /// *Note* As of now, this will not recurse on PTR record responses, that is up to
    ///        the caller.
    ///
    /// # Arguments
    ///
    /// * `name` - the label to lookup
    /// * `query_class` - most likely this should always be DNSClass::IN
    /// * `query_type` - record type to lookup
    fn query(
        &self,
        name: &Name,
        query_class: DNSClass,
        query_type: RecordType,
    ) -> ClientResult<DnsResponse> {
        let mut reactor = Runtime::new()?;
        let (bg, mut client) = self.new_future();
        reactor
            .spawn(bg)
            .block_on(client.query(name.clone(), query_class, query_type))
    }

    /// Sends a NOTIFY message to the remote system
    ///
    /// # Arguments
    ///
    /// * `name` - the label which is being notified
    /// * `query_class` - most likely this should always be DNSClass::IN
    /// * `query_type` - record type which has been updated
    /// * `rrset` - the new version of the record(s) being notified
    fn notify<R>(
        &mut self,
        name: Name,
        query_class: DNSClass,
        query_type: RecordType,
        rrset: Option<R>,
    ) -> ClientResult<DnsResponse>
    where
        R: Into<RecordSet>,
    {
        let mut reactor = Runtime::new()?;
        let (bg, mut client) = self.new_future();
        reactor
            .spawn(bg)
            .block_on(client.notify(name, query_class, query_type, rrset))
    }

    /// Sends a record to create on the server, this will fail if the record exists (atomicity
    ///  depends on the server)
    ///
    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    ///  2.4.3 - RRset Does Not Exist
    ///
    ///   No RRs with a specified NAME and TYPE (in the zone and class denoted
    ///   by the Zone Section) can exist.
    ///
    ///   For this prerequisite, a requestor adds to the section a single RR
    ///   whose NAME and TYPE are equal to that of the RRset whose nonexistence
    ///   is required.  The RDLENGTH of this record is zero (0), and RDATA
    ///   field is therefore empty.  CLASS must be specified as NONE in order
    ///   to distinguish this condition from a valid RR whose RDLENGTH is
    ///   naturally zero (0) (for example, the NULL RR).  TTL must be specified
    ///   as zero (0).
    ///
    /// 2.5.1 - Add To An RRset
    ///
    ///    RRs are added to the Update Section whose NAME, TYPE, TTL, RDLENGTH
    ///    and RDATA are those being added, and CLASS is the same as the zone
    ///    class.  Any duplicate RRs will be silently ignored by the primary
    ///    master.
    /// ```
    ///
    /// # Arguments
    ///
    /// * `rrset` - the record(s) to create
    /// * `zone_origin` - the zone name to update, i.e. SOA name
    ///
    /// The update must go to a zone authority (i.e. the server used in the ClientConnection)
    fn create<R>(&self, rrset: R, zone_origin: Name) -> ClientResult<DnsResponse>
    where
        R: Into<RecordSet>,
    {
        let mut reactor = Runtime::new()?;
        let (bg, mut client) = self.new_future();
        reactor
            .spawn(bg)
            .block_on(client.create(rrset, zone_origin))
    }

    /// Appends a record to an existing rrset, optionally require the rrset to exist (atomicity
    ///  depends on the server)
    ///
    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    /// 2.4.1 - RRset Exists (Value Independent)
    ///
    ///   At least one RR with a specified NAME and TYPE (in the zone and class
    ///   specified in the Zone Section) must exist.
    ///
    ///   For this prerequisite, a requestor adds to the section a single RR
    ///   whose NAME and TYPE are equal to that of the zone RRset whose
    ///   existence is required.  RDLENGTH is zero and RDATA is therefore
    ///   empty.  CLASS must be specified as ANY to differentiate this
    ///   condition from that of an actual RR whose RDLENGTH is naturally zero
    ///   (0) (e.g., NULL).  TTL is specified as zero (0).
    ///
    /// 2.5.1 - Add To An RRset
    ///
    ///    RRs are added to the Update Section whose NAME, TYPE, TTL, RDLENGTH
    ///    and RDATA are those being added, and CLASS is the same as the zone
    ///    class.  Any duplicate RRs will be silently ignored by the primary
    ///    master.
    /// ```
    ///
    /// # Arguments
    ///
    /// * `rrset` - the record(s) to append to an RRSet
    /// * `zone_origin` - the zone name to update, i.e. SOA name
    /// * `must_exist` - if true, the request will fail if the record does not exist
    ///
    /// The update must go to a zone authority (i.e. the server used in the ClientConnection). If
    /// the rrset does not exist and must_exist is false, then the RRSet will be created.
    fn append<R>(&self, rrset: R, zone_origin: Name, must_exist: bool) -> ClientResult<DnsResponse>
    where
        R: Into<RecordSet>,
    {
        let mut reactor = Runtime::new()?;
        let (bg, mut client) = self.new_future();
        reactor
            .spawn(bg)
            .block_on(client.append(rrset, zone_origin, must_exist))
    }

    /// Compares and if it matches, swaps it for the new value (atomicity depends on the server)
    ///
    /// ```text
    ///  2.4.2 - RRset Exists (Value Dependent)
    ///
    ///   A set of RRs with a specified NAME and TYPE exists and has the same
    ///   members with the same RDATAs as the RRset specified here in this
    ///   section.  While RRset ordering is undefined and therefore not
    ///   significant to this comparison, the sets be identical in their
    ///   extent.
    ///
    ///   For this prerequisite, a requestor adds to the section an entire
    ///   RRset whose preexistence is required.  NAME and TYPE are that of the
    ///   RRset being denoted.  CLASS is that of the zone.  TTL must be
    ///   specified as zero (0) and is ignored when comparing RRsets for
    ///   identity.
    ///
    ///  2.5.4 - Delete An RR From An RRset
    ///
    ///   RRs to be deleted are added to the Update Section.  The NAME, TYPE,
    ///   RDLENGTH and RDATA must match the RR being deleted.  TTL must be
    ///   specified as zero (0) and will otherwise be ignored by the primary
    ///   master.  CLASS must be specified as NONE to distinguish this from an
    ///   RR addition.  If no such RRs exist, then this Update RR will be
    ///   silently ignored by the primary master.
    ///
    ///  2.5.1 - Add To An RRset
    ///
    ///   RRs are added to the Update Section whose NAME, TYPE, TTL, RDLENGTH
    ///   and RDATA are those being added, and CLASS is the same as the zone
    ///   class.  Any duplicate RRs will be silently ignored by the primary
    ///   master.
    /// ```
    ///
    /// # Arguments
    ///
    /// * `current` - the current rrset which must exist for the swap to complete
    /// * `new` - the new rrset with which to replace the current rrset
    /// * `zone_origin` - the zone name to update, i.e. SOA name
    ///
    /// The update must go to a zone authority (i.e. the server used in the ClientConnection).
    fn compare_and_swap<CR, NR>(
        &self,
        current: CR,
        new: NR,
        zone_origin: Name,
    ) -> ClientResult<DnsResponse>
    where
        CR: Into<RecordSet>,
        NR: Into<RecordSet>,
    {
        let mut reactor = Runtime::new()?;
        let (bg, mut client) = self.new_future();
        reactor
            .spawn(bg)
            .block_on(client.compare_and_swap(current, new, zone_origin))
    }

    /// Deletes a record (by rdata) from an rrset, optionally require the rrset to exist.
    ///
    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    /// 2.4.1 - RRset Exists (Value Independent)
    ///
    ///   At least one RR with a specified NAME and TYPE (in the zone and class
    ///   specified in the Zone Section) must exist.
    ///
    ///   For this prerequisite, a requestor adds to the section a single RR
    ///   whose NAME and TYPE are equal to that of the zone RRset whose
    ///   existence is required.  RDLENGTH is zero and RDATA is therefore
    ///   empty.  CLASS must be specified as ANY to differentiate this
    ///   condition from that of an actual RR whose RDLENGTH is naturally zero
    ///   (0) (e.g., NULL).  TTL is specified as zero (0).
    ///
    /// 2.5.4 - Delete An RR From An RRset
    ///
    ///   RRs to be deleted are added to the Update Section.  The NAME, TYPE,
    ///   RDLENGTH and RDATA must match the RR being deleted.  TTL must be
    ///   specified as zero (0) and will otherwise be ignored by the primary
    ///   master.  CLASS must be specified as NONE to distinguish this from an
    ///   RR addition.  If no such RRs exist, then this Update RR will be
    ///   silently ignored by the primary master.
    /// ```
    ///
    /// # Arguments
    ///
    /// * `rrset` - the record(s) to delete from a RRSet, the name, type and rdata must match the
    ///              record to delete
    /// * `zone_origin` - the zone name to update, i.e. SOA name
    ///
    /// The update must go to a zone authority (i.e. the server used in the ClientConnection). If
    /// the rrset does not exist and must_exist is false, then the RRSet will be deleted.
    fn delete_by_rdata<R>(&self, record: R, zone_origin: Name) -> ClientResult<DnsResponse>
    where
        R: Into<RecordSet>,
    {
        let mut reactor = Runtime::new()?;
        let (bg, mut client) = self.new_future();
        reactor
            .spawn(bg)
            .block_on(client.delete_by_rdata(record, zone_origin))
    }

    /// Deletes an entire rrset, optionally require the rrset to exist.
    ///
    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    /// 2.4.1 - RRset Exists (Value Independent)
    ///
    ///   At least one RR with a specified NAME and TYPE (in the zone and class
    ///   specified in the Zone Section) must exist.
    ///
    ///   For this prerequisite, a requestor adds to the section a single RR
    ///   whose NAME and TYPE are equal to that of the zone RRset whose
    ///   existence is required.  RDLENGTH is zero and RDATA is therefore
    ///   empty.  CLASS must be specified as ANY to differentiate this
    ///   condition from that of an actual RR whose RDLENGTH is naturally zero
    ///   (0) (e.g., NULL).  TTL is specified as zero (0).
    ///
    /// 2.5.2 - Delete An RRset
    ///
    ///   One RR is added to the Update Section whose NAME and TYPE are those
    ///   of the RRset to be deleted.  TTL must be specified as zero (0) and is
    ///   otherwise not used by the primary master.  CLASS must be specified as
    ///   ANY.  RDLENGTH must be zero (0) and RDATA must therefore be empty.
    ///   If no such RRset exists, then this Update RR will be silently ignored
    ///   by the primary master.
    /// ```
    ///
    /// # Arguments
    ///
    /// * `record` - the record to delete from a RRSet, the name, and type must match the
    ///              record set to delete
    /// * `zone_origin` - the zone name to update, i.e. SOA name
    ///
    /// The update must go to a zone authority (i.e. the server used in the ClientConnection). If
    /// the rrset does not exist and must_exist is false, then the RRSet will be deleted.
    fn delete_rrset(&self, record: Record, zone_origin: Name) -> ClientResult<DnsResponse> {
        let mut reactor = Runtime::new()?;
        let (bg, mut client) = self.new_future();
        reactor
            .spawn(bg)
            .block_on(client.delete_rrset(record, zone_origin))
    }

    /// Deletes all records at the specified name
    ///
    /// [RFC 2136](https://tools.ietf.org/html/rfc2136), DNS Update, April 1997
    ///
    /// ```text
    /// 2.5.3 - Delete All RRsets From A Name
    ///
    ///   One RR is added to the Update Section whose NAME is that of the name
    ///   to be cleansed of RRsets.  TYPE must be specified as ANY.  TTL must
    ///   be specified as zero (0) and is otherwise not used by the primary
    ///   master.  CLASS must be specified as ANY.  RDLENGTH must be zero (0)
    ///   and RDATA must therefore be empty.  If no such RRsets exist, then
    ///   this Update RR will be silently ignored by the primary master.
    /// ```
    ///
    /// # Arguments
    ///
    /// * `name_of_records` - the name of all the record sets to delete
    /// * `zone_origin` - the zone name to update, i.e. SOA name
    /// * `dns_class` - the class of the SOA
    ///
    /// The update must go to a zone authority (i.e. the server used in the ClientConnection). This
    /// operation attempts to delete all resource record sets the specified name regardless of
    /// the record type.
    fn delete_all(
        &self,
        name_of_records: Name,
        zone_origin: Name,
        dns_class: DNSClass,
    ) -> ClientResult<DnsResponse> {
        let mut reactor = Runtime::new()?;
        let (bg, mut client) = self.new_future();
        reactor
            .spawn(bg)
            .block_on(client.delete_all(name_of_records, zone_origin, dns_class))
    }
}

/// The Client is abstracted over either trust_dns::tcp::TcpClientConnection or
///  trust_dns::udp::UdpClientConnection.
///
/// Usage of TCP or UDP is up to the user. Some DNS servers
///  disallow TCP in some cases, so if TCP double check if UDP works.
pub struct SyncClient<CC> {
    conn: CC,
    signer: Option<Arc<Signer>>,
}

impl<CC> SyncClient<CC>
where
    CC: ClientConnection,
{
    /// Creates a new DNS client with the specified connection type
    ///
    /// # Arguments
    ///
    /// * `conn` - the [`ClientConnection`] to use for all communication
    pub fn new(conn: CC) -> Self {
        SyncClient { conn, signer: None }
    }

    /// Creates a new DNS client with the specified connection type and a SIG0 signer.
    ///
    /// This is necessary for signed update requests to update trust-dns-server entries.
    ///
    /// # Arguments
    ///
    /// * `conn` - the [`ClientConnection`] to use for all communication
    /// * `signer` - signer to use, this needs an associated private key
    pub fn with_signer(conn: CC, signer: Signer) -> Self {
        SyncClient {
            conn,
            signer: Some(Arc::new(signer)),
        }
    }
}

impl<CC> Client for SyncClient<CC>
where
    CC: ClientConnection,
{
    type Response = CC::Response;
    type Sender = CC::Sender;
    type SenderFuture = CC::SenderFuture;
    type Handle = BasicClientHandle<CC::Response>;

    #[allow(clippy::type_complexity)]
    fn new_future(
        &self,
    ) -> (
        ClientFuture<Self::SenderFuture, Self::Sender, Self::Response>,
        Self::Handle,
    ) {
        let stream = self.conn.new_stream(self.signer.clone());

        ClientFuture::connect(stream)
    }
}

/// A DNS client which will validate DNSSec records upon receipt
#[cfg(feature = "dnssec")]
pub struct SecureSyncClient<CC> {
    conn: CC,
    signer: Option<Arc<Signer>>,
}

#[cfg(feature = "dnssec")]
impl<CC> SecureSyncClient<CC>
where
    CC: ClientConnection,
{
    /// Creates a new DNS client with the specified connection type
    ///
    /// # Arguments
    ///
    /// * `client_connection` - the client_connection to use for all communication
    #[allow(clippy::new_ret_no_self)]
    pub fn new(conn: CC) -> SecureSyncClientBuilder<CC> {
        SecureSyncClientBuilder {
            conn,
            trust_anchor: None,
            signer: None,
        }
    }

    /// DNSSec validating query, this will return an error if the requested records can not be
    ///  validated against the trust_anchor.
    ///
    /// *Deprecated* This function only exists for backward compatibility. It's just a wrapper around `Client::query` at this point
    ///
    /// When the resolver receives an answer via the normal DNS lookup process, it then checks to
    ///  make sure that the answer is correct. Then starts
    ///  with verifying the DS and DNSKEY records at the DNS root. Then use the DS
    ///  records for the top level domain found at the root, e.g. 'com', to verify the DNSKEY
    ///  records in the 'com' zone. From there see if there is a DS record for the
    ///  subdomain, e.g. 'example.com', in the 'com' zone, and if there is use the
    ///  DS record to verify a DNSKEY record found in the 'example.com' zone. Finally,
    ///  verify the RRSIG record found in the answer for the rrset, e.g. 'www.example.com'.
    ///
    /// *Note* As of now, this will not recurse on PTR or CNAME record responses, that is up to
    ///        the caller.
    ///
    /// # Arguments
    ///
    /// * `query_name` - the label to lookup
    /// * `query_class` - most likely this should always be DNSClass::IN
    /// * `query_type` - record type to lookup
    #[deprecated(note = "use `Client::query` instead")]
    pub fn secure_query(
        &self,
        query_name: &Name,
        query_class: DNSClass,
        query_type: RecordType,
    ) -> ClientResult<DnsResponse> {
        let mut reactor = Runtime::new()?;
        let (bg, mut client) = self.new_future();
        reactor
            .spawn(bg)
            .block_on(client.query(query_name.clone(), query_class, query_type))
    }
}

#[cfg(feature = "dnssec")]
impl<CC> Client for SecureSyncClient<CC>
where
    CC: ClientConnection,
{
    type Response = CC::Response;
    type Sender = CC::Sender;
    type SenderFuture = CC::SenderFuture;
    type Handle = SecureClientHandle<BasicClientHandle<Self::Response>>;

    #[allow(clippy::type_complexity)]
    fn new_future(
        &self,
    ) -> (
        ClientFuture<Self::SenderFuture, Self::Sender, Self::Response>,
        Self::Handle,
    ) {
        let stream = self.conn.new_stream(self.signer.clone());

        let (background, handle) = ClientFuture::connect(stream);
        (background, SecureClientHandle::new(handle))
    }
}

#[cfg(feature = "dnssec")]
pub struct SecureSyncClientBuilder<CC>
where
    CC: ClientConnection,
{
    conn: CC,
    trust_anchor: Option<TrustAnchor>,
    signer: Option<Arc<Signer>>,
}

#[cfg(feature = "dnssec")]
impl<CC> SecureSyncClientBuilder<CC>
where
    CC: ClientConnection,
{
    /// This variant allows for the trust_anchor to be replaced
    ///
    /// # Arguments
    ///
    /// * `trust_anchor` - the set of trusted DNSKEY public_keys, by default this only contains the
    ///                    root public_key.
    pub fn trust_anchor(mut self, trust_anchor: TrustAnchor) -> Self {
        self.trust_anchor = Some(trust_anchor);
        self
    }

    /// Associate a signer to produce a SIG0 for all update requests
    ///
    /// This is necessary for signed update requests to update trust-dns-server entries
    ///
    /// # Arguments
    ///
    /// * `signer` - signer to use, this needs an associated private key
    pub fn signer(mut self, signer: Signer) -> Self {
        self.signer = Some(Arc::new(signer));
        self
    }

    pub fn build(self) -> SecureSyncClient<CC> {
        SecureSyncClient {
            conn: self.conn,
            signer: self.signer,
        }
    }
}

#[cfg(test)]
fn assert_send_and_sync<T: Send + Sync>() {}

#[test]
fn test_sync_client_send_and_sync() {
    use crate::tcp::TcpClientConnection;
    use crate::udp::UdpClientConnection;
    assert_send_and_sync::<SyncClient<UdpClientConnection>>();
    assert_send_and_sync::<SyncClient<TcpClientConnection>>();
}

#[test]
#[cfg(feature = "dnssec")]
fn test_secure_client_send_and_sync() {
    use crate::tcp::TcpClientConnection;
    use crate::udp::UdpClientConnection;
    assert_send_and_sync::<SecureSyncClient<UdpClientConnection>>();
    assert_send_and_sync::<SecureSyncClient<TcpClientConnection>>();
}
