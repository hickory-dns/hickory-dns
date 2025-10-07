//! `tshark` JSON output parser

use std::fmt::{self, Write};
use std::io::{self, BufRead, BufReader};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::atomic::{self, AtomicUsize};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::de::{DeserializeSeed, Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::Error;
use crate::container::{Child, Container};

static ID: AtomicUsize = AtomicUsize::new(0);

const DNS_PORT: u16 = 53;

fn pid_file(id: usize) -> String {
    format!("/tmp/tshark{id}.pid")
}

pub struct Tshark {
    /// Subprocess running `docker exec` that in turn runs `tshark` inside the container.
    child: Child,

    /// Handle for the container in which `tshark` is capturing packets.
    container: Container,

    /// Unique number to identify the file storing this `tshark` instance's PID.
    id: usize,

    /// Thread join handle for the thread parsing standard output into packets.
    stdout_handle: JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,

    /// Thread join handle for the thread capturing standard error.
    stderr_handle: JoinHandle<Result<String, io::Error>>,

    /// Receives captured packets from the thread reading standard output.
    receiver: Receiver<Capture>,

    /// Packets received so far.
    captures: Vec<Capture>,

    /// High watermark count of packets observed by [`Self::wait_for_capture`].
    ///
    /// This field keeps track of how many packets had been received at the time
    /// [`Self::wait_for_capture`] was last called. This is done to match the behavior of the
    /// previous implementation of this method.
    wait_capture_count_watermark: usize,
}

impl Tshark {
    /// Spawn a Tshark instance for the given container capturing plaintext UDP DNS traffic.
    pub fn new(container: &Container) -> Result<Self, Error> {
        Self::builder().build(container)
    }

    /// Construct a TsharkBuilder that can build a customized Tshark instance.
    pub fn builder() -> TsharkBuilder {
        TsharkBuilder::default()
    }

    /// Waits until the captured packets satisfy some condition.
    pub fn wait_until(
        &mut self,
        condition: impl Fn(&[Capture]) -> bool,
        timeout: Duration,
    ) -> Result<(), Error> {
        let deadline = Instant::now() + timeout;
        while !condition(&self.captures) {
            let recv_timeout = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_default();
            match self.receiver.recv_timeout(recv_timeout) {
                Ok(capture) => self.captures.push(capture),
                Err(RecvTimeoutError::Timeout) => return Err("timed out waiting for packet".into()),
                Err(RecvTimeoutError::Disconnected) => return Err("unexpected EOF".into()),
            }
        }
        Ok(())
    }

    /// Blocks until `tshark` reports that it has captured new DNS messages.
    ///
    /// This method returns the number of newly captured messages.
    ///
    /// Consider using [`Self::wait_until`] instead, and waiting for packets with specific
    /// properties.
    pub fn wait_for_capture(&mut self) -> Result<usize, Error> {
        let old_watermark = self.wait_capture_count_watermark;
        if self.captures.len() <= old_watermark {
            // Block until we receive a new packet.
            match self.receiver.recv() {
                Ok(capture) => self.captures.push(capture),
                Err(_) => return Err("unexpected EOF".into()),
            }
        }
        // If there are more packets ready in the channel, move them into the vector.
        while let Ok(capture) = self.receiver.try_recv() {
            self.captures.push(capture);
        }

        let new_watermark = self.captures.len();
        self.wait_capture_count_watermark = new_watermark;
        Ok(new_watermark - old_watermark)
    }

    pub fn terminate(mut self) -> Result<Vec<Capture>, Error> {
        let pidfile = pid_file(self.id);
        let kill = format!("test -f {pidfile} || sleep 1; kill $(cat {pidfile})");

        self.container.status_ok(&["sh", "-c", &kill])?;

        // wait until tshark exits and closes stdout (and stderr)
        let output = self.child.wait()?;
        if !output.status.success() {
            let stderr_output = self
                .stderr_handle
                .join()
                .map_err(|_| "stderr thread panicked")??;

            return Err(format!("the `tshark` process failed\n{stderr_output}").into());
        }

        self.stdout_handle
            .join()
            .map_err(|_| "stdout thread panicked")?
            .map_err(|e| e.to_string())?;

        // Read from the channel until it produces `Err(RecvError)` due to the other thread hanging
        // up.
        while let Ok(capture) = self.receiver.recv() {
            self.captures.push(capture);
        }

        Ok(self.captures)
    }
}

pub struct TsharkBuilder {
    filters: Vec<ProtocolFilter>,
    ssl_keylog_file: Option<String>,
    include_non_dns_packets: bool,
}

impl TsharkBuilder {
    /// Set the capture filters.
    ///
    /// Multiple filters are logically OR'd together.
    pub fn filters(mut self, filters: Vec<ProtocolFilter>) -> Self {
        self.filters = filters;
        self
    }

    /// Set the `SSLKEYLOGFILE` path to use to decrypt encrypted traffic.
    pub fn ssl_keylog_file(mut self, path: impl Into<String>) -> Self {
        self.ssl_keylog_file = Some(path.into());
        self
    }

    /// Include packets without DNS data (e.g., failed connection attempts).
    pub fn include_non_dns_packets(mut self, include: bool) -> Self {
        self.include_non_dns_packets = include;
        self
    }

    /// Spawn a new `Tshark` instance for the `Container`.
    pub fn build(self, container: &Container) -> Result<Tshark, Error> {
        let id = ID.fetch_add(1, atomic::Ordering::Relaxed);
        let pidfile = pid_file(id);

        let mut protocol_filter = String::new();
        for filter in self.filters {
            if !protocol_filter.is_empty() {
                protocol_filter.push_str(" or ");
            }
            match filter.protocol {
                Protocol::Udp => write!(protocol_filter, "udp port {}", filter.port)?,
                Protocol::Tcp => write!(protocol_filter, "tcp port {}", filter.port)?,
            }
        }

        let ssl_keylog_arg = self
            .ssl_keylog_file
            .map(|file| format!("-o tls.keylog_file:{file} "))
            .unwrap_or_default();

        let tshark = format!(
            "echo $$ > {pidfile}
exec tshark -l -i eth0 -T json -O dns {ssl_keylog_arg}-f '({protocol_filter})'"
        );
        let mut child = container.spawn(&["sh", "-c", &tshark])?;

        let stderr = child.stderr()?;
        let mut stderr = BufReader::new(stderr).lines();

        let (sender, receiver) = channel();

        // Read from stdout and stderr on separate threads. This ensures the subprocess won't block
        // when writing to either due to full pipe buffers.
        let stdout = child.stdout()?;
        let stdout_handle = thread::spawn({
            let own_addr = container.ipv4_addr();
            let include_non_dns_packets = self.include_non_dns_packets;
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                let mut deserializer = serde_json::Deserializer::from_reader(stdout);
                let adapter = StreamingCapture::new(sender, own_addr, include_non_dns_packets);
                adapter.deserialize(&mut deserializer)?;
                Ok(())
            }
        });

        for res in stderr.by_ref() {
            let line = res?;

            if line.contains("Capture started") {
                break;
            }
        }

        let stderr_handle = thread::spawn(move || -> Result<String, io::Error> {
            let mut buf = String::new();
            for line_res in stderr {
                buf.push_str(&line_res?);
                buf.push('\n');
            }
            Ok(buf)
        });

        Ok(Tshark {
            container: container.clone(),
            child,
            stdout_handle,
            stderr_handle,
            id,
            receiver,
            captures: Vec::new(),
            wait_capture_count_watermark: 0,
        })
    }
}

impl Default for TsharkBuilder {
    fn default() -> Self {
        Self {
            filters: vec![ProtocolFilter::default()],
            ssl_keylog_file: None,
            include_non_dns_packets: false,
        }
    }
}

#[derive(Clone, Copy)]
pub struct ProtocolFilter {
    port: u16,
    protocol: Protocol,
}

impl ProtocolFilter {
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }
}

impl Default for ProtocolFilter {
    fn default() -> Self {
        Self {
            port: DNS_PORT,
            protocol: Protocol::Udp,
        }
    }
}

#[derive(Debug)]
pub struct Capture {
    pub message: Message,
    pub direction: Direction,
    pub protocol: Protocol,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Debug)]
pub struct Message {
    // TODO this should be more "cooked", i.e. be deserialized into a `struct`
    inner: serde_json::Value,
}

impl Message {
    /// Returns `true` if the DO bit is set
    ///
    /// Returns `None` if there's no OPT pseudo-RR
    pub fn is_do_bit_set(&self) -> Option<bool> {
        let do_bit = match self
            .opt_record()?
            .get("dns.resp.z_tree")?
            .get("dns.resp.z.do")?
            .as_str()?
        {
            "1" => true,
            "0" => false,
            _ => return None,
        };

        Some(do_bit)
    }

    /// Returns the "sender's UDP payload size" field in the OPT pseudo-RR
    ///
    /// Returns `None` if there's no OPT record present
    pub fn udp_payload_size(&self) -> Option<u16> {
        self.opt_record()?
            .get("dns.rr.udp_payload_size")?
            .as_str()?
            .parse()
            .ok()
    }

    pub fn as_value(&self) -> &serde_json::Value {
        &self.inner
    }

    pub fn is_ad_flag_set(&self) -> bool {
        let Some(authenticated) = self.inner["dns.flags_tree"]
            .as_object()
            .unwrap()
            .get("dns.flags.authenticated")
        else {
            return false;
        };

        let authenticated = authenticated.as_str().unwrap();
        assert_eq!("1", authenticated);
        true
    }

    fn opt_record(&self) -> Option<&serde_json::Value> {
        for (key, value) in self.inner.get("Additional records")?.as_object()? {
            if key.ends_with(": type OPT") {
                return Some(value);
            }
        }

        None
    }

    pub fn is_rd_flag_set(&self) -> bool {
        let Some(recursion_desired) = self.inner["dns.flags_tree"]
            .as_object()
            .unwrap()
            .get("dns.flags.recdesired")
        else {
            return false;
        };

        let recursion_desired = recursion_desired.as_str().unwrap();
        match recursion_desired {
            "1" => true,
            "0" => false,
            _ => panic!("unexpected value for dns.flags.recdesired: {recursion_desired}"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Direction {
    Incoming { source: Ipv4Addr },
    Outgoing { destination: Ipv4Addr },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Udp,
    Tcp,
}

impl Direction {
    /// The address of the peer, independent of the direction of the packet
    pub fn peer_addr(&self) -> Ipv4Addr {
        match self {
            Direction::Incoming { source } => *source,
            Direction::Outgoing { destination } => *destination,
        }
    }

    pub fn try_into_incoming(self) -> Result<Ipv4Addr, Self> {
        if let Self::Incoming { source } = self {
            Ok(source)
        } else {
            Err(self)
        }
    }

    pub fn try_into_outgoing(self) -> Result<Ipv4Addr, Self> {
        if let Self::Outgoing { destination } = self {
            Ok(destination)
        } else {
            Err(self)
        }
    }
}

#[derive(Deserialize)]
struct Entry {
    _source: Source,
}

#[derive(Deserialize)]
struct Source {
    layers: Layers,
}

#[derive(Deserialize)]
struct Layers {
    ip: Ip,
    udp: Option<TransportLayer>,
    tcp: Option<TransportLayer>,
    dns: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct Ip {
    #[serde(rename = "ip.src", deserialize_with = "deserialize_ip")]
    src: Ipv4Addr,

    #[serde(rename = "ip.dst", deserialize_with = "deserialize_ip")]
    dst: Ipv4Addr,
}

pub(super) fn deserialize_ip<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Ipv4Addr, D::Error> {
    Ipv4Addr::from_str(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
}

#[derive(Debug, Deserialize)]
struct TransportLayer {
    #[serde(
        rename = "udp.srcport",
        alias = "tcp.srcport",
        deserialize_with = "deserialize_port"
    )]
    src_port: u16,

    #[serde(
        rename = "udp.dstport",
        alias = "tcp.dstport",
        deserialize_with = "deserialize_port"
    )]
    dst_port: u16,
}

fn deserialize_port<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u16, D::Error> {
    u16::from_str(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
}

/// This handles deserialization of the outer array in `tshark`'s JSON output, and makes each
/// captured packet available in a streaming fashion via synchronization primitives.
///
/// Since the output of `tshark -T json` is one big JSON array, we can't just use
/// [`serde_json::StreamDeserializer`], which expects multiple self-delimiting JSON values.
struct StreamingCapture {
    sender: Sender<Capture>,
    own_addr: Ipv4Addr,
    include_non_dns_packets: bool,
}

impl StreamingCapture {
    fn new(sender: Sender<Capture>, own_addr: Ipv4Addr, include_non_dns_packets: bool) -> Self {
        Self {
            sender,
            own_addr,
            include_non_dns_packets,
        }
    }
}

impl<'de> DeserializeSeed<'de> for StreamingCapture {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(StreamingCaptureVisitor::new(
            self.sender,
            self.own_addr,
            self.include_non_dns_packets,
        ))
    }
}

/// Visitor to accompany [`StreamingCapture`].
struct StreamingCaptureVisitor {
    sender: Sender<Capture>,
    own_addr: Ipv4Addr,
    include_non_dns_packets: bool,
}

impl StreamingCaptureVisitor {
    fn new(sender: Sender<Capture>, own_addr: Ipv4Addr, include_non_dns_packets: bool) -> Self {
        Self {
            sender,
            own_addr,
            include_non_dns_packets,
        }
    }
}

impl<'de> Visitor<'de> for StreamingCaptureVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a sequence")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(entry) = seq.next_element::<Entry>()? {
            let Layers { ip, udp, tcp, dns } = entry._source.layers;

            // Skip packets without DNS data (e.g., TCP handshake packets)
            // unless configured to include them.
            let dns = match dns {
                Some(dns) => dns,
                None if self.include_non_dns_packets => serde_json::json!({}),
                None => continue,
            };

            // Determine protocol and extract port information
            let (protocol, src_port, dst_port) = match (udp, tcp) {
                (Some(udp), None) => (Protocol::Udp, udp.src_port, udp.dst_port),
                (None, Some(tcp)) => (Protocol::Tcp, tcp.src_port, tcp.dst_port),
                _ => {
                    return Err(A::Error::custom(
                        "packet has DNS data with missing or conflicting UDP/TCP layers",
                    ));
                }
            };

            let direction = if ip.dst == self.own_addr {
                Direction::Incoming { source: ip.src }
            } else if ip.src == self.own_addr {
                Direction::Outgoing {
                    destination: ip.dst,
                }
            } else {
                return Err(A::Error::custom(format!(
                    "unexpected IP packet found in wireshark trace: {ip:?}"
                )));
            };

            let _ = self.sender.send(Capture {
                message: Message { inner: dns },
                direction,
                protocol,
                src_port,
                dst_port,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::client::{Client, DigSettings};
    use crate::name_server::{NameServer, Running};
    use crate::record::RecordType;
    use crate::{FQDN, Implementation, Network, Pki, Resolver};

    use super::*;

    #[test]
    fn nameserver_udp() -> Result<(), Error> {
        let network = &Network::new()?;
        let ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, network)?.start()?;
        let tshark = Tshark::new(ns.container())?;
        test_nameserver(network, ns, DigSettings::default(), Protocol::Udp, tshark)
    }

    #[test]
    fn nameserver_tcp() -> Result<(), Error> {
        let network = &Network::new()?;
        let ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, network)?.start()?;
        let tshark = Tshark::builder()
            .filters(vec![ProtocolFilter::default().protocol(Protocol::Tcp)])
            .build(ns.container())?;
        let dig_settings = *DigSettings::default().tcp();
        test_nameserver(network, ns, dig_settings, Protocol::Tcp, tshark)
    }

    #[test]
    fn nameserver_dot() -> Result<(), Error> {
        let network = &Network::new()?;
        // NOTE: We use an implementation here we know supports SSLKEYLOGFILE.
        let ns = NameServer::builder(Implementation::hickory(), FQDN::ROOT, network.clone())
            .pki(Pki::new()?.into())
            .build()?
            .start()?;
        let tshark = Tshark::builder()
            .filters(vec![
                ProtocolFilter::default()
                    .protocol(Protocol::Tcp)
                    .port(DOT_PORT),
            ])
            .ssl_keylog_file("/tmp/sslkeys.log") // See hickory.Dockerfile
            .build(ns.container())?;
        // NOTE: We have to specify both tcp() and tls() because the default settings will write
        // +notcp otherwise, and that takes priority over the +tls arg!
        let dig_settings = *DigSettings::default().tcp().tls();
        test_nameserver(network, ns, dig_settings, Protocol::Tcp, tshark)
    }

    fn test_nameserver(
        network: &Network,
        ns: NameServer<Running>,
        dig_settings: DigSettings,
        expected_protocol: Protocol,
        mut tshark: Tshark,
    ) -> Result<(), Error> {
        let client = Client::new(network)?;
        let resp = client.dig(dig_settings, ns.ipv4_addr(), RecordType::SOA, &FQDN::ROOT)?;

        assert!(resp.status.is_noerror());

        tshark.wait_until(
            |captures| {
                captures
                    .iter()
                    .any(|capture| matches!(capture.direction, Direction::Outgoing { .. }))
            },
            Duration::from_secs(10),
        )?;

        let messages = tshark.terminate()?;

        let [first, second] = messages.try_into().expect("2 DNS messages");
        assert_eq!(
            client.ipv4_addr(),
            first.direction.try_into_incoming().unwrap()
        );
        assert_eq!(first.protocol, expected_protocol);

        assert_eq!(
            client.ipv4_addr(),
            second.direction.try_into_outgoing().unwrap()
        );
        assert_eq!(second.protocol, expected_protocol);
        assert_eq!(second.dst_port, first.src_port,);

        Ok(())
    }

    #[test]
    fn nameserver_multiple_filters() -> Result<(), Error> {
        let network = &Network::new()?;
        // NOTE: We use an implementation here we know supports SSLKEYLOGFILE.
        let ns = NameServer::builder(Implementation::hickory(), FQDN::ROOT, network.clone())
            .pki(Pki::new()?.into())
            .build()?
            .start()?;
        let mut tshark = Tshark::builder()
            // Set up a capture filter for _both_ plaintext UDP on 53, and DOT encrypted TCP on 853.
            .filters(vec![
                ProtocolFilter::default(),
                ProtocolFilter::default()
                    .protocol(Protocol::Tcp)
                    .port(DOT_PORT),
            ])
            .ssl_keylog_file("/tmp/sslkeys.log") // See hickory.Dockerfile
            .build(ns.container())?;

        let client = Client::new(network)?;

        // Make a plaintext UDP query first.
        let resp = client.dig(
            DigSettings::default(),
            ns.ipv4_addr(),
            RecordType::SOA,
            &FQDN::ROOT,
        )?;
        assert!(resp.status.is_noerror());

        // And then make a DoT encrypted TCP query second.
        let resp = client.dig(
            *DigSettings::default().tcp().tls(),
            ns.ipv4_addr(),
            RecordType::SOA,
            &FQDN::ROOT,
        )?;
        assert!(resp.status.is_noerror());

        // Wait until we've captured two incoming messages, or hit the timeout.
        tshark.wait_until(
            |captures| {
                captures
                    .iter()
                    .filter(|capture| matches!(capture.direction, Direction::Incoming { .. }))
                    .count()
                    == 2
            },
            Duration::from_secs(10),
        )?;

        // Grab just the inbound messages. There should be two.
        let messages = tshark
            .terminate()?
            .into_iter()
            .filter(|m| matches!(m.direction, Direction::Incoming { .. }))
            .collect::<Vec<_>>();
        let [first, second] = messages.try_into().expect("2 DNS messages");

        // We should have gotten the right protocol/dest port messages in the right order.
        assert_eq!(first.protocol, Protocol::Udp);
        assert_eq!(first.dst_port, DNS_PORT);
        assert_eq!(second.protocol, Protocol::Tcp);
        assert_eq!(second.dst_port, DOT_PORT);
        Ok(())
    }

    #[test]
    fn resolver() -> Result<(), Error> {
        let network = &Network::new()?;
        let mut root_ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, network)?;
        let mut com_ns = NameServer::new(&Implementation::Unbound, FQDN::TEST_TLD, network)?;

        let mut nameservers_ns =
            NameServer::new(&Implementation::Unbound, FQDN::TEST_DOMAIN, network)?;
        nameservers_ns.add(root_ns.a()).add(com_ns.a());
        let nameservers_ns = nameservers_ns.start()?;

        com_ns.referral_nameserver(&nameservers_ns);
        let com_ns = com_ns.start()?;

        root_ns.referral_nameserver(&com_ns);
        let root_ns = root_ns.start()?;

        let resolver = Resolver::new(network, root_ns.root_hint())
            .start_with_subject(&Implementation::Unbound)?;
        let mut tshark = resolver.eavesdrop_udp()?;
        let resolver_addr = resolver.ipv4_addr();

        let client = Client::new(network)?;
        let settings = *DigSettings::default().recurse();
        let output = client.dig(settings, dbg!(resolver_addr), RecordType::A, root_ns.fqdn())?;

        assert!(output.status.is_noerror());

        let count = tshark.wait_for_capture()?;
        dbg!(count);

        let messages = tshark.terminate()?;
        assert!(messages.len() > 2);

        let ns_addrs = dbg!([
            root_ns.ipv4_addr(),
            com_ns.ipv4_addr(),
            nameservers_ns.ipv4_addr(),
        ]);
        let client_addr = dbg!(client.ipv4_addr());

        let mut from_client_count = 0;
        let mut to_client_count = 0;
        let mut to_ns_count = 0;
        let mut from_ns_count = 0;
        for message in messages {
            match message.direction {
                Direction::Incoming { source } => {
                    if source == client_addr {
                        from_client_count += 1;
                    } else if ns_addrs.contains(&source) {
                        from_ns_count += 1;
                    } else {
                        panic!(
                            "found packet coming from {source} which is outside the network graph"
                        )
                    }
                }

                Direction::Outgoing { destination } => {
                    if destination == client_addr {
                        to_client_count += 1;
                    } else if ns_addrs.contains(&destination) {
                        to_ns_count += 1;
                    } else {
                        panic!(
                            "found packet going to {destination} which is outside the network graph"
                        )
                    }
                }
            }
        }

        // query from client (dig)
        assert_eq!(1, from_client_count);

        // answer to client (dig)
        assert_eq!(1, to_client_count);

        // check that all queries sent to nameservers were answered
        assert_eq!(to_ns_count, from_ns_count);

        Ok(())
    }

    const DOT_PORT: u16 = 853;
}
