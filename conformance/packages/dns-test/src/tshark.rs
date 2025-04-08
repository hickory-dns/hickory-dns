//! `tshark` JSON output parser

use core::result::Result as CoreResult;
use std::fmt;
use std::io::{self, BufRead, BufReader};
use std::net::Ipv4Addr;
use std::sync::atomic::{self, AtomicUsize};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::de::{DeserializeSeed, Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_with::{DisplayFromStr, serde_as};

use crate::Result;
use crate::container::{Child, Container};

static ID: AtomicUsize = AtomicUsize::new(0);

const UDP_PORT: u16 = 53;

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
    stdout_handle: JoinHandle<CoreResult<(), Box<dyn std::error::Error + Send + Sync>>>,

    /// Thread join handle for the thread capturing standard error.
    stderr_handle: JoinHandle<CoreResult<String, io::Error>>,

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
    pub fn new(container: &Container) -> Result<Self> {
        let id = ID.fetch_add(1, atomic::Ordering::Relaxed);
        let pidfile = pid_file(id);

        let tshark = format!(
            "echo $$ > {pidfile}
exec tshark -l -i eth0 -T json -O dns -f 'udp port {UDP_PORT}'"
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
            move || -> CoreResult<(), Box<dyn std::error::Error + Send + Sync>> {
                let mut deserializer = serde_json::Deserializer::from_reader(stdout);
                let adapter = StreamingCapture::new(sender, own_addr);
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

        let stderr_handle = thread::spawn(move || -> CoreResult<String, io::Error> {
            let mut buf = String::new();
            for line_res in stderr {
                buf.push_str(&line_res?);
                buf.push('\n');
            }
            Ok(buf)
        });

        Ok(Self {
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

    /// Waits until the captured packets satisfy some condition.
    pub fn wait_until(
        &mut self,
        condition: impl Fn(&[Capture]) -> bool,
        timeout: Duration,
    ) -> Result<()> {
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
    pub fn wait_for_capture(&mut self) -> Result<usize> {
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

    pub fn terminate(mut self) -> Result<Vec<Capture>> {
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

#[derive(Debug)]
pub struct Capture {
    pub message: Message,
    pub direction: Direction,
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

impl Direction {
    /// The address of the peer, independent of the direction of the packet
    pub fn peer_addr(&self) -> Ipv4Addr {
        match self {
            Direction::Incoming { source } => *source,
            Direction::Outgoing { destination } => *destination,
        }
    }

    pub fn try_into_incoming(self) -> CoreResult<Ipv4Addr, Self> {
        if let Self::Incoming { source } = self {
            Ok(source)
        } else {
            Err(self)
        }
    }

    pub fn try_into_outgoing(self) -> CoreResult<Ipv4Addr, Self> {
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
    dns: serde_json::Value,
}

#[serde_as]
#[derive(Debug, Deserialize)]
struct Ip {
    #[serde(rename = "ip.src")]
    #[serde_as(as = "DisplayFromStr")]
    src: Ipv4Addr,

    #[serde(rename = "ip.dst")]
    #[serde_as(as = "DisplayFromStr")]
    dst: Ipv4Addr,
}

/// This handles deserialization of the outer array in `tshark`'s JSON output, and makes each
/// captured packet available in a streaming fashion via synchronization primitives.
///
/// Since the output of `tshark -T json` is one big JSON array, we can't just use
/// [`serde_json::StreamDeserializer`], which expects multiple self-delimiting JSON values.
struct StreamingCapture {
    sender: Sender<Capture>,
    own_addr: Ipv4Addr,
}

impl StreamingCapture {
    fn new(sender: Sender<Capture>, own_addr: Ipv4Addr) -> Self {
        Self { sender, own_addr }
    }
}

impl<'de> DeserializeSeed<'de> for StreamingCapture {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> CoreResult<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        let visitor = StreamingCaptureVisitor::new(self.sender, self.own_addr);
        deserializer.deserialize_seq(visitor)
    }
}

/// Visitor to accompany [`StreamingCapture`].
struct StreamingCaptureVisitor {
    sender: Sender<Capture>,
    own_addr: Ipv4Addr,
}

impl StreamingCaptureVisitor {
    fn new(sender: Sender<Capture>, own_addr: Ipv4Addr) -> Self {
        Self { sender, own_addr }
    }
}

impl<'de> Visitor<'de> for StreamingCaptureVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a sequence")
    }

    fn visit_seq<A>(self, mut seq: A) -> CoreResult<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(entry) = seq.next_element::<Entry>()? {
            let Layers { ip, dns } = entry._source.layers;

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
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::client::{Client, DigSettings};
    use crate::name_server::NameServer;
    use crate::record::RecordType;
    use crate::{FQDN, Implementation, Network, Resolver};

    use super::*;

    #[test]
    fn nameserver() -> Result<()> {
        let network = &Network::new()?;
        let ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, network)?.start()?;
        let mut tshark = Tshark::new(ns.container())?;

        let client = Client::new(network)?;
        let resp = client.dig(
            DigSettings::default(),
            ns.ipv4_addr(),
            RecordType::SOA,
            &FQDN::ROOT,
        )?;

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

        assert_eq!(
            client.ipv4_addr(),
            second.direction.try_into_outgoing().unwrap()
        );

        Ok(())
    }

    #[test]
    fn resolver() -> Result<()> {
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
        let mut tshark = resolver.eavesdrop()?;
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
}
