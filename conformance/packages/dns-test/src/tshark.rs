//! `tshark` JSON output parser

use core::result::Result as CoreResult;
use std::io::{BufRead, BufReader, Lines};
use std::net::Ipv4Addr;
use std::process::ChildStdout;
use std::sync::atomic::{self, AtomicUsize};

use serde::Deserialize;
use serde_with::{serde_as, DisplayFromStr};

use crate::container::{Child, Container};
use crate::Result;

static ID: AtomicUsize = AtomicUsize::new(0);

const UDP_PORT: u16 = 53;

impl Container {
    pub fn eavesdrop(&self) -> Result<Tshark> {
        let id = ID.fetch_add(1, atomic::Ordering::Relaxed);
        let pidfile = pid_file(id);
        let capture_file = capture_file(id);

        // `docker exec $child` merges the child's stderr and stdout streams and pipes them into
        // its stdout. as we cannot tell stdout (JSON) from stderr (log message) from the host side,
        // we'll redirect the JSON output to a file inside the container and read the log messages
        // from the host side
        // --log-level info --log-domain main
        let tshark = format!(
            "echo $$ > {pidfile}
exec tshark --log-level debug --log-domain main,capture -l -i eth0 -T json -O dns -f 'udp port {UDP_PORT}' > {capture_file}"
        );
        let mut child = self.spawn(&["sh", "-c", &tshark])?;

        let stdout = child.stdout()?;
        let mut stdout = BufReader::new(stdout).lines();

        for res in stdout.by_ref() {
            let line = res?;

            if line.contains("Capture started") {
                break;
            }
        }

        Ok(Tshark {
            container: self.clone(),
            child,
            stdout,
            id,
        })
    }
}

fn pid_file(id: usize) -> String {
    format!("/tmp/tshark{id}.pid")
}

fn capture_file(id: usize) -> String {
    format!("/tmp/tshark{id}.json")
}

pub struct Tshark {
    child: Child,
    container: Container,
    id: usize,
    stdout: Lines<BufReader<ChildStdout>>,
}

impl Tshark {
    /// Blocks until `tshark` reports the number of expected captured packets.
    pub fn wait_for_new_packets(&mut self, expected: usize) -> Result<usize> {
        let mut captured = 0;

        loop {
            captured += self.wait_for_capture()?;
            if captured >= expected {
                break;
            }
        }

        Ok(captured)
    }

    /// Blocks until `tshark` reports that it has captured new DNS messages
    ///
    /// This method returns the number of newly captured messages
    // XXX maybe do this automatically / always in `terminate`?
    pub fn wait_for_capture(&mut self) -> Result<usize> {
        // sync_pipe_input_cb(): new packets NN
        for res in self.stdout.by_ref() {
            let line = res?;

            if line.contains(": new packets ") {
                let (_rest, count) = line.rsplit_once(' ').unwrap();
                return Ok(count.parse()?);
            }
        }

        Err("unexpected EOF".into())
    }

    pub fn terminate(self) -> Result<Vec<Capture>> {
        let pidfile = pid_file(self.id);
        let kill = format!("test -f {pidfile} || sleep 1; kill $(cat {pidfile})");

        self.container.status_ok(&["sh", "-c", &kill])?;
        let output = self.child.wait()?;

        if !output.status.success() {
            return Err("could not terminate the `tshark` process".into());
        }

        // wait until the message "NN packets captured" appears
        // wireshark will close stderr after printing that so exhausting
        // the file descriptor produces the same result
        for res in self.stdout {
            res?;
        }

        let capture_file = capture_file(self.id);
        let output = self.container.stdout(&["cat", &capture_file])?;

        let mut messages = vec![];
        let entries: Vec<Entry> = serde_json::from_str(&output)?;

        let own_addr = self.container.ipv4_addr();
        for entry in entries {
            let Layers { ip, dns } = entry._source.layers;

            let direction = if ip.dst == own_addr {
                Direction::Incoming { source: ip.src }
            } else if ip.src == own_addr {
                Direction::Outgoing {
                    destination: ip.dst,
                }
            } else {
                return Err(
                    format!("unexpected IP packet found in wireshark trace: {ip:?}").into(),
                );
            };

            messages.push(Capture {
                message: Message { inner: dns },
                direction,
            });
        }

        Ok(messages)
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

#[cfg(test)]
mod tests {
    use crate::client::{Client, DigSettings};
    use crate::name_server::NameServer;
    use crate::record::RecordType;
    use crate::{Implementation, Network, Resolver, FQDN};

    use super::*;

    #[test]
    fn nameserver() -> Result<()> {
        let network = &Network::new()?;
        let ns = NameServer::new(&Implementation::Unbound, FQDN::ROOT, network)?.start()?;
        let mut tshark = ns.eavesdrop()?;

        let client = Client::new(network)?;
        let resp = client.dig(
            DigSettings::default(),
            ns.ipv4_addr(),
            RecordType::SOA,
            &FQDN::ROOT,
        )?;

        assert!(resp.status.is_noerror());

        tshark.wait_for_new_packets(2)?;

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
        let mut com_ns = NameServer::new(&Implementation::Unbound, FQDN::COM, network)?;

        let mut nameservers_ns =
            NameServer::new(&Implementation::Unbound, FQDN("nameservers.com.")?, network)?;
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
