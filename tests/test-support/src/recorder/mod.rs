//! Test utility to record and replay DNS transactions with internet-based servers.

use std::{
    env::{self, VarError},
    fs::{File, OpenOptions},
    io::{self, BufWriter, ErrorKind, Write},
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    path::PathBuf,
    process::{Command, Stdio},
    string::FromUtf8Error,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use tracing::{debug, error, warn};

/// Records and plays back DNS-over-UDP transactions with DNS servers on the internet.
///
/// This is intended to enable realistic tests against a wide variety of DNS servers, while being
/// reproducible and allowing tests to be re-run offline. It operates in one of two modes, on
/// whether the environment variable `DNS_RECORDER` is set to `record`.
///
/// If `DNS_RECORDER=record` is set, it acts as a minimal DNS proxy in front of the target
/// internet-based DNS server, and saves all queries and responses it processes to a file. This file
/// should be checked in to source control alongside the test that uses it.
///
/// If `DNS_RECORDER` is not set, then no internet connections are made, and incoming queries are
/// compared against the transactions previously saved in the file. If there is a matching query,
/// then its response will be sent back.
pub struct UdpDnsRecorder {
    local_addr: SocketAddr,
    path: PathBuf,
    inner: Arc<Mutex<RecorderInner>>,
    handle: JoinHandle<()>,
    stop: Arc<AtomicBool>,
}

impl UdpDnsRecorder {
    /// Construct a new instance that acts as a proxy for the given remote address, and loads from
    /// or saves to the given filename.
    pub fn new(remote_addr: SocketAddr, path: PathBuf) -> Result<Self, Error> {
        Self::with_record(remote_addr, path, is_recording())
    }

    fn with_record(remote_addr: SocketAddr, path: PathBuf, record: bool) -> Result<Self, Error> {
        let source = if record {
            let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
            socket.set_read_timeout(Some(DNS_TIMEOUT))?;
            Source::Upstream {
                remote_addr,
                socket,
                transactions: Vec::new(),
            }
        } else {
            let file = match File::open(&path) {
                Ok(file) => file,
                Err(err) if err.kind() == ErrorKind::NotFound => return Err(Error::NoFile),
                Err(err) => return Err(err.into()),
            };
            let recording = serde_json::from_reader(&file)?;
            Source::Replay(recording)
        };

        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        socket.set_read_timeout(Some(RECV_TIMEOUT))?;
        let local_addr = socket.local_addr()?;

        let inner = Arc::new(Mutex::new(RecorderInner {
            source,
            error: None,
        }));
        let stop = Arc::new(AtomicBool::new(false));

        debug!(%local_addr, %remote_addr, "starting proxy server");
        let handle = thread::spawn({
            let inner = Arc::clone(&inner);
            let stop = Arc::clone(&stop);
            move || RecorderInner::run(inner, stop, socket)
        });

        Ok(Self {
            local_addr,
            path,
            inner,
            handle,
            stop,
        })
    }

    /// The local socket address of the proxy. Pass this to your DNS client instead of the
    /// internet-based DNS server.
    pub fn local_address(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stop the proxy, write out the recording file if applicable, and return any error
    /// encountered while running.
    pub fn stop(self) -> Result<(), Error> {
        self.stop.fetch_or(true, Ordering::Relaxed);

        self.handle.join().map_err(|_| Error::Panic)?;

        let mut guard = self.inner.lock().unwrap();
        if let Source::Upstream {
            remote_addr,
            transactions,
            ..
        } = &guard.source
        {
            let recording = Recording {
                protocol: "UDP".to_owned(),
                remote_address: *remote_addr,
                transactions: transactions
                    .iter()
                    .map(|(query, response)| {
                        let mut query_hex = query.clone();
                        query_hex[0..2].copy_from_slice(&[0; 2]);
                        let query_dissected = dissect(&query_hex);
                        let mut response_hex = response.clone();
                        response_hex[0..2].copy_from_slice(&[0; 2]);
                        let response_dissected = dissect(&response_hex);
                        Transaction {
                            query_hex,
                            query_dissected,
                            response_hex,
                            response_dissected,
                        }
                    })
                    .collect(),
            };

            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&self.path)?;
            serde_json::to_writer_pretty(&file, &recording)?;
            file.flush()?;
        }
        if let Some(error) = guard.error.take() {
            Err(error)
        } else {
            Ok(())
        }
    }
}

struct RecorderInner {
    source: Source,
    error: Option<Error>,
}

impl RecorderInner {
    fn run(inner: Arc<Mutex<Self>>, stop: Arc<AtomicBool>, socket: UdpSocket) {
        let mut buffer = [0; u16::MAX as usize];
        while !stop.load(Ordering::Relaxed) {
            match socket.recv_from(&mut buffer) {
                Ok((bytes_read, socket_addr)) => {
                    let mut guard = inner.lock().unwrap();
                    let query = &buffer[..bytes_read];
                    let response = match guard.handle_query(query) {
                        Ok(response) => response,
                        Err(error) => {
                            error!(%error, "error handling query");
                            guard.error = Some(error);
                            break;
                        }
                    };
                    if let Err(error) = socket.send_to(&response, socket_addr) {
                        error!(%error, "error sending response");
                        guard.error = Some(error.into());
                        break;
                    }
                }
                Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(error) => {
                    error!(%error, "error receiving datagram");
                    inner.lock().unwrap().error = Some(error.into());
                    break;
                }
            }
        }
        debug!("stopping proxy server");
    }

    fn handle_query(&mut self, query: &[u8]) -> Result<Vec<u8>, Error> {
        if query.len() < 2 {
            return Err(Error::InvalidMessage);
        }
        match &mut self.source {
            Source::Upstream {
                remote_addr,
                socket,
                transactions,
            } => {
                socket.send_to(query, *remote_addr)?;
                let start = Instant::now();
                let mut buffer = [0; u16::MAX as usize];
                while start.elapsed() < DNS_TIMEOUT {
                    match socket.recv_from(&mut buffer) {
                        Ok((bytes_read, _)) => {
                            if bytes_read < 2 {
                                return Err(Error::InvalidMessage);
                            } else if buffer[..2] == query[..2] {
                                let response = &buffer[..bytes_read];
                                transactions.push((query.to_vec(), response.to_vec()));
                                return Ok(response.to_vec());
                            }
                        }
                        Err(err)
                            if matches!(
                                err.kind(),
                                ErrorKind::WouldBlock | ErrorKind::TimedOut
                            ) => {}
                        Err(err) => return Err(err.into()),
                    }
                }
                Err(Error::NoResponse)
            }
            Source::Replay(recording) => {
                for transaction in recording.transactions.iter() {
                    if query[2..] == transaction.query_hex[2..] {
                        let mut response = transaction.response_hex.clone();
                        response[..2].copy_from_slice(&query[..2]);
                        return Ok(response);
                    }
                }
                Err(Error::NoMatch)
            }
        }
    }
}

enum Source {
    Upstream {
        remote_addr: SocketAddr,
        socket: UdpSocket,
        transactions: Vec<(Vec<u8>, Vec<u8>)>,
    },
    Replay(Recording),
}

#[derive(Debug, Serialize, Deserialize)]
struct Recording {
    protocol: String,
    remote_address: SocketAddr,
    transactions: Vec<Transaction>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Transaction {
    #[serde(with = "hex::serde")]
    query_hex: Vec<u8>,

    query_dissected: Option<Vec<String>>,

    #[serde(with = "hex::serde")]
    response_hex: Vec<u8>,

    response_dissected: Option<Vec<String>>,
}

/// Errors produced by the DNS recorder server.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// JSON serialization/deserialization error.
    #[error("json error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    /// Network thread panicked.
    #[error("network thread panicked")]
    Panic,

    /// Invalid DNS message received.
    #[error("invalid DNS message")]
    InvalidMessage,

    /// Recording file does not exist.
    #[error("no recording file was found, try re-running with DNS_RECORDER=record")]
    NoFile,

    /// Received a query that did not match any recorded transaction.
    #[error("no matching query in recording, try re-running with DNS_RECORDER=record")]
    NoMatch,

    /// Timed out waiting for a response from the remote server.
    #[error("no response from remote server")]
    NoResponse,

    /// Child process failed.
    #[error("child process returned a failed exit status")]
    ChildProcesssFailed,

    /// Invalid UTF-8.
    #[error("{0}")]
    Utf8(#[from] FromUtf8Error),
}

fn is_recording() -> bool {
    let res = env::var("DNS_RECORDER");
    match res {
        Ok(value) if &value == "record" => true,
        Ok(_) => panic!("expected DNS_RECORDER=record"),
        Err(VarError::NotPresent) => false,
        Err(e) => panic!("{e}"),
    }
}

pub(crate) fn dissect(message: &[u8]) -> Option<Vec<String>> {
    static WARNED: AtomicBool = AtomicBool::new(false);

    match try_dissect(message) {
        Ok(lines) => Some(lines),
        Err(error) => {
            if !WARNED.fetch_or(true, Ordering::SeqCst) {
                warn!(%error, "could not dissect message, check if text2pcap and tshark are installed");
            }
            None
        }
    }
}

fn try_dissect(message: &[u8]) -> Result<Vec<String>, Error> {
    let hex_temp_file = NamedTempFile::new().unwrap();
    let mut writer = BufWriter::new(hex_temp_file.as_file());
    for byte in message {
        writer.write_fmt(format_args!("{byte:02x} ")).unwrap();
    }
    writer.flush().unwrap();
    drop(writer);
    let hex_temp_file_path = hex_temp_file.into_temp_path();

    let pcapng_temp_file_path = NamedTempFile::new().unwrap().into_temp_path();

    let status = Command::new("text2pcap")
        .args([
            // no offsets in hex dump (only one packet)
            "-o",
            "none",
            // set the special encapsulation type to allow dissecting application-layer data
            "-E",
            "wireshark-upper-pdu",
            // specify the Wireshark dissector to be used
            "-P",
            "dns",
        ])
        .arg(&hex_temp_file_path)
        .arg(&pcapng_temp_file_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(Error::ChildProcesssFailed);
    }

    hex_temp_file_path.close().unwrap();

    let output = Command::new("tshark")
        .args([
            // show all details for DNS, and summary details for the encapsulation layer
            "-O", "dns",
        ])
        .arg(
            // read capture from a file
            "-r",
        )
        .arg(&pcapng_temp_file_path)
        .output()?;

    pcapng_temp_file_path.close().unwrap();

    let stdout = String::from_utf8(output.stdout)?;
    Ok(stdout.lines().map(|line| line.to_owned()).collect())
}

/// Receive timeout used when listening on the mock server.
const RECV_TIMEOUT: Duration = Duration::from_millis(100);
/// Timeout used when making DNS requests to internet servers.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        net::{Ipv4Addr, UdpSocket},
        thread,
        time::Duration,
    };

    use serde_json::Value;
    use tempfile::TempDir;

    use super::UdpDnsRecorder;

    #[test]
    fn test_udp_recorder() {
        static QUERY_MESSAGE_1: &[u8] = &[0x01, 0x02, 0x03, 0x04];
        static RESPONSE_MESSAGE_1: &[u8] = &[0x01, 0x02, 0x05, 0x06];
        static QUERY_MESSAGE_2: &[u8] = &[0xfe, 0xff, 0x03, 0x04];
        static RESPONSE_MESSAGE_2: &[u8] = &[0xfe, 0xff, 0x05, 0x06];

        // Start a server for the mock to sit in front of, which will send exactly one response and
        // shut down.
        let server_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        server_socket
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        server_socket
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut buffer = [0u8; u16::MAX as usize];
            let (bytes_read, src_addr) = server_socket.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..bytes_read], QUERY_MESSAGE_1);
            server_socket.send_to(RESPONSE_MESSAGE_1, src_addr).unwrap();
        });

        // Set up an instance as if DNS_RECORDER=record were set.
        let temp_dir = TempDir::new().unwrap();
        let filename = temp_dir.path().join("recording.json");
        let recorder_1 = UdpDnsRecorder::with_record(server_addr, filename.clone(), true).unwrap();

        // Send a request and check the response.
        let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        client_socket
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        client_socket
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        client_socket
            .send_to(QUERY_MESSAGE_1, recorder_1.local_address())
            .unwrap();
        let mut buffer = [0u8; u16::MAX as usize];
        let (bytes_read, _) = client_socket.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..bytes_read], RESPONSE_MESSAGE_1);

        // The server thread should have stopped by now.
        handle.join().unwrap();

        // Finalize the recording, and check the file that was produced.
        recorder_1.stop().unwrap();
        let value = serde_json::from_reader::<_, Value>(File::open(&filename).unwrap()).unwrap();
        let top_level_object = value.as_object().unwrap();
        assert_eq!(
            top_level_object.get("protocol").unwrap().as_str().unwrap(),
            "UDP"
        );
        assert_eq!(
            top_level_object
                .get("remote_address")
                .unwrap()
                .as_str()
                .unwrap(),
            server_addr.to_string()
        );
        let transactions = top_level_object
            .get("transactions")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(transactions.len(), 1);
        let transaction = transactions.first().unwrap().as_object().unwrap();
        assert_eq!(
            transaction.get("query_hex").unwrap().as_str().unwrap(),
            "00000304"
        );
        assert_eq!(
            transaction.get("response_hex").unwrap().as_str().unwrap(),
            "00000506"
        );

        // Start a new instance that plays back the recording.
        let recorder_2 = UdpDnsRecorder::with_record(server_addr, filename.clone(), false).unwrap();

        // Send another request and check the response.
        let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        client_socket
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        client_socket
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        client_socket
            .send_to(QUERY_MESSAGE_1, recorder_2.local_address())
            .unwrap();
        let mut buffer = [0u8; u16::MAX as usize];
        let (bytes_read, _) = client_socket.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..bytes_read], RESPONSE_MESSAGE_1);

        // Repeat with an equivalent query, but with a different message ID.
        let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        client_socket
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        client_socket
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        client_socket
            .send_to(QUERY_MESSAGE_2, recorder_2.local_address())
            .unwrap();
        let mut buffer = [0u8; u16::MAX as usize];
        let (bytes_read, _) = client_socket.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..bytes_read], RESPONSE_MESSAGE_2);

        recorder_2.stop().unwrap();
    }
}
