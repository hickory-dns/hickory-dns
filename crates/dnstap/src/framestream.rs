//! Frame Streams protocol writer for DNSTAP transport.
//!
//! Implements the client (sender) side of the Frame Streams protocol.
//! See: <https://farsightsec.github.io/fstrm/>

use std::io;

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The content type used for DNSTAP Frame Streams.
pub(crate) const DNSTAP_CONTENT_TYPE: &[u8] = b"protobuf:dnstap.Dnstap";

/// Control frame types.
const CONTROL_ACCEPT: u32 = 0x01;
const CONTROL_START: u32 = 0x02;
const CONTROL_STOP: u32 = 0x03;
const CONTROL_READY: u32 = 0x04;
const CONTROL_FINISH: u32 = 0x05;

/// Control field types.
const FIELD_CONTENT_TYPE: u32 = 0x01;

/// Upper bound on the size of a control frame payload.
///
/// Real control frames carry only a type and a few short fields; the cap keeps
/// a broken collector from triggering an unbounded allocation.
const MAX_CONTROL_LEN: u32 = 64 * 1024;

/// Build a control frame with the given control type and optional content type field.
fn build_control_frame(control_type: u32, include_content_type: bool) -> Vec<u8> {
    let mut buf = BytesMut::new();

    // Escape: 4 bytes of zero to indicate this is a control frame
    buf.put_u32(0);

    // We'll fill in the control frame length after building the payload
    let len_pos = buf.len();
    buf.put_u32(0); // placeholder

    // Control type
    buf.put_u32(control_type);

    if include_content_type {
        // Field type
        buf.put_u32(FIELD_CONTENT_TYPE);
        // Field length
        buf.put_u32(DNSTAP_CONTENT_TYPE.len() as u32);
        // Field value
        buf.put_slice(DNSTAP_CONTENT_TYPE);
    }

    // Fill in control frame length (everything after the length field)
    let control_len = (buf.len() - len_pos - 4) as u32;
    let mut len_slice = &mut buf[len_pos..len_pos + 4];
    len_slice.put_u32(control_len);

    buf.to_vec()
}

/// Build a data frame (length-prefixed payload).
pub(crate) fn build_data_frame(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Read a control frame from the stream.
/// Returns the control type and the raw payload following it.
async fn read_control_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<(u32, Vec<u8>)> {
    // Read escape (must be 0)
    let escape = reader.read_u32().await?;
    if escape != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected control frame escape (0), got {escape}"),
        ));
    }

    // Read control frame length
    let control_len = reader.read_u32().await?;
    if control_len < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control frame too short",
        ));
    }
    if control_len > MAX_CONTROL_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("control frame too large ({control_len} bytes)"),
        ));
    }

    // Read the control frame payload
    let mut payload = vec![0u8; control_len as usize];
    reader.read_exact(&mut payload).await?;

    // Parse control type
    let mut buf = &payload[..];
    let control_type = buf.get_u32();

    Ok((control_type, payload))
}

/// Find the content type field in a control frame payload, if present.
fn find_content_type(payload: &[u8]) -> Option<&[u8]> {
    let mut buf = &payload[4..];
    while buf.len() >= 8 {
        let field_type = buf.get_u32();
        let field_len = buf.get_u32() as usize;
        if field_len > buf.len() {
            return None;
        }
        let (value, rest) = buf.split_at(field_len);
        if field_type == FIELD_CONTENT_TYPE {
            return Some(value);
        }
        buf = rest;
    }
    None
}

/// Perform the Frame Streams handshake as a client (sender).
///
/// Protocol:
/// 1. Client sends READY frame (with content type)
/// 2. Server sends ACCEPT frame
/// 3. Client sends START frame
pub(crate) async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> io::Result<()> {
    // Send READY control frame
    let ready = build_control_frame(CONTROL_READY, true);
    stream.write_all(&ready).await?;
    stream.flush().await?;

    // Read ACCEPT control frame
    let (control_type, payload) = read_control_frame(stream).await?;
    if control_type != CONTROL_ACCEPT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected ACCEPT ({CONTROL_ACCEPT}), got {control_type}"),
        ));
    }

    // The collector should echo our content type in the ACCEPT frame.
    if let Some(content_type) = find_content_type(&payload) {
        if content_type != DNSTAP_CONTENT_TYPE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "collector rejected content type {:?}, accepted {:?}",
                    String::from_utf8_lossy(DNSTAP_CONTENT_TYPE),
                    String::from_utf8_lossy(content_type),
                ),
            ));
        }
    }

    // Send START control frame
    let start = build_control_frame(CONTROL_START, true);
    stream.write_all(&start).await?;
    stream.flush().await?;

    Ok(())
}

/// Send a STOP control frame and wait for FINISH.
pub(crate) async fn shutdown<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> io::Result<()> {
    // Send STOP control frame
    let stop = build_control_frame(CONTROL_STOP, false);
    stream.write_all(&stop).await?;
    stream.flush().await?;

    // Try to read FINISH, but don't fail if connection closes
    match read_control_frame(stream).await {
        Ok((CONTROL_FINISH, _)) => Ok(()),
        Ok((control_type, _)) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected FINISH ({CONTROL_FINISH}), got {control_type}"),
        )),
        // Connection may be closed by server before FINISH
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_handshake() {
        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            // Server reads READY
            let (control_type, _) = read_control_frame(&mut server).await.unwrap();
            assert_eq!(control_type, CONTROL_READY);

            // Server sends ACCEPT
            let accept = build_control_frame(CONTROL_ACCEPT, true);
            server.write_all(&accept).await.unwrap();
            server.flush().await.unwrap();

            // Server reads START
            let (control_type, _) = read_control_frame(&mut server).await.unwrap();
            assert_eq!(control_type, CONTROL_START);

            server
        });

        handshake(&mut client).await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_data_frame() {
        let payload = b"hello world";
        let frame = build_data_frame(payload);
        assert_eq!(&frame[..4], &(payload.len() as u32).to_be_bytes());
        assert_eq!(&frame[4..], payload);
    }

    #[tokio::test]
    async fn test_shutdown() {
        let (mut client, mut server) = duplex(4096);

        let server_task = tokio::spawn(async move {
            // Server reads STOP
            let (control_type, _) = read_control_frame(&mut server).await.unwrap();
            assert_eq!(control_type, CONTROL_STOP);

            // Server sends FINISH
            let finish = build_control_frame(CONTROL_FINISH, false);
            server.write_all(&finish).await.unwrap();
            server.flush().await.unwrap();
        });

        shutdown(&mut client).await.unwrap();
        server_task.await.unwrap();
    }
}
