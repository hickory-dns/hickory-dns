//! Minimal Frame Streams (fstrm) mock collector for DNSTAP tests and the
//! profiling example.
//!
//! Mirrors the framing and handshake that `DnstapClient` speaks, so both the
//! integration tests and the profiling driver exercise the same protocol
//! behavior. Deliberately decoding-free: payload frames are handed to the
//! caller untouched, so profiles stay isolated from any sink work.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Content type declared in ACCEPT frames by both sides.
pub const DNSTAP_CONTENT_TYPE: &[u8] = b"protobuf:dnstap.Dnstap";

pub const CONTROL_ACCEPT: u32 = 0x01;
pub const CONTROL_START: u32 = 0x02;
pub const CONTROL_STOP: u32 = 0x03;
pub const CONTROL_READY: u32 = 0x04;
pub const CONTROL_FINISH: u32 = 0x05;

/// Encode a control frame: escape (zero), payload length, payload. The payload
/// starts with the control type and optionally carries one content-type field.
pub fn build_control_frame(control_type: u32, include_content_type: bool) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&control_type.to_be_bytes());
    if include_content_type {
        payload.extend_from_slice(&1u32.to_be_bytes()); // CONTENT_TYPE field type
        payload.extend_from_slice(&(DNSTAP_CONTENT_TYPE.len() as u32).to_be_bytes());
        payload.extend_from_slice(DNSTAP_CONTENT_TYPE);
    }

    let mut buf = Vec::with_capacity(8 + payload.len());
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(&payload);
    buf
}

/// Perform the client-initiated handshake: assert the client's READY, reply
/// ACCEPT carrying the DNSTAP content type, then assert START.
pub async fn handshake<S>(stream: &mut S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (control_type, _) = read_control(stream).await;
    assert_eq!(control_type, CONTROL_READY, "expected READY");

    stream
        .write_all(&build_control_frame(CONTROL_ACCEPT, true))
        .await
        .unwrap();
    stream.flush().await.unwrap();

    let (control_type, _) = read_control(stream).await;
    assert_eq!(control_type, CONTROL_START, "expected START");
}

/// Read frames from an established connection until the client closes it.
///
/// A STOP control frame is answered with a bare FINISH; reading continues
/// until the stream ends. Payload frames go to `on_payload` as raw bytes.
pub async fn collect<S>(stream: &mut S, mut on_payload: impl FnMut(&[u8]))
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }

        while let Some(frame) = parse_frame(&mut buf) {
            match frame {
                Frame::Control { control_type } => {
                    if control_type == CONTROL_STOP {
                        stream
                            .write_all(&build_control_frame(CONTROL_FINISH, false))
                            .await
                            .unwrap();
                        stream.flush().await.unwrap();
                    }
                }
                Frame::Payload { frame_len } => {
                    on_payload(&buf[..frame_len]);
                    buf.drain(..frame_len);
                }
            }
        }
    }
}

enum Frame {
    Control {
        control_type: u32,
    },
    /// Full frame length, including the length prefix. The buffer is left
    /// undrained so the caller can hand out the payload before consuming it.
    Payload {
        frame_len: usize,
    },
}

/// Parse one frame from the front of `buf`; `None` while more bytes are needed.
fn parse_frame(buf: &mut Vec<u8>) -> Option<Frame> {
    if buf.len() < 4 {
        return None;
    }
    let header = u32::from_be_bytes(buf[..4].try_into().unwrap());
    if header == 0 {
        if buf.len() < 8 {
            return None;
        }
        let control_len = u32::from_be_bytes(buf[4..8].try_into().unwrap()) as usize;
        if control_len < 4 || buf.len() < 8 + control_len {
            return None;
        }
        let control_type = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        buf.drain(..8 + control_len);
        return Some(Frame::Control { control_type });
    }

    let frame_len = 4 + header as usize;
    if buf.len() < frame_len {
        return None;
    }
    Some(Frame::Payload { frame_len })
}

/// Read one control frame; panics on anything but a control frame escape.
async fn read_control<S>(stream: &mut S) -> (u32, Vec<u8>)
where
    S: AsyncRead + Unpin,
{
    let mut escape = [0u8; 4];
    stream.read_exact(&mut escape).await.unwrap();
    assert_eq!(
        u32::from_be_bytes(escape),
        0,
        "expected control frame escape"
    );

    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await.unwrap();
    let mut payload = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut payload).await.unwrap();

    let control_type = u32::from_be_bytes(payload[..4].try_into().unwrap());
    (control_type, payload)
}
