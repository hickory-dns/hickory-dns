//! Frame Streams protocol codec for DNSTAP transport.
//!
//! Implements the sender side of the Frame Streams protocol as a
//! [`tokio_util::codec`]; a `Framed` stream over the connection handles
//! buffering and partial frame reads.
//! See: <https://farsightsec.github.io/fstrm/>

use std::io;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::client::{DnstapEvent, EncoderConfig};
use crate::dnstap_message::{DnstapEventParams, build_query_into, build_response_into};

/// The content type used for DNSTAP Frame Streams.
pub(crate) const DNSTAP_CONTENT_TYPE: &[u8] = b"protobuf:dnstap.Dnstap";

/// Control frame types.
pub(crate) const CONTROL_ACCEPT: u32 = 0x01;
pub(crate) const CONTROL_START: u32 = 0x02;
pub(crate) const CONTROL_STOP: u32 = 0x03;
pub(crate) const CONTROL_READY: u32 = 0x04;
pub(crate) const CONTROL_FINISH: u32 = 0x05;

/// Control field types.
const FIELD_CONTENT_TYPE: u32 = 0x01;

/// Upper bound on the size of a control frame.
///
/// Real control frames carry only a type and a few short fields; the cap keeps
/// a broken collector from triggering an unbounded allocation.
const MAX_CONTROL_LEN: u32 = 64 * 1024;

/// Upper bound on the size of a data frame.
///
/// A collector should never send data frames to a sender; the cap bounds the
/// allocation a broken collector could trigger.
const MAX_DATA_LEN: u32 = 1024 * 1024;

/// A frame read from or written to a Frame Streams connection.
#[derive(Debug)]
pub(crate) enum FrameStreamItem {
    /// A data frame; the bytes are one DNSTAP protobuf message.
    Data(Bytes),
    /// A DNSTAP event to encode as a data frame at write time.
    ///
    /// Encoding happens here rather than at the emit site so the protobuf
    /// bytes land directly in the sink's write buffer with no intermediate
    /// Vec per event.
    Event(DnstapEvent),
    /// A control frame, with the value of its content-type field if present.
    Control {
        control_type: u32,
        content_type: Option<Bytes>,
    },
}

impl FrameStreamItem {
    /// A control frame carrying the DNSTAP content type.
    pub(crate) fn typed_control(control_type: u32) -> Self {
        Self::Control {
            control_type,
            content_type: Some(Bytes::from_static(DNSTAP_CONTENT_TYPE)),
        }
    }

    /// A control frame without fields.
    pub(crate) fn bare_control(control_type: u32) -> Self {
        Self::Control {
            control_type,
            content_type: None,
        }
    }
}

/// Encoder and decoder for Frame Streams frames.
///
/// Carries the identity/version values DNSTAP data frames embed, so data
/// frames can be encoded directly into the sink's write buffer.
#[derive(Debug, Default)]
pub(crate) struct FrameStreamCodec {
    encoder: EncoderConfig,
}

impl FrameStreamCodec {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_encoder(encoder: EncoderConfig) -> Self {
        Self { encoder }
    }
}

impl Decoder for FrameStreamCodec {
    type Item = FrameStreamItem;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<FrameStreamItem>> {
        // Every frame opens with a 32-bit big-endian word: zero marks a
        // control frame, any other value is a data frame length.
        if src.len() < 4 {
            return Ok(None);
        }
        let mut header = &src[..4];
        let word = header.get_u32();

        if word == 0 {
            // Control frame: escape (4), control length (4), then the payload,
            // which starts with the control type.
            if src.len() < 8 {
                return Ok(None);
            }
            let mut length = &src[4..8];
            let control_len = length.get_u32();
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
            let total = 8 + control_len as usize;
            if src.len() < total {
                src.reserve(total - src.len());
                return Ok(None);
            }
            let frame = src.split_to(total);
            let mut body = &frame[8..];
            let control_type = body.get_u32();
            let content_type = find_content_type(body).map(Bytes::copy_from_slice);
            Ok(Some(FrameStreamItem::Control {
                control_type,
                content_type,
            }))
        } else if word > MAX_DATA_LEN {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("data frame too large ({word} bytes)"),
            ))
        } else {
            let len = word as usize;
            let total = 4 + len;
            if src.len() < total {
                src.reserve(total - src.len());
                return Ok(None);
            }
            src.advance(4);
            Ok(Some(FrameStreamItem::Data(src.split_to(len).freeze())))
        }
    }
}

/// Find the content-type field in a control frame payload's fields, if present.
fn find_content_type(mut fields: &[u8]) -> Option<&[u8]> {
    while fields.len() >= 8 {
        let field_type = fields.get_u32();
        let field_len = fields.get_u32() as usize;
        if field_len > fields.len() {
            return None;
        }
        let (value, rest) = fields.split_at(field_len);
        if field_type == FIELD_CONTENT_TYPE {
            return Some(value);
        }
        fields = rest;
    }
    None
}

impl Encoder<FrameStreamItem> for FrameStreamCodec {
    type Error = io::Error;

    fn encode(&mut self, item: FrameStreamItem, dst: &mut BytesMut) -> io::Result<()> {
        match item {
            FrameStreamItem::Data(message) => {
                // A zero-length data frame would be read as a control frame.
                if message.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "data frame payload is empty",
                    ));
                }
                dst.reserve(4 + message.len());
                dst.put_u32(message.len() as u32);
                dst.put(message);
            }
            FrameStreamItem::Event(event) => self.encode_event(event, dst)?,
            FrameStreamItem::Control {
                control_type,
                content_type,
            } => {
                // Type (4) plus the optional content-type field (8 + value).
                let body_len: u32 = 4 + match &content_type {
                    Some(content_type) => 8 + content_type.len() as u32,
                    None => 0,
                };
                dst.reserve(8 + body_len as usize);
                dst.put_u32(0);
                dst.put_u32(body_len);
                dst.put_u32(control_type);
                if let Some(content_type) = content_type {
                    dst.put_u32(FIELD_CONTENT_TYPE);
                    dst.put_u32(content_type.len() as u32);
                    dst.put(content_type);
                }
            }
        }
        Ok(())
    }
}

impl FrameStreamCodec {
    /// Encode a DNSTAP event as a data frame appended to `dst`.
    ///
    /// The protobuf bytes are written straight into `dst`; only the payload
    /// fields inside the protobuf struct copy their bytes.
    fn encode_event(&mut self, event: DnstapEvent, dst: &mut BytesMut) -> io::Result<()> {
        // The length prefix must precede the protobuf bytes, so write a
        // placeholder, encode the message, then patch the real length. This
        // assembles each message exactly once; sizing up front would need a
        // second assemble (and a second payload copy) per event.
        match event {
            DnstapEvent::Query {
                message_type,
                src_addr,
                server_addr,
                transport,
                query_bytes,
                query_zone,
                query_time,
            } => {
                let params = DnstapEventParams {
                    identity: &self.encoder.identity,
                    version: &self.encoder.version,
                    src_addr,
                    server_addr,
                    transport,
                    query_time,
                    response_time: None,
                    message_type: &message_type,
                    query_zone: query_zone.as_deref(),
                };
                if query_bytes.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "data frame payload is empty",
                    ));
                }
                let start = dst.len();
                dst.put_u32(0);
                build_query_into(&params, &query_bytes, dst);
                patch_len(dst, start);
                Ok(())
            }
            DnstapEvent::Response {
                message_type,
                src_addr,
                server_addr,
                transport,
                query_time,
                response_time,
                query_zone,
                response_bytes,
            } => {
                let params = DnstapEventParams {
                    identity: &self.encoder.identity,
                    version: &self.encoder.version,
                    src_addr,
                    server_addr,
                    transport,
                    query_time,
                    response_time: Some(response_time),
                    message_type: &message_type,
                    query_zone: query_zone.as_deref(),
                };
                if response_bytes.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "data frame payload is empty",
                    ));
                }
                let start = dst.len();
                dst.put_u32(0);
                build_response_into(&params, &response_bytes, dst);
                patch_len(dst, start);
                Ok(())
            }
        }
    }
}

/// Overwrite the frame length at `start` with the bytes written since.
fn patch_len(dst: &mut BytesMut, start: usize) {
    let proto_len = (dst.len() - start - 4) as u32;
    dst[start..start + 4].copy_from_slice(&proto_len.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnstap_message::build_query;

    #[test]
    fn test_encode_typed_control_frame() {
        let mut dst = BytesMut::new();
        FrameStreamCodec::new()
            .encode(FrameStreamItem::typed_control(CONTROL_READY), &mut dst)
            .unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&0u32.to_be_bytes()); // escape
        expected.extend_from_slice(&(4 + 8 + DNSTAP_CONTENT_TYPE.len() as u32).to_be_bytes());
        expected.extend_from_slice(&CONTROL_READY.to_be_bytes());
        expected.extend_from_slice(&FIELD_CONTENT_TYPE.to_be_bytes());
        expected.extend_from_slice(&(DNSTAP_CONTENT_TYPE.len() as u32).to_be_bytes());
        expected.extend_from_slice(DNSTAP_CONTENT_TYPE);
        assert_eq!(dst.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_control_frame_roundtrip() {
        let mut codec = FrameStreamCodec::new();
        let mut buf = BytesMut::new();
        codec
            .encode(FrameStreamItem::typed_control(CONTROL_ACCEPT), &mut buf)
            .unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        match decoded {
            FrameStreamItem::Control {
                control_type,
                content_type,
            } => {
                assert_eq!(control_type, CONTROL_ACCEPT);
                assert_eq!(content_type.as_deref(), Some(DNSTAP_CONTENT_TYPE));
            }
            other => panic!("expected a control frame, got {other:?}"),
        }
    }

    #[test]
    fn test_bare_control_frame_roundtrip() {
        let mut codec = FrameStreamCodec::new();
        let mut buf = BytesMut::new();
        codec
            .encode(FrameStreamItem::bare_control(CONTROL_STOP), &mut buf)
            .unwrap();
        assert_eq!(&buf[..4], &[0u8; 4]); // escape
        assert_eq!(&buf[4..8], &4u32.to_be_bytes()); // control length: type only
        assert_eq!(&buf[8..12], &CONTROL_STOP.to_be_bytes());

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(
            decoded,
            FrameStreamItem::Control {
                control_type: CONTROL_STOP,
                content_type: None,
            }
        ));
    }

    #[test]
    fn test_data_frame_roundtrip() {
        let mut codec = FrameStreamCodec::new();
        let mut buf = BytesMut::new();
        codec
            .encode(
                FrameStreamItem::Data(Bytes::from_static(b"payload")),
                &mut buf,
            )
            .unwrap();
        assert_eq!(&buf[..4], &(7u32).to_be_bytes());
        assert_eq!(&buf[4..], b"payload");

        let mut partial = BytesMut::new();
        partial.extend_from_slice(&buf[..2]);
        assert!(codec.decode(&mut partial).unwrap().is_none());
        partial.extend_from_slice(&buf[2..]);
        let decoded = codec.decode(&mut partial).unwrap().unwrap();
        match decoded {
            FrameStreamItem::Data(payload) => assert_eq!(payload.as_ref(), b"payload"),
            other => panic!("expected a data frame, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_rejects_oversized_frames() {
        let mut codec = FrameStreamCodec::new();

        let mut control = BytesMut::new();
        control.put_u32(0);
        control.put_u32(MAX_CONTROL_LEN + 1);
        assert!(codec.decode(&mut control).is_err());

        let mut data = BytesMut::new();
        data.put_u32(MAX_DATA_LEN + 1);
        assert!(codec.decode(&mut data).is_err());
    }

    #[test]
    fn test_decode_rejects_short_control_frame() {
        let mut codec = FrameStreamCodec::new();
        let mut buf = BytesMut::new();
        buf.put_u32(0);
        buf.put_u32(0);
        assert!(codec.decode(&mut buf).is_err());
    }

    /// The codec's Event encode must produce the same wire bytes the old
    /// build_*_vec plus Data-frame path produced.
    #[test]
    fn test_event_encode_matches_data_path() {
        let event = DnstapEvent::Query {
            message_type: crate::client::DnstapMessageType::Auth,
            src_addr: Some("192.168.1.1:12345".parse().unwrap()),
            server_addr: Some("192.0.2.53:53".parse().unwrap()),
            transport: Some(crate::DnsTransport::Udp),
            query_bytes: b"\x00\x01\x01\x00".to_vec(),
            query_zone: Some(b"\x07example\x03com\x00".to_vec()),
            query_time: (1_000_000, 500),
        };

        // Old path: owned protobuf Vec wrapped in Data.
        let params = DnstapEventParams {
            identity: &None,
            version: &None,
            src_addr: Some("192.168.1.1:12345".parse().unwrap()),
            server_addr: Some("192.0.2.53:53".parse().unwrap()),
            transport: Some(crate::DnsTransport::Udp),
            query_time: (1_000_000, 500),
            response_time: Some((2_000_000, 500)),
            message_type: &crate::client::DnstapMessageType::Auth,
            query_zone: Some(b"\x07example\x03com\x00"),
        };
        let proto = build_query(&params, event_bytes(&event));

        let mut direct = BytesMut::new();
        FrameStreamCodec::new()
            .encode(FrameStreamItem::Data(proto.clone().into()), &mut direct)
            .unwrap();

        let mut via_event = BytesMut::new();
        FrameStreamCodec::new()
            .encode(FrameStreamItem::Event(event), &mut via_event)
            .unwrap();

        assert_eq!(via_event.as_ref(), direct.as_ref());
        // And the payload matches the plain protobuf bytes.
        assert_eq!(&via_event[4..], proto.as_slice());
    }

    fn event_bytes(event: &DnstapEvent) -> &[u8] {
        match event {
            DnstapEvent::Query { query_bytes, .. } => query_bytes,
            DnstapEvent::Response { response_bytes, .. } => response_bytes,
        }
    }
}
