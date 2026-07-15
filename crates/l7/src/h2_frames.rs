//! Shared raw HTTP/2 framing primitives for the frame-level engines.
//!
//! The high-level `h2` crate (used by [`crate::rapid_reset`]) only ever emits
//! complete, valid exchanges, so the primitives that abuse framing directly —
//! [`crate::h2_continuation`] and [`crate::h2_frame_flood`] — craft frames by
//! hand, std-only, exactly as `jinrai_l34` crafts packets. This module holds the
//! bytes they share: the connection preface, the frame type/flag constants, and
//! the frame encoder. No new dependency.

/// The HTTP/2 client connection preface (RFC 7540 §3.5) — the fixed 24-byte
/// string every h2 connection opens with, before any frames.
pub(crate) const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// HTTP/2 frame type bytes (RFC 7540 §6).
pub(crate) const TYPE_SETTINGS: u8 = 0x4;
pub(crate) const TYPE_PING: u8 = 0x6;
pub(crate) const TYPE_HEADERS: u8 = 0x1;
pub(crate) const TYPE_CONTINUATION: u8 = 0x9;
pub(crate) const TYPE_PRIORITY: u8 = 0x2;
pub(crate) const TYPE_WINDOW_UPDATE: u8 = 0x8;

/// No frame flag set. (`ACK` on SETTINGS/PING and `END_HEADERS`/`END_STREAM` on
/// HEADERS all live in the flags byte; the framing floods deliberately set none.)
pub(crate) const FLAG_NONE: u8 = 0x0;

/// Encode a 9-byte HTTP/2 frame header (RFC 7540 §4.1) followed by `payload`,
/// appending to `out`. `len` is taken from the payload; the 24-bit length field
/// caps at ~16 MiB, far above anything these engines send.
pub(crate) fn push_frame(out: &mut Vec<u8>, ty: u8, flags: u8, stream_id: u32, payload: &[u8]) {
    let len = payload.len() as u32;
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.push(ty);
    out.push(flags);
    // 31-bit stream id, reserved high bit 0.
    out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_frame_encodes_header_and_payload() {
        // 9-byte header: length(3) type(1) flags(1) stream(4), then payload.
        let mut out = Vec::new();
        push_frame(&mut out, TYPE_CONTINUATION, FLAG_NONE, 1, &[0xAA, 0xBB]);
        assert_eq!(&out[0..3], &[0, 0, 2], "24-bit length = 2");
        assert_eq!(out[3], 0x9, "type CONTINUATION");
        assert_eq!(out[4], 0x0, "no flags");
        assert_eq!(&out[5..9], &[0, 0, 0, 1], "stream id 1");
        assert_eq!(&out[9..], &[0xAA, 0xBB], "payload appended");
    }

    #[test]
    fn preface_is_the_fixed_24_bytes() {
        assert_eq!(PREFACE.len(), 24);
        assert!(PREFACE.starts_with(b"PRI * HTTP/2.0"));
    }
}
