//! The light frame, SPEC_CORE_V2 §3.2.
//!
//! The heavy frame (`frame.rs`) writes the 24-byte preamble twice, with resync
//! markers between payload slots, for recovery from a partly damaged document.
//! That robustness costs at least 48 bytes plus markers before a single payload
//! byte, which makes hiding a small secret in a short cover impractical, and it
//! penalises the multi-carrier composition that is the tool's primary way to
//! carry text in little cover.
//!
//! The light frame is the default for that primary path. It writes a single
//! minimal header and the payload contiguously, no second replica and no
//! markers. The salt (16 bytes, for the crypto key tree) is carried only when a
//! cipher is used, so plain text pays an 8-byte header and an encrypted payload a
//! 24-byte one. The heavy frame stays available for work that needs its recovery
//! guarantees; the reader tells the two apart by the version byte and never
//! guesses (invariant 2).
//!
//! ```text
//! offset  size  field
//!      0     2  magic = 0x5348
//!      2     1  version = 0x03 (plain) or 0x04 (a salt follows)
//!      3     1  flags: bit0 stealth, bit1 detached signature, bit2-3 mission
//!      4     2  payload_bits, big endian
//!    [ 6    16  salt, present only when version == 0x04 ]
//!    C..C+2     header_crc, CRC-16/CCITT over every header byte before it
//!    then   ..  payload
//! ```

use crate::crypto::keytree::SALT_LEN;
use crate::error::{Result, SteganoError};
use crate::format::crc::crc16_ccitt;
use crate::format::frame::{bits_to_bytes, bytes_to_bits};
use crate::format::preamble::{Flags, MAGIC};

/// Light frame carrying no salt: a plain (unencrypted) payload.
pub const VERSION_LIGHT_PLAIN: u8 = 0x03;
/// Light frame carrying a 16-byte salt: an encrypted payload whose key tree
/// needs it at read time.
pub const VERSION_LIGHT_SEALED: u8 = 0x04;

const OFFSET_MAGIC: usize = 0;
const OFFSET_VERSION: usize = 2;
const OFFSET_FLAGS: usize = 3;
const OFFSET_PAYLOAD_BITS: usize = 4;
const OFFSET_SALT: usize = 6;

/// Header length in bytes for a plain light frame (no salt).
pub const HEADER_LEN_PLAIN: usize = 8;
/// Header length in bytes for a sealed light frame (with salt).
pub const HEADER_LEN_SEALED: usize = HEADER_LEN_PLAIN + SALT_LEN;

/// A parsed light frame: its flags, the salt when one was carried, and the
/// payload exactly as long as the header declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightContents {
    pub flags: Flags,
    pub salt: Option<[u8; SALT_LEN]>,
    pub payload: Vec<u8>,
}

/// The positions (bits) a light frame occupies for a payload of `payload_len`
/// bytes, with or without a salt. The single anchor a carrier that creates its
/// own positions sizes its span against.
pub fn frame_bits(payload_len: usize, has_salt: bool) -> usize {
    let header = if has_salt { HEADER_LEN_SEALED } else { HEADER_LEN_PLAIN };
    (header + payload_len) * 8
}

/// The payload capacity in whole bytes a cover offering `positions` substitutable
/// positions holds under the light frame, its header deducted. The figure encode
/// actually accepts, so a capacity report and the engine agree.
pub fn payload_capacity_bytes(positions: usize, has_salt: bool) -> usize {
    let header = if has_salt { HEADER_LEN_SEALED } else { HEADER_LEN_PLAIN };
    (positions / 8).saturating_sub(header)
}

/// Build a light frame as a bit stream (one byte per bit, MSB first), the same
/// shape the carriers write. The salt is included exactly when it is `Some`.
///
/// Refuses an empty payload, and a payload whose bit length does not fit the
/// 16-bit length field, by name rather than truncating (invariant 2).
pub fn build_light(flags: Flags, salt: Option<[u8; SALT_LEN]>, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.is_empty() {
        return Err(SteganoError::InvalidInput(
            "light frame: refusing to build an empty payload".into(),
        ));
    }
    let payload_bits = payload.len() * 8;
    if payload_bits > u16::MAX as usize {
        return Err(SteganoError::CapacityExceeded {
            needed: payload_bits,
            available: u16::MAX as usize,
        });
    }

    let header_len = if salt.is_some() { HEADER_LEN_SEALED } else { HEADER_LEN_PLAIN };
    let mut bytes = Vec::with_capacity(header_len + payload.len());
    bytes.extend_from_slice(&MAGIC.to_be_bytes());
    bytes.push(if salt.is_some() { VERSION_LIGHT_SEALED } else { VERSION_LIGHT_PLAIN });
    bytes.push(flags.to_byte());
    bytes.extend_from_slice(&(payload_bits as u16).to_be_bytes());
    if let Some(salt) = salt {
        bytes.extend_from_slice(&salt);
    }
    // CRC over every header byte written so far, then the payload after it.
    let crc = crc16_ccitt(&bytes);
    bytes.extend_from_slice(&crc.to_be_bytes());
    bytes.extend_from_slice(payload);

    Ok(bytes_to_bits(&bytes))
}

/// Read a light frame from a bit stream. Validates the magic, the version, the
/// header checksum and the declared length; every failure names itself. Trailing
/// positions past the declared payload (a carrier reads more than were written)
/// are ignored, which is exactly the length field the pre-format path lacked.
pub fn read_light(bits: &[u8]) -> Result<LightContents> {
    let bytes = bits_to_bytes(bits);
    if bytes.len() < HEADER_LEN_PLAIN {
        return Err(named("a light frame is shorter than its minimum header"));
    }
    if u16::from_be_bytes([bytes[OFFSET_MAGIC], bytes[OFFSET_MAGIC + 1]]) != MAGIC {
        return Err(named("the light frame magic does not match"));
    }
    let version = bytes[OFFSET_VERSION];
    let has_salt = match version {
        VERSION_LIGHT_PLAIN => false,
        VERSION_LIGHT_SEALED => true,
        other => return Err(named(&format!("not a light frame version: 0x{other:02X}"))),
    };
    let flags = Flags::from_byte(bytes[OFFSET_FLAGS])?;
    let payload_bits =
        u16::from_be_bytes([bytes[OFFSET_PAYLOAD_BITS], bytes[OFFSET_PAYLOAD_BITS + 1]]) as usize;

    let (salt, crc_offset) = if has_salt {
        if bytes.len() < HEADER_LEN_SEALED {
            return Err(named("a sealed light frame is shorter than its header"));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[OFFSET_SALT..OFFSET_SALT + SALT_LEN]);
        (Some(salt), OFFSET_SALT + SALT_LEN)
    } else {
        (None, OFFSET_PAYLOAD_BITS + 2)
    };

    let stored_crc = u16::from_be_bytes([bytes[crc_offset], bytes[crc_offset + 1]]);
    if crc16_ccitt(&bytes[..crc_offset]) != stored_crc {
        return Err(named("the light frame header checksum failed"));
    }

    if payload_bits % 8 != 0 {
        return Err(named("the light frame payload length is not a whole number of bytes"));
    }
    let payload_start = crc_offset + 2;
    let payload_len = payload_bits / 8;
    if bytes.len() < payload_start + payload_len {
        return Err(named("the light frame declares more payload than the document holds"));
    }
    let payload = bytes[payload_start..payload_start + payload_len].to_vec();

    Ok(LightContents { flags, salt, payload })
}

/// Peek the version byte of a candidate frame without parsing it, so the decode
/// path can send a document to the heavy or the light reader. `None` when the
/// stream is too short or the magic does not match.
pub fn peek_version(bits: &[u8]) -> Option<u8> {
    let bytes = bits_to_bytes(bits);
    if bytes.len() < OFFSET_VERSION + 1 {
        return None;
    }
    if u16::from_be_bytes([bytes[OFFSET_MAGIC], bytes[OFFSET_MAGIC + 1]]) != MAGIC {
        return None;
    }
    Some(bytes[OFFSET_VERSION])
}

/// Scan a bit stream for the first whole light frame at any bit offset.
///
/// The normal reader takes the frame at the start of the stream. A saturated
/// channel (SPEC_SATURATE) carries the frame repeated, and an excerpt of such a
/// document begins part way through the stream, so its first frame is not at
/// offset zero and can be bit-shifted. This walks every bit offset, and where the
/// magic matches there it validates a whole frame through `read_light` (header
/// checksum and declared length), returning the first that holds. `None` when no
/// whole frame survives anywhere in the stream.
pub fn scan_light(bits: &[u8]) -> Option<LightContents> {
    if bits.len() < HEADER_LEN_PLAIN * 8 {
        return None;
    }
    let magic = bytes_to_bits(&MAGIC.to_be_bytes());
    let last = bits.len() - magic.len();
    let mut offset = 0;
    while offset <= last {
        if bits[offset..offset + magic.len()] == magic[..] {
            if let Ok(contents) = read_light(&bits[offset..]) {
                return Some(contents);
            }
        }
        offset += 1;
    }
    None
}

fn named(reason: &str) -> SteganoError {
    SteganoError::DecodingFailed {
        method: "light frame".into(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_salt() -> [u8; SALT_LEN] {
        let mut salt = [0u8; SALT_LEN];
        for (i, b) in salt.iter_mut().enumerate() {
            *b = i as u8;
        }
        salt
    }

    #[test]
    fn a_plain_frame_round_trips_with_an_eight_byte_header() {
        let payload = b"the meeting is at dawn";
        let bits = build_light(Flags::conceal(), None, payload).unwrap();
        // 8-byte header + payload, no replica, no markers.
        assert_eq!(bits.len(), (HEADER_LEN_PLAIN + payload.len()) * 8);
        let read = read_light(&bits).unwrap();
        assert_eq!(read.payload, payload);
        assert_eq!(read.salt, None);
        assert_eq!(read.flags, Flags::conceal());
    }

    #[test]
    fn a_sealed_frame_carries_the_salt_and_round_trips() {
        let payload = b"encrypted bytes here";
        let bits = build_light(Flags::conceal(), Some(a_salt()), payload).unwrap();
        assert_eq!(bits.len(), (HEADER_LEN_SEALED + payload.len()) * 8);
        let read = read_light(&bits).unwrap();
        assert_eq!(read.payload, payload);
        assert_eq!(read.salt, Some(a_salt()));
    }

    #[test]
    fn trailing_positions_past_the_payload_are_ignored() {
        // A carrier that creates its own positions can hand back more bits than
        // were written; the declared length trims them, which the pre-format path
        // could not do.
        let payload = b"exact";
        let mut bits = build_light(Flags::conceal(), None, payload).unwrap();
        bits.extend(std::iter::repeat(0u8).take(200));
        let read = read_light(&bits).unwrap();
        assert_eq!(read.payload, payload);
    }

    #[test]
    fn a_corrupt_header_is_refused_by_name() {
        let payload = b"data";
        let mut bits = build_light(Flags::conceal(), None, payload).unwrap();
        // Flip a bit inside the length field; the header CRC must catch it.
        bits[OFFSET_PAYLOAD_BITS * 8] ^= 1;
        let err = read_light(&bits).unwrap_err();
        assert!(matches!(err, SteganoError::DecodingFailed { .. }), "corrupt header refused");
    }

    #[test]
    fn a_wrong_magic_is_not_read_as_a_light_frame() {
        let bits = bytes_to_bits(&[0x00, 0x00, VERSION_LIGHT_PLAIN, 0, 0, 8, 0, 0]);
        assert!(read_light(&bits).is_err());
        assert_eq!(peek_version(&bits), None);
    }

    #[test]
    fn peek_reports_the_version_for_dispatch() {
        let plain = build_light(Flags::conceal(), None, b"x").unwrap();
        assert_eq!(peek_version(&plain), Some(VERSION_LIGHT_PLAIN));
        let sealed = build_light(Flags::conceal(), Some(a_salt()), b"x").unwrap();
        assert_eq!(peek_version(&sealed), Some(VERSION_LIGHT_SEALED));
    }

    #[test]
    fn an_empty_payload_is_refused() {
        assert!(build_light(Flags::conceal(), None, b"").is_err());
    }
}
