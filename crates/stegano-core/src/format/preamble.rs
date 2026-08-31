//! The 24-byte preamble, SPEC_CORE_V2 §3.1.
//!
//! ```text
//! offset  size  field
//!      0     2  magic = 0x5348
//!      2     1  version = 0x02
//!      3     1  flags: bit0 stealth, bit1 detached signature, bit2-3 mission
//!      4    16  salt
//!     20     2  payload_bits, big endian
//!     22     2  preamble_crc, CRC-16/CCITT over bytes 0..=21
//! ```
//!
//! `payload_bits` is the field the decoder was missing. Without it a carrier
//! reads every substitutable position it can find, so on any cover larger than
//! its payload the unused positions arrive as trailing zero bytes and parsing
//! rejects the result. The decoder now reads exactly the bits that were written.

use crate::crypto::keytree::SALT_LEN;
use crate::error::{Result, SteganoError};
use crate::format::crc::crc16_ccitt;

/// Format signature, ASCII "SH", big endian.
pub const MAGIC: u16 = 0x5348;

/// The version this build writes. It reads v1 documents as well (§8).
pub const VERSION_V2: u8 = 0x02;

/// Preamble size in bytes.
pub const PREAMBLE_LEN: usize = 24;

/// Preamble size in substitutable positions.
pub const PREAMBLE_BITS: usize = PREAMBLE_LEN * 8;

const OFFSET_MAGIC: usize = 0;
const OFFSET_VERSION: usize = 2;
const OFFSET_FLAGS: usize = 3;
const OFFSET_SALT: usize = 4;
const OFFSET_PAYLOAD_BITS: usize = 20;
const OFFSET_CRC: usize = 22;

/// Which mission the document was produced for, SPEC_CORE_V2 §5.3.
///
/// Carried in flag bits 2 and 3. Density is tuned per mission, so a reader
/// that has to judge a document needs to know which optimum it was built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mission {
    /// Minimise statistical evidence.
    Conceal,
    /// Survive redistribution, stay unobtrusive.
    Sign,
    /// Redundancy and excerpt survival dominate.
    Mark,
}

impl Mission {
    fn to_bits(self) -> u8 {
        match self {
            Mission::Conceal => 0,
            Mission::Sign => 1,
            Mission::Mark => 2,
        }
    }

    fn from_bits(bits: u8) -> Result<Self> {
        match bits {
            0 => Ok(Mission::Conceal),
            1 => Ok(Mission::Sign),
            2 => Ok(Mission::Mark),
            other => Err(SteganoError::DecodingFailed {
                method: "preamble".into(),
                reason: format!("mission field holds reserved value {other}"),
            }),
        }
    }
}

/// The flags byte at offset 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags {
    /// Stealth mode: no preamble is written, the salt derives from the cover.
    pub stealth: bool,
    /// The authorship signature travels beside the document, not inside it.
    pub detached_signature: bool,
    /// Mission this document was tuned for.
    pub mission: Mission,
}

impl Flags {
    /// Flags for a plain concealment document.
    pub fn conceal() -> Self {
        Self {
            stealth: false,
            detached_signature: false,
            mission: Mission::Conceal,
        }
    }

    pub fn to_byte(self) -> u8 {
        let mut byte = 0u8;
        if self.stealth {
            byte |= 0b0000_0001;
        }
        if self.detached_signature {
            byte |= 0b0000_0010;
        }
        byte |= self.mission.to_bits() << 2;
        byte
    }

    /// Parse the flags byte.
    ///
    /// Reserved bits 4 to 7 must be zero. A reader that quietly ignored them
    /// would be reading a document it does not actually understand, which is
    /// the silent degradation invariant 2 forbids.
    pub fn from_byte(byte: u8) -> Result<Self> {
        if byte & 0b1111_0000 != 0 {
            return Err(SteganoError::DecodingFailed {
                method: "preamble".into(),
                reason: format!("reserved flag bits set: 0x{byte:02X}"),
            });
        }
        Ok(Self {
            stealth: byte & 0b0000_0001 != 0,
            detached_signature: byte & 0b0000_0010 != 0,
            mission: Mission::from_bits((byte >> 2) & 0b11)?,
        })
    }
}

/// The parsed 24-byte preamble.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preamble {
    pub version: u8,
    pub flags: Flags,
    pub salt: [u8; SALT_LEN],
    /// Length of the payload region in substitutable positions.
    pub payload_bits: u16,
}

impl Preamble {
    /// Build a v2 preamble.
    pub fn new(flags: Flags, salt: [u8; SALT_LEN], payload_bits: u16) -> Self {
        Self {
            version: VERSION_V2,
            flags,
            salt,
            payload_bits,
        }
    }

    /// Serialise to the 24 bytes of §3.1, checksum included.
    pub fn to_bytes(&self) -> [u8; PREAMBLE_LEN] {
        let mut out = [0u8; PREAMBLE_LEN];
        out[OFFSET_MAGIC..OFFSET_MAGIC + 2].copy_from_slice(&MAGIC.to_be_bytes());
        out[OFFSET_VERSION] = self.version;
        out[OFFSET_FLAGS] = self.flags.to_byte();
        out[OFFSET_SALT..OFFSET_SALT + SALT_LEN].copy_from_slice(&self.salt);
        out[OFFSET_PAYLOAD_BITS..OFFSET_PAYLOAD_BITS + 2]
            .copy_from_slice(&self.payload_bits.to_be_bytes());
        let crc = crc16_ccitt(&out[..OFFSET_CRC]);
        out[OFFSET_CRC..OFFSET_CRC + 2].copy_from_slice(&crc.to_be_bytes());
        out
    }

    /// Parse 24 bytes, verifying magic, checksum and version.
    ///
    /// Every rejection names its reason. Scanners that probe many candidate
    /// offsets call this and discard the errors; a decoder that expected a
    /// preamble propagates them.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < PREAMBLE_LEN {
            return Err(SteganoError::DecodingFailed {
                method: "preamble".into(),
                reason: format!(
                    "need {PREAMBLE_LEN} bytes, received {received}",
                    received = bytes.len()
                ),
            });
        }

        let magic = u16::from_be_bytes([bytes[OFFSET_MAGIC], bytes[OFFSET_MAGIC + 1]]);
        if magic != MAGIC {
            return Err(SteganoError::DecodingFailed {
                method: "preamble".into(),
                reason: format!("magic mismatch: expected 0x{MAGIC:04X}, read 0x{magic:04X}"),
            });
        }

        let stored_crc = u16::from_be_bytes([bytes[OFFSET_CRC], bytes[OFFSET_CRC + 1]]);
        let computed_crc = crc16_ccitt(&bytes[..OFFSET_CRC]);
        if stored_crc != computed_crc {
            return Err(SteganoError::DecodingFailed {
                method: "preamble".into(),
                reason: format!(
                    "checksum mismatch: stored 0x{stored_crc:04X}, computed 0x{computed_crc:04X}"
                ),
            });
        }

        let version = bytes[OFFSET_VERSION];
        if version != VERSION_V2 {
            return Err(SteganoError::DecodingFailed {
                method: "preamble".into(),
                reason: format!("unsupported preamble version 0x{version:02X}"),
            });
        }

        let flags = Flags::from_byte(bytes[OFFSET_FLAGS])?;

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[OFFSET_SALT..OFFSET_SALT + SALT_LEN]);

        let payload_bits = u16::from_be_bytes([
            bytes[OFFSET_PAYLOAD_BITS],
            bytes[OFFSET_PAYLOAD_BITS + 1],
        ]);

        Ok(Self {
            version,
            flags,
            salt,
            payload_bits,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Preamble {
        Preamble::new(
            Flags {
                stealth: false,
                detached_signature: true,
                mission: Mission::Mark,
            },
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFF,
            ],
            584,
        )
    }

    #[test]
    fn the_layout_matches_the_specification_table() {
        let bytes = sample().to_bytes();

        assert_eq!(bytes.len(), 24);
        assert_eq!(&bytes[0..2], &[0x53, 0x48], "magic at offset 0");
        assert_eq!(bytes[2], 0x02, "version at offset 2");
        assert_eq!(bytes[3], 0b0000_1010, "flags at offset 3");
        assert_eq!(&bytes[4..20], &sample().salt, "salt at offset 4");
        assert_eq!(&bytes[20..22], &584u16.to_be_bytes(), "payload_bits at 20");
        assert_eq!(
            u16::from_be_bytes([bytes[22], bytes[23]]),
            crc16_ccitt(&bytes[..22]),
            "checksum at offset 22 covers bytes 0 to 21"
        );
    }

    #[test]
    fn round_trips_through_bytes() {
        let original = sample();
        let parsed = Preamble::parse(&original.to_bytes()).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn payload_bits_survives_the_round_trip_at_the_extremes() {
        for bits in [0u16, 1, 8, 584, 1648, u16::MAX] {
            let preamble = Preamble::new(Flags::conceal(), [0u8; SALT_LEN], bits);
            let parsed = Preamble::parse(&preamble.to_bytes()).unwrap();
            assert_eq!(parsed.payload_bits, bits);
        }
    }

    #[test]
    fn every_mission_round_trips() {
        for mission in [Mission::Conceal, Mission::Sign, Mission::Mark] {
            let flags = Flags {
                stealth: true,
                detached_signature: false,
                mission,
            };
            let parsed = Flags::from_byte(flags.to_byte()).unwrap();
            assert_eq!(parsed, flags);
        }
    }

    #[test]
    fn reserved_mission_value_is_named_not_ignored() {
        // Mission bits 2-3 set to 0b11, which no mission claims.
        match Flags::from_byte(0b0000_1100) {
            Err(SteganoError::DecodingFailed { method, reason }) => {
                assert_eq!(method, "preamble");
                assert!(reason.contains("mission"), "reason was: {reason}");
            }
            other => panic!("expected a named rejection, got {other:?}"),
        }
    }

    #[test]
    fn reserved_flag_bits_are_named_not_ignored() {
        match Flags::from_byte(0b0001_0000) {
            Err(SteganoError::DecodingFailed { reason, .. }) => {
                assert!(reason.contains("reserved"), "reason was: {reason}");
            }
            other => panic!("expected a named rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_corrupted_byte_fails_the_checksum() {
        let mut bytes = sample().to_bytes();
        bytes[10] ^= 0x01;
        match Preamble::parse(&bytes) {
            Err(SteganoError::DecodingFailed { reason, .. }) => {
                assert!(reason.contains("checksum"), "reason was: {reason}");
            }
            other => panic!("expected a checksum rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_corrupted_payload_bits_field_fails_the_checksum() {
        // The regression guard for the defect: the length field must not be
        // silently readable after corruption.
        let mut bytes = sample().to_bytes();
        bytes[20] ^= 0xFF;
        assert!(Preamble::parse(&bytes).is_err());
    }

    #[test]
    fn foreign_bytes_are_rejected_on_magic() {
        match Preamble::parse(&[0u8; PREAMBLE_LEN]) {
            Err(SteganoError::DecodingFailed { reason, .. }) => {
                assert!(reason.contains("magic"), "reason was: {reason}");
            }
            other => panic!("expected a magic rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_short_buffer_is_refused_by_length() {
        assert!(Preamble::parse(&[0x53, 0x48]).is_err());
    }

    #[test]
    fn an_unknown_version_is_refused() {
        let mut bytes = sample().to_bytes();
        bytes[2] = 0x09;
        let crc = crc16_ccitt(&bytes[..22]);
        bytes[22..24].copy_from_slice(&crc.to_be_bytes());
        match Preamble::parse(&bytes) {
            Err(SteganoError::DecodingFailed { reason, .. }) => {
                assert!(reason.contains("version"), "reason was: {reason}");
            }
            other => panic!("expected a version rejection, got {other:?}"),
        }
    }
}
