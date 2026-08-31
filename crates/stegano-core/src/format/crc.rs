//! The two checksums the format uses: CRC-16/CCITT-FALSE for the preamble of
//! SPEC_CORE_V2 §3.1, and CRC-32/ISO-HDLC for the integrity step of §4.1.
//!
//! Implemented here rather than pulled in as a dependency: each polynomial is
//! four lines and the format must stay readable by the standalone decoder (§9).
//! Both are pinned to their published check vectors in the tests below, which
//! is the only thing that makes a hand-written CRC safe to keep.
//!
//! CRC-32 lived in `pipeline.rs` until backlog F21 moved it here. It is a
//! property of the format, not of the cascade that drives it.

const POLYNOMIAL: u16 = 0x1021;
const INITIAL: u16 = 0xFFFF;

/// CRC-32/ISO-HDLC reversed polynomial: 0x04C11DB7 bit reversed.
const POLYNOMIAL_32: u32 = 0xEDB8_8320;
/// CRC-32/ISO-HDLC initial value, also its final XOR.
const INITIAL_32: u32 = 0xFFFF_FFFF;

/// CRC-16/CCITT-FALSE over `data`.
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc = INITIAL;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ POLYNOMIAL
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// CRC-32/ISO-HDLC over `data`, the integrity step of SPEC_CORE_V2 §4.1.
///
/// Parameters: reversed polynomial 0xEDB88320, initial value 0xFFFFFFFF, input
/// and output reflected, final XOR 0xFFFFFFFF. Pinned to the standard check
/// vector 0xCBF43926 below.
///
/// A transform step that does not authenticate its own output carries this
/// checksum trailing its bytes, so every document has at least one exact
/// oracle even when no cipher was chosen (§7, level 2).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = INITIAL_32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (POLYNOMIAL_32 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_the_standard_check_vector() {
        // The check value published for CRC-32/ISO-HDLC.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn crc32_of_no_bytes_is_zero() {
        // Initial value XOR final XOR. Stated because the integrity step runs
        // over whatever the last transform produced, which may be nothing.
        assert_eq!(crc32(&[]), 0);
    }

    #[test]
    fn crc32_notices_a_single_flipped_bit() {
        let mut data = [0x02u8, 0x00, 0x11, 0x22, 0x33, 0x44];
        let before = crc32(&data);
        data[3] ^= 0x01;
        assert_ne!(crc32(&data), before);
    }

    #[test]
    fn crc32_does_not_absorb_leading_zeros() {
        // An envelope payload can legitimately begin with zero bytes, so the
        // two lengths must not score identically.
        assert_ne!(crc32(&[0x00, 0x01]), crc32(&[0x00, 0x00, 0x01]));
    }

    #[test]
    fn the_two_checksums_are_not_the_same_function_at_two_widths() {
        // A guard against someone widening the 16 bit routine and calling it
        // the 32 bit one: the polynomials and the reflection differ.
        assert_ne!(crc16_ccitt(b"123456789") as u32, crc32(b"123456789"));
    }

    #[test]
    fn matches_the_standard_check_vector() {
        // The check value published for CRC-16/CCITT-FALSE.
        assert_eq!(crc16_ccitt(b"123456789"), 0x29B1);
    }

    #[test]
    fn empty_input_returns_the_initial_value() {
        assert_eq!(crc16_ccitt(&[]), INITIAL);
    }

    #[test]
    fn a_single_flipped_bit_changes_the_checksum() {
        let mut data = [0x53u8, 0x48, 0x02, 0x00, 0x11, 0x22];
        let before = crc16_ccitt(&data);
        data[4] ^= 0x01;
        assert_ne!(crc16_ccitt(&data), before);
    }

    #[test]
    fn leading_zeros_are_not_absorbed() {
        // A CRC initialised to zero would score these identically. The
        // preamble's salt can legitimately begin with zero bytes, so this
        // property is load bearing rather than cosmetic.
        assert_ne!(crc16_ccitt(&[0x00, 0x01]), crc16_ccitt(&[0x00, 0x00, 0x01]));
    }
}
