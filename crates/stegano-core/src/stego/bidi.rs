//! Bidirectional steganography — hides data using Unicode bidi control characters.
//!
//! Uses LTR/RTL marks and embeddings to encode bits:
//! - Bit 0: LEFT-TO-RIGHT MARK (U+200E)
//! - Bit 1: RIGHT-TO-LEFT MARK (U+200F)
//! - Delimiter: POP DIRECTIONAL FORMATTING (U+202C)
//!
//! These characters are invisible in most renderers but affect text direction.
//! They survive most copy/paste operations and many normalizations.
//!
//! Encoding: payload bytes → bidi bit sequence → inserted after each visible char.
//!
//! Threat model:
//! - Survives: NFC/NFD normalization, most copy/paste
//! - Vulnerable: NFKC/NFKD normalization, bidi-stripping sanitizers
//! - Detection: any bidi control in pure-LTR text is suspicious

use crate::error::{Result, SteganoError};
use crate::format::frame::bytes_to_bits;
use crate::format::PositionChannel;
use crate::stego::recognition;
use crate::traits::StegoMethod;

/// Bit 0: LEFT-TO-RIGHT MARK
const ZERO: char = '\u{200E}';
/// Bit 1: RIGHT-TO-LEFT MARK
const ONE: char = '\u{200F}';
/// Byte delimiter: POP DIRECTIONAL FORMATTING
const DELIM: char = '\u{202C}';

/// Codepoint alphabet of this carrier (SPEC_CORE_V2 §6.5).
const CHANNEL: [char; 3] = [ZERO, ONE, DELIM];

/// Bidirectional steganography method.
pub struct Bidi;

impl Bidi {
    pub fn new() -> Self {
        Self
    }

    /// The channel sequence for a bit stream: one character per bit, a
    /// delimiter every eight of them.
    ///
    /// This is the same sequence `bytes_to_bidi` built byte by byte, expressed
    /// over bits so a frame whose length is not a whole number of bytes can
    /// still be written. Placement itself is untouched.
    fn bits_to_bidi(bits: &[u8]) -> String {
        let mut result = String::with_capacity(bits.len() + bits.len() / 8);
        for (i, &bit) in bits.iter().enumerate() {
            if i > 0 && i % 8 == 0 {
                result.push(DELIM);
            }
            result.push(if bit == 1 { ONE } else { ZERO });
        }
        result
    }

    /// Convert payload bytes to bidi character sequence.
    fn bytes_to_bidi(data: &[u8]) -> String {
        Self::bits_to_bidi(&bytes_to_bits(data))
    }

    /// The bit-placement routine of this carrier, and the only one.
    ///
    /// One bidi character at each word-boundary slot, in document order, with
    /// the remainder appended at the end (backlog F22). Where each character
    /// lands moved; the sequence of bits, delimiters included, keeps its value
    /// and its order, which the golden vectors prove.
    ///
    /// `encode` and `write_positions` both funnel through here. The framing
    /// layer decides which bits arrive; it never decides where they land
    /// (invariant 4, SPEC_CORE_V2 §5).
    fn place_sequence(cover: &str, sequence: &str) -> String {
        let bidi_chars: Vec<char> = sequence.chars().collect();
        crate::stego::placement::place_at_word_boundaries(cover, &bidi_chars)
    }

    /// The bit-extraction routine of this carrier, and the only one.
    ///
    /// Delimiters carry no payload, so they are skipped rather than counted.
    fn extract_bits(stego: &str) -> Vec<u8> {
        stego
            .chars()
            .filter_map(|c| match c {
                ZERO => Some(0),
                ONE => Some(1),
                _ => None,
            })
            .collect()
    }

    /// Rebuild the bytes a bidi sequence carries.
    ///
    /// This carrier inserts exactly the bits it is handed and a frame is
    /// always a whole number of bytes, so a sequence that ends mid-byte is
    /// never something this carrier wrote: it is damage, or characters that
    /// belong to the cover. The reader used to pad the remainder with zeros,
    /// which invents bits nobody wrote (backlog F13b).
    fn bidi_to_bytes(bidi: &str) -> Result<Vec<u8>> {
        if bidi.is_empty() {
            return Err(SteganoError::DecodingFailed {
                method: "bidi".into(),
                reason: "no bidi content found".into(),
            });
        }

        let carried = bidi.chars().filter(|c| matches!(*c, ZERO | ONE)).count();
        if carried == 0 {
            return Err(SteganoError::DecodingFailed {
                method: "bidi".into(),
                reason: "no bidi content found".into(),
            });
        }
        if carried % 8 != 0 {
            return Err(recognition::channel_ends_mid_byte("bidi", carried));
        }

        let mut bytes = Vec::new();
        let mut current_byte: u8 = 0;
        let mut bit_count: u8 = 0;

        for c in bidi.chars() {
            match c {
                ZERO => {
                    current_byte = (current_byte << 1) | 0;
                    bit_count += 1;
                }
                ONE => {
                    current_byte = (current_byte << 1) | 1;
                    bit_count += 1;
                }
                DELIM => {
                    if bit_count == 8 {
                        bytes.push(current_byte);
                        current_byte = 0;
                        bit_count = 0;
                    }
                    // Ignore extra delimiters
                }
                _ => {} // Ignore non-bidi chars
            }

            if bit_count == 8 {
                bytes.push(current_byte);
                current_byte = 0;
                bit_count = 0;
            }
        }

        if bit_count > 0 {
            // Unreachable: the whole-byte check above ran first. Raising here
            // rather than padding keeps that fact from decaying into invented
            // bits if the guard is ever moved.
            return Err(recognition::channel_ends_mid_byte("bidi", carried));
        }

        if bytes.is_empty() {
            return Err(SteganoError::DecodingFailed {
                method: "bidi".into(),
                reason: "no data decoded from bidi characters".into(),
            });
        }

        Ok(bytes)
    }
}

/// The position-addressed view of the same placement routine, SPEC_CORE_V2 §3.
///
/// `StegoMethod` speaks bytes, which cannot express a frame whose bit count is
/// not a whole number of bytes. This speaks positions.
impl PositionChannel for Bidi {
    /// Payload bits this cover offers, which is what `capacity()` reports:
    /// the delimiter cost is already deducted there.
    fn positions(&self, text: &str) -> usize {
        self.capacity(text)
    }

    fn read_positions(&self, text: &str) -> Vec<u8> {
        Self::extract_bits(text)
    }

    /// A cover already holding characters of this carrier's alphabet is
    /// refused by name.
    ///
    /// Reading returns every bidi control in document order, so pre-existing
    /// ones would be read as payload bits and shift everything after them.
    /// Refusing is the only honest answer.
    fn check_writable(&self, cover: &str) -> Result<()> {
        let occupied = cover
            .chars()
            .filter(|c| matches!(*c, ZERO | ONE | DELIM))
            .count();
        if occupied == 0 {
            return Ok(());
        }
        Err(recognition::cover_already_occupied("bidi", occupied))
    }

    fn write_positions(&self, cover: &str, bits: &[u8]) -> Result<String> {
        self.check_writable(cover)?;

        let available = self.positions(cover);
        if bits.len() > available {
            return Err(SteganoError::CapacityExceeded {
                needed: bits.len(),
                available,
            });
        }
        Ok(Self::place_sequence(cover, &Self::bits_to_bidi(bits)))
    }
}

impl StegoMethod for Bidi {
    fn id(&self) -> &str {
        "bidi"
    }

    fn name(&self) -> &str {
        "Bidirectional Controls"
    }

    fn encode(&self, cover: &str, payload: &[u8]) -> Result<String> {
        // Backlog F26: the byte path used to skip this, so a cover already
        // holding this carrier's alphabet was refused by one guard on one path
        // and a different guard on the other, giving two explanations for one
        // situation (backlog F20).
        self.check_writable(cover)?;

        // Both sides of this comparison are payload bits, which is what
        // `capacity()` reports. It used to add the delimiters to the left side
        // only, so the carrier refused loads it had just advertised as fitting
        // (backlog F13). The delimiter cost is accounted for inside
        // `capacity()`, where it belongs, and placement below is untouched.
        let needed = payload.len() * 8;
        let available = self.capacity(cover);

        if needed > available {
            return Err(SteganoError::CapacityExceeded { needed, available });
        }

        Ok(Self::place_sequence(cover, &Self::bytes_to_bidi(payload)))
    }

    fn decode(&self, stego: &str) -> Result<Vec<u8>> {
        // Extract only bidi control characters
        let bidi_content: String = stego
            .chars()
            .filter(|c| *c == ZERO || *c == ONE || *c == DELIM)
            .collect();

        Self::bidi_to_bytes(&bidi_content)
    }

    /// Payload bits this cover holds, delimiters already deducted.
    ///
    /// One bidi character rides at each word-boundary slot, so the cover offers
    /// exactly `slots` of them (backlog F22). N payload bytes occupy 8N bits
    /// plus the N-1 delimiters between them, that is 9N-1 slots, so the cover
    /// holds `floor((slots + 1) / 9)` bytes. The figure is reported in payload
    /// bits because that is what callers budget in, and `encode()` holds itself
    /// to this exact number (backlog F13).
    ///
    /// Characters of this carrier's own alphabet that the cover arrived with are
    /// occupancy, not slots: the slot count is taken over the visible skeleton,
    /// so counting them never offers room that was already taken (backlog F13b).
    fn capacity(&self, cover: &str) -> usize {
        let slots = crate::stego::placement::boundary_slots(cover);
        if slots < 8 {
            return 0;
        }
        let bytes = (slots + 1) / 9;
        bytes * 8
    }

    fn detect(&self, text: &str) -> f64 {
        let bidi_count = text
            .chars()
            .filter(|c| *c == ZERO || *c == ONE || *c == DELIM)
            .count();

        if bidi_count == 0 {
            return 0.0;
        }

        let total = text.chars().count() as f64;
        let ratio = bidi_count as f64 / total;

        // Even a few bidi chars in normal text is suspicious
        (ratio * 50.0).min(1.0)
    }

    fn strip(&self, text: &str) -> String {
        text.chars()
            .filter(|c| *c != ZERO && *c != ONE && *c != DELIM
                && *c != '\u{202A}' && *c != '\u{202B}'
                && *c != '\u{202D}' && *c != '\u{202E}'
                && *c != '\u{2066}' && *c != '\u{2067}'
                && *c != '\u{2068}' && *c != '\u{2069}')
            .collect()
    }

    fn channel(&self) -> &'static [char] {
        &CHANNEL
    }
}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Attribution: the cover's own characters are not free slots ───

    /// Backlog F13b. `capacity()` counted every character of the cover,
    /// including the channel characters already sitting in it, so it offered
    /// slots that were already taken.
    #[test]
    fn capacity_does_not_count_channel_characters_the_cover_already_holds() {
        let bidi = Bidi::new();
        let plain = "x".repeat(25);
        let carrying = format!("{plain}{ZERO}");

        assert_eq!(
            bidi.capacity(&carrying),
            bidi.capacity(&plain),
            "a slot the cover already occupies is not a slot this carrier can write"
        );
    }

    /// A group that ends mid-byte is damage or somebody else's characters. The
    /// old reader padded it with zeros, which invents bits that were never
    /// written.
    #[test]
    fn decode_refuses_a_group_that_ends_mid_byte_rather_than_inventing_the_rest() {
        let bidi = Bidi::new();
        let message = bidi
            .decode(&format!("a{ZERO}b{ONE}c"))
            .expect_err("two bits are not a byte")
            .to_string();
        assert!(
            message.contains('2'),
            "the refusal must name what it found: {message}"
        );
    }

    /// Backlog F20 and F26. One situation, one refusal: the byte path and the
    /// position path must give the same answer in the same words when the
    /// cover already holds this carrier's alphabet.
    #[test]
    fn encode_and_the_position_path_refuse_an_occupied_cover_in_the_same_words() {
        let bidi = Bidi::new();
        let cover = format!("A cover text with room enough for a byte or two of payload{ZERO}");

        let via_bytes = bidi
            .encode(&cover, b"x")
            .expect_err("the cover already holds this carrier's alphabet")
            .to_string();
        let via_positions = bidi
            .write_positions(&cover, &[0u8; 8])
            .expect_err("the cover already holds this carrier's alphabet")
            .to_string();

        assert_eq!(via_bytes, via_positions);
    }

    #[test]
    fn channel_is_the_bidi_alphabet() {
        let bidi = Bidi::new();
        assert_eq!(bidi.channel(), &[ZERO, ONE, DELIM]);
    }

    #[test]
    fn the_byte_path_and_the_position_path_place_the_same_characters() {
        // Handing the carrier a byte payload and handing it the same bits
        // through the position channel must produce the same text. If these
        // ever diverge, the framing layer has grown a placement rule of its
        // own, which invariant 4 forbids.
        let bidi = Bidi::new();
        let cover = "A cover text long enough to take a payload of a few dozen bytes and then a good deal \
                     more besides it, because this carrier spends nine characters of cover on every \
                     byte it places and refuses anything beyond that";

        for payload in [b"x".as_slice(), b"two", b"a payload"] {
            let through_bytes = bidi.encode(cover, payload).unwrap();
            let through_bits = bidi.write_positions(cover, &bytes_to_bits(payload)).unwrap();
            assert_eq!(through_bytes, through_bits, "payload {payload:?}");

            let read_back = bidi.read_positions(&through_bits);
            assert_eq!(read_back, bytes_to_bits(payload));
        }
    }

    #[test]
    fn the_position_channel_refuses_what_the_byte_path_refuses() {
        let bidi = Bidi::new();
        let cover = "short cover";
        let oversized = vec![0u8; 64];

        assert!(matches!(
            bidi.encode(cover, &oversized),
            Err(SteganoError::CapacityExceeded { .. })
        ));
        assert!(matches!(
            bidi.write_positions(cover, &bytes_to_bits(&oversized)),
            Err(SteganoError::CapacityExceeded { .. })
        ));
    }

    #[test]
    fn a_cover_already_holding_the_alphabet_is_refused_by_name() {
        let bidi = Bidi::new();
        match bidi.check_writable("already\u{200E}carrying") {
            Err(SteganoError::EncodingFailed { method, reason }) => {
                assert_eq!(method, "bidi");
                assert!(reason.contains("alphabet"), "reason was: {reason}");
            }
            other => panic!("expected a named refusal, got {other:?}"),
        }
        assert!(bidi.check_writable("nothing here yet").is_ok());
    }

    #[test]
    fn roundtrip_ascii() {
        let bidi = Bidi::new();
        let cover = "This is a sufficiently long cover text for hiding some secret data in it easily today";
        let secret = b"Hi!";

        let stego = bidi.encode(cover, secret).unwrap();
        let decoded = bidi.decode(&stego).unwrap();
        assert_eq!(decoded, secret);
    }

    #[test]
    fn roundtrip_binary() {
        let bidi = Bidi::new();
        let cover = "A long enough cover text that can hold a decent amount of hidden binary payload data for testing";
        let secret: Vec<u8> = (0..4).collect();

        let stego = bidi.encode(cover, &secret).unwrap();
        let decoded = bidi.decode(&stego).unwrap();
        assert_eq!(decoded, secret);
    }

    #[test]
    fn visual_identity() {
        let bidi = Bidi::new();
        let cover = "This text looks completely normal and has nothing unusual about it at all";
        let stego = bidi.encode(cover, b"x").unwrap();

        // Stripped version should be identical to cover
        assert_eq!(bidi.strip(&stego), cover);
    }

    #[test]
    fn capacity_exceeded() {
        let bidi = Bidi::new();
        let cover = "short";
        let result = bidi.encode(cover, b"way too much data");
        assert!(result.is_err());
    }

    /// Backlog F13, remeasured for word-boundary placement (F22).
    /// `tests/corpus/en_short.txt` is 71 characters offering 22 word-boundary
    /// slots. Two bytes occupy 16 bits plus the one delimiter between them, 17
    /// slots, which fits; three bytes need 24 bits plus two delimiters, 26 slots,
    /// which the 22 do not hold. The carrier must report exactly what it will
    /// place, because that figure is the input to every pre-flight check.
    #[test]
    fn the_short_corpus_document_holds_exactly_what_it_reports() {
        let bidi = Bidi::new();
        let cover = include_str!("../../../../tests/corpus/en_short.txt");

        assert_eq!(cover.chars().count(), 71, "corpus document changed size");
        assert_eq!(bidi.capacity(cover), 16, "two bytes, in bits");

        let payload: Vec<u8> = (0..2u8).map(|i| 0xA0 ^ i).collect();
        let stego = bidi
            .encode(cover, &payload)
            .expect("the carrier must place what it reported");

        assert_eq!(bidi.decode(&stego).unwrap(), payload);
        assert_eq!(bidi.strip(&stego), cover);

        let one_byte_more: Vec<u8> = (0..3u8).map(|i| 0xA0 ^ i).collect();
        assert!(
            bidi.encode(cover, &one_byte_more).is_err(),
            "one byte past the reported limit must be refused"
        );
    }

    /// The reported figure holds at every cover length, not only the one the
    /// backlog measured: place at exactly the limit, recover it, then refuse
    /// one byte more.
    #[test]
    fn reported_capacity_is_honoured_at_every_cover_length() {
        let bidi = Bidi::new();

        for len in 1..=200usize {
            let cover: String = "abcdefghij ".chars().cycle().take(len).collect();
            let limit = bidi.capacity(&cover) / 8;

            if limit == 0 {
                assert!(
                    bidi.encode(&cover, b"x").is_err(),
                    "cover of {len} chars reported no room and must refuse a byte"
                );
                continue;
            }

            let payload: Vec<u8> = (0..limit).map(|i| (i * 37 % 256) as u8).collect();
            let stego = bidi.encode(&cover, &payload).unwrap_or_else(|e| {
                panic!("cover of {len} chars reported {limit} bytes then refused them: {e}")
            });

            assert_eq!(
                bidi.decode(&stego).unwrap(),
                payload,
                "cover of {len} chars did not give back its full load"
            );
            assert_eq!(bidi.strip(&stego), cover, "cover of {len} chars");

            let over: Vec<u8> = (0..=limit).map(|i| (i * 37 % 256) as u8).collect();
            assert!(
                bidi.encode(&cover, &over).is_err(),
                "cover of {len} chars accepted {} bytes past its reported {limit}",
                over.len() - limit
            );
        }
    }

    #[test]
    fn detection_positive() {
        let bidi = Bidi::new();
        let cover = "This is a long enough cover text for encoding some hidden data inside it for testing purposes";
        let stego = bidi.encode(cover, b"Hi").unwrap();

        let confidence = bidi.detect(&stego);
        assert!(confidence > 0.0, "should detect bidi stego, got {confidence}");
    }

    #[test]
    fn detection_negative() {
        let bidi = Bidi::new();
        let confidence = bidi.detect("Normal English text with no hidden content.");
        assert_eq!(confidence, 0.0);
    }

    #[test]
    fn strip_cleans_text() {
        let bidi = Bidi::new();
        let text = "He\u{200E}ll\u{200F}o \u{202C}world";
        let clean = bidi.strip(text);
        assert_eq!(clean, "Hello world");
    }

    #[test]
    fn survives_nfc_normalization() {
        use unicode_normalization::UnicodeNormalization;

        let bidi = Bidi::new();
        let cover = "A sufficiently long cover text with enough room for hidden data to survive normalization tests";
        let stego = bidi.encode(cover, b"NFC").unwrap();

        // NFC normalization should NOT destroy bidi marks
        let normalized: String = stego.nfc().collect();
        let decoded = bidi.decode(&normalized).unwrap();
        assert_eq!(decoded, b"NFC");
    }
}
