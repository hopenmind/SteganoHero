//! Whitespace Variation steganography — hides data using Unicode whitespace-like characters.
//!
//! Uses characters that are distinct from the zero-width set used by ZeroWidth:
//! - Bit 0: WORD JOINER (U+2060)
//! - Bit 1: ZERO WIDTH NO-BREAK SPACE / BOM (U+FEFF)
//! - Delimiter: INVISIBLE SEPARATOR (U+2063)
//!
//! These are semantically different from ZWSP/ZWNJ:
//! - U+2060 (Word Joiner): prevents line breaks
//! - U+FEFF (BOM/ZWNBSP): byte order mark / legacy no-break space
//! - U+2063 (Invisible Separator): mathematical separator
//!
//! This gives SteganoHero a third invisible-character channel, orthogonal to
//! zero-width (ZWSP/ZWNJ) and bidi (LRM/RLM). Stacking methods = defense in depth.
//!
//! Threat model:
//! - Survives: most copy/paste, NFC/NFD normalization
//! - Vulnerable: NFKC strips U+FEFF, aggressive Unicode sanitizers
//! - Detection: presence of U+2060/U+FEFF in normal text is unusual

use crate::error::{Result, SteganoError};
use crate::format::frame::bytes_to_bits;
use crate::format::PositionChannel;
use crate::stego::recognition;
use crate::traits::StegoMethod;

/// Bit 0: WORD JOINER
const ZERO: char = '\u{2060}';
/// Bit 1: ZERO WIDTH NO-BREAK SPACE (BOM)
const ONE: char = '\u{FEFF}';
/// Byte delimiter: INVISIBLE SEPARATOR
const DELIM: char = '\u{2063}';

/// Codepoint alphabet of this carrier (SPEC_CORE_V2 §6.5).
const CHANNEL: [char; 3] = [ZERO, ONE, DELIM];

/// Whitespace Variation steganography method.
pub struct WhitespaceVar;

impl WhitespaceVar {
    pub fn new() -> Self {
        Self
    }

    /// The channel sequence for a bit stream: one character per bit, a
    /// delimiter every eight of them.
    ///
    /// This is the same sequence `bytes_to_ws` built byte by byte, expressed
    /// over bits so a frame whose length is not a whole number of bytes can
    /// still be written. Placement itself is untouched.
    fn bits_to_ws(bits: &[u8]) -> String {
        let mut result = String::with_capacity(bits.len() + bits.len() / 8);
        for (i, &bit) in bits.iter().enumerate() {
            if i > 0 && i % 8 == 0 {
                result.push(DELIM);
            }
            result.push(if bit == 1 { ONE } else { ZERO });
        }
        result
    }

    fn bytes_to_ws(data: &[u8]) -> String {
        Self::bits_to_ws(&bytes_to_bits(data))
    }

    /// The bit-placement routine of this carrier, and the only one.
    ///
    /// One channel character at each word-boundary slot, in document order, with
    /// the remainder appended at the end (backlog F22). Where each character
    /// lands moved; the sequence of bits, delimiters included, keeps its value
    /// and its order, which the golden vectors prove.
    ///
    /// `encode` and `write_positions` both funnel through here. The framing
    /// layer decides which bits arrive; it never decides where they land
    /// (invariant 4, SPEC_CORE_V2 §5).
    fn place_sequence(cover: &str, sequence: &str) -> String {
        let ws_chars: Vec<char> = sequence.chars().collect();
        crate::stego::placement::place_at_word_boundaries(cover, &ws_chars)
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

    /// Rebuild the bytes a channel sequence carries.
    ///
    /// This carrier inserts exactly the bits it is handed and a frame is
    /// always a whole number of bytes, so a sequence that ends mid-byte is
    /// never something this carrier wrote: it is damage, or characters that
    /// belong to the cover. The reader used to pad the remainder with zeros,
    /// which invents bits nobody wrote and reported a one-byte secret in an
    /// untouched document (backlog F13b).
    fn ws_to_bytes(ws: &str) -> Result<Vec<u8>> {
        if ws.is_empty() {
            return Err(SteganoError::DecodingFailed {
                method: "whitespace_var".into(),
                reason: "no whitespace-variation content found".into(),
            });
        }

        let carried = ws.chars().filter(|c| matches!(*c, ZERO | ONE)).count();
        if carried == 0 {
            return Err(SteganoError::DecodingFailed {
                method: "whitespace_var".into(),
                reason: "no whitespace-variation content found".into(),
            });
        }
        if carried % 8 != 0 {
            return Err(recognition::channel_ends_mid_byte("whitespace_var", carried));
        }

        let mut bytes = Vec::new();
        let mut current_byte: u8 = 0;
        let mut bit_count: u8 = 0;

        for c in ws.chars() {
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
                }
                _ => {}
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
            return Err(recognition::channel_ends_mid_byte(
                "whitespace_var",
                carried,
            ));
        }

        if bytes.is_empty() {
            return Err(SteganoError::DecodingFailed {
                method: "whitespace_var".into(),
                reason: "no data decoded".into(),
            });
        }

        Ok(bytes)
    }
}

/// The position-addressed view of the same placement routine, SPEC_CORE_V2 §3.
///
/// `StegoMethod` speaks bytes, which cannot express a frame whose bit count is
/// not a whole number of bytes. This speaks positions.
impl PositionChannel for WhitespaceVar {
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
    /// Reading returns every channel character in document order, so
    /// pre-existing ones would be read as payload bits and shift everything
    /// after them. Refusing is the only honest answer.
    fn check_writable(&self, cover: &str) -> Result<()> {
        let occupied = cover
            .chars()
            .filter(|c| matches!(*c, ZERO | ONE | DELIM))
            .count();
        if occupied == 0 {
            return Ok(());
        }
        Err(recognition::cover_already_occupied("whitespace_var", occupied))
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
        Ok(Self::place_sequence(cover, &Self::bits_to_ws(bits)))
    }
}

impl StegoMethod for WhitespaceVar {
    fn id(&self) -> &str {
        "whitespace_var"
    }

    fn name(&self) -> &str {
        "Whitespace Variation"
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

        Ok(Self::place_sequence(cover, &Self::bytes_to_ws(payload)))
    }

    fn decode(&self, stego: &str) -> Result<Vec<u8>> {
        let ws_content: String = stego
            .chars()
            .filter(|c| *c == ZERO || *c == ONE || *c == DELIM)
            .collect();

        Self::ws_to_bytes(&ws_content)
    }

    /// Payload bits this cover holds, delimiters already deducted.
    ///
    /// One channel character rides at each word-boundary slot, so the cover
    /// offers exactly `slots` of them (backlog F22). N payload bytes occupy 8N
    /// bits plus the N-1 delimiters between them, that is 9N-1 slots, so the
    /// cover holds `floor((slots + 1) / 9)` bytes. The figure is reported in
    /// payload bits because that is what callers budget in, and `encode()`
    /// holds itself to this exact number (backlog F13).
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
        let ws_count = text
            .chars()
            .filter(|c| *c == ZERO || *c == ONE || *c == DELIM)
            .count();

        if ws_count == 0 {
            return 0.0;
        }

        let total = text.chars().count() as f64;
        let ratio = ws_count as f64 / total;

        (ratio * 50.0).min(1.0)
    }

    fn strip(&self, text: &str) -> String {
        text.chars()
            .filter(|c| *c != ZERO && *c != ONE && *c != DELIM
                && *c != '\u{2061}' // Function Application
                && *c != '\u{2062}' // Invisible Times
                && *c != '\u{2064}' // Invisible Plus
            )
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

    const ALREADY_CARRYING: &str = include_str!("../../../../tests/corpus/already_carrying.txt");

    // ─── Attribution: the cover's own characters are not free slots ───

    /// Backlog F13b. `capacity()` counted every character of the cover,
    /// including the channel characters already sitting in it, so it offered
    /// slots that were already taken.
    #[test]
    fn capacity_does_not_count_channel_characters_the_cover_already_holds() {
        let ws = WhitespaceVar::new();
        let plain = "x".repeat(25);
        let carrying = format!("{plain}{ZERO}");

        assert_eq!(
            ws.capacity(&carrying),
            ws.capacity(&plain),
            "a slot the cover already occupies is not a slot this carrier can write"
        );
    }

    /// The same figure, on the corpus document that arrives already holding
    /// this carrier's alphabet.
    #[test]
    fn the_document_that_arrives_carrying_offers_no_room_for_what_it_already_holds() {
        let ws = WhitespaceVar::new();
        let without: String = ALREADY_CARRYING
            .chars()
            .filter(|c| !matches!(*c, ZERO | ONE | DELIM))
            .collect();

        assert!(
            without.chars().count() < ALREADY_CARRYING.chars().count(),
            "this document is the one that arrives with a history"
        );
        assert_eq!(ws.capacity(ALREADY_CARRYING), ws.capacity(&without));
    }

    /// Backlog F13b. Two stray channel characters were read as payload and
    /// padded out into a whole byte, so an untouched document reported a
    /// one-byte secret that nobody wrote.
    #[test]
    fn a_cover_that_merely_holds_two_channel_characters_carries_no_payload() {
        assert!(
            WhitespaceVar::new().decode(ALREADY_CARRYING).is_err(),
            "stray channel characters are not a payload"
        );
    }

    /// A group that ends mid-byte is damage or somebody else's characters. The
    /// old reader padded it with zeros, which invents bits that were never
    /// written.
    #[test]
    fn decode_refuses_a_group_that_ends_mid_byte_rather_than_inventing_the_rest() {
        let ws = WhitespaceVar::new();
        let message = ws
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
        let ws = WhitespaceVar::new();
        let cover = format!("A cover text with room enough for a byte or two of payload{ZERO}");

        let via_bytes = ws
            .encode(&cover, b"x")
            .expect_err("the cover already holds this carrier's alphabet")
            .to_string();
        let via_positions = ws
            .write_positions(&cover, &[0u8; 8])
            .expect_err("the cover already holds this carrier's alphabet")
            .to_string();

        assert_eq!(via_bytes, via_positions);
    }

    #[test]
    fn channel_is_the_whitespace_alphabet() {
        let ws = WhitespaceVar::new();
        assert_eq!(ws.channel(), &[ZERO, ONE, DELIM]);
    }

    #[test]
    fn the_byte_path_and_the_position_path_place_the_same_characters() {
        // Handing the carrier a byte payload and handing it the same bits
        // through the position channel must produce the same text. If these
        // ever diverge, the framing layer has grown a placement rule of its
        // own, which invariant 4 forbids.
        let ws = WhitespaceVar::new();
        let cover = "A cover text long enough to take a payload of a few dozen bytes and then a good deal \
                     more besides it, because this carrier spends nine characters of cover on every \
                     byte it places and refuses anything beyond that";

        for payload in [b"x".as_slice(), b"two", b"a payload"] {
            let through_bytes = ws.encode(cover, payload).unwrap();
            let through_bits = ws.write_positions(cover, &bytes_to_bits(payload)).unwrap();
            assert_eq!(through_bytes, through_bits, "payload {payload:?}");

            let read_back = ws.read_positions(&through_bits);
            assert_eq!(read_back, bytes_to_bits(payload));
        }
    }

    #[test]
    fn the_position_channel_refuses_what_the_byte_path_refuses() {
        let ws = WhitespaceVar::new();
        let cover = "short cover";
        let oversized = vec![0u8; 64];

        assert!(matches!(
            ws.encode(cover, &oversized),
            Err(SteganoError::CapacityExceeded { .. })
        ));
        assert!(matches!(
            ws.write_positions(cover, &bytes_to_bits(&oversized)),
            Err(SteganoError::CapacityExceeded { .. })
        ));
    }

    #[test]
    fn a_cover_already_holding_the_alphabet_is_refused_by_name() {
        let ws = WhitespaceVar::new();
        match ws.check_writable("already\u{2060}carrying") {
            Err(SteganoError::EncodingFailed { method, reason }) => {
                assert_eq!(method, "whitespace_var");
                assert!(reason.contains("alphabet"), "reason was: {reason}");
            }
            other => panic!("expected a named refusal, got {other:?}"),
        }
        assert!(ws.check_writable("nothing here yet").is_ok());
    }

    #[test]
    fn roundtrip_ascii() {
        let ws = WhitespaceVar::new();
        let cover = "This is a sufficiently long cover text for hiding some secret data in it easily today";
        let secret = b"Hi!";

        let stego = ws.encode(cover, secret).unwrap();
        let decoded = ws.decode(&stego).unwrap();
        assert_eq!(decoded, secret);
    }

    #[test]
    fn roundtrip_binary() {
        let ws = WhitespaceVar::new();
        let cover = "A long enough cover text that can hold a decent amount of hidden binary payload data for testing";
        let secret: Vec<u8> = (0..4).collect();

        let stego = ws.encode(cover, &secret).unwrap();
        let decoded = ws.decode(&stego).unwrap();
        assert_eq!(decoded, secret);
    }

    #[test]
    fn visual_identity() {
        let ws = WhitespaceVar::new();
        let cover = "This text looks completely normal and has nothing unusual about it at all";
        let stego = ws.encode(cover, b"x").unwrap();

        assert_eq!(ws.strip(&stego), cover);
    }

    #[test]
    fn capacity_exceeded() {
        let ws = WhitespaceVar::new();
        let cover = "short";
        let result = ws.encode(cover, b"way too much data");
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
        let ws = WhitespaceVar::new();
        let cover = include_str!("../../../../tests/corpus/en_short.txt");

        assert_eq!(cover.chars().count(), 71, "corpus document changed size");
        assert_eq!(ws.capacity(cover), 16, "two bytes, in bits");

        let payload: Vec<u8> = (0..2u8).map(|i| 0xA0 ^ i).collect();
        let stego = ws
            .encode(cover, &payload)
            .expect("the carrier must place what it reported");

        assert_eq!(ws.decode(&stego).unwrap(), payload);
        assert_eq!(ws.strip(&stego), cover);

        let one_byte_more: Vec<u8> = (0..3u8).map(|i| 0xA0 ^ i).collect();
        assert!(
            ws.encode(cover, &one_byte_more).is_err(),
            "one byte past the reported limit must be refused"
        );
    }

    /// The reported figure holds at every cover length, not only the one the
    /// backlog measured: place at exactly the limit, recover it, then refuse
    /// one byte more.
    #[test]
    fn reported_capacity_is_honoured_at_every_cover_length() {
        let ws = WhitespaceVar::new();

        for len in 1..=200usize {
            let cover: String = "abcdefghij ".chars().cycle().take(len).collect();
            let limit = ws.capacity(&cover) / 8;

            if limit == 0 {
                assert!(
                    ws.encode(&cover, b"x").is_err(),
                    "cover of {len} chars reported no room and must refuse a byte"
                );
                continue;
            }

            let payload: Vec<u8> = (0..limit).map(|i| (i * 37 % 256) as u8).collect();
            let stego = ws.encode(&cover, &payload).unwrap_or_else(|e| {
                panic!("cover of {len} chars reported {limit} bytes then refused them: {e}")
            });

            assert_eq!(
                ws.decode(&stego).unwrap(),
                payload,
                "cover of {len} chars did not give back its full load"
            );
            assert_eq!(ws.strip(&stego), cover, "cover of {len} chars");

            let over: Vec<u8> = (0..=limit).map(|i| (i * 37 % 256) as u8).collect();
            assert!(
                ws.encode(&cover, &over).is_err(),
                "cover of {len} chars accepted {} bytes past its reported {limit}",
                over.len() - limit
            );
        }
    }

    #[test]
    fn detection_positive() {
        let ws = WhitespaceVar::new();
        let cover = "This is a long enough cover text for encoding some hidden data inside it for testing purposes";
        let stego = ws.encode(cover, b"Hi").unwrap();

        let confidence = ws.detect(&stego);
        assert!(confidence > 0.0, "should detect whitespace stego, got {confidence}");
    }

    #[test]
    fn detection_negative() {
        let ws = WhitespaceVar::new();
        let confidence = ws.detect("Normal English text with no hidden content.");
        assert_eq!(confidence, 0.0);
    }

    #[test]
    fn strip_cleans_text() {
        let ws = WhitespaceVar::new();
        let text = "He\u{2060}ll\u{FEFF}o \u{2063}world";
        let clean = ws.strip(text);
        assert_eq!(clean, "Hello world");
    }

    #[test]
    fn orthogonal_to_zero_width() {
        // Ensure whitespace_var chars are NOT the same as zero_width chars
        use crate::stego::ZeroWidth;

        let zw = ZeroWidth::new();
        let ws = WhitespaceVar::new();

        let cover = "This is a long enough text for encoding hidden data using multiple methods at once for a test";
        let stego_ws = ws.encode(cover, b"WS").unwrap();

        // ZeroWidth should NOT detect whitespace-variation stego
        assert_eq!(zw.detect(&stego_ws), 0.0, "ZW should not detect WS stego");
    }

    #[test]
    fn survives_nfc_normalization() {
        use unicode_normalization::UnicodeNormalization;

        let ws = WhitespaceVar::new();
        let cover = "A sufficiently long cover text with enough room for hidden data to survive normalization tests";
        let stego = ws.encode(cover, b"NFC").unwrap();

        let normalized: String = stego.nfc().collect();
        let decoded = ws.decode(&normalized).unwrap();
        assert_eq!(decoded, b"NFC");
    }
}
