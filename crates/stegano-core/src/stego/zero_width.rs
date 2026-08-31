use crate::error::{Result, SteganoError};
use crate::format::frame::bytes_to_bits;
use crate::format::PositionChannel;
use crate::stego::recognition;
use crate::traits::StegoMethod;

/// Zero-Width Character Steganography
///
/// Port fidèle de la logique Python originale (Unisteg/SteganoHero-v1).
/// Encode en insérant des chars zero-width entre les chars visibles,
/// puis DÉBORDE à la fin si le cover est trop court (pas de limite stricte).
///
/// Characters:
/// - U+200B (ZERO WIDTH SPACE)      = bit 0
/// - U+200C (ZERO WIDTH NON-JOINER) = bit 1
const ZERO: char = '\u{200B}'; // ZWSP = bit 0
const ONE: char = '\u{200C}';  // ZWNJ = bit 1

/// Codepoint alphabet of this carrier (SPEC_CORE_V2 §6.5).
const CHANNEL: [char; 2] = [ZERO, ONE];

pub struct ZeroWidth;

impl ZeroWidth {
    pub fn new() -> Self {
        Self
    }

    /// The bit-placement routine of this carrier, and the only one.
    ///
    /// One zero-width character per bit, placed at a word boundary in document
    /// order (backlog F22), then the remainder appended at the end. The overflow
    /// tail is this carrier's identity: it has no strict capacity, and that is
    /// preserved here exactly as the Python original wrote it.
    ///
    /// Where each character lands moved from "after every visible character" to
    /// "at a word boundary, clear of code": the bits themselves keep their value
    /// and their order, which the golden vectors prove. `place_at_word_boundaries`
    /// carries the shared geometry.
    ///
    /// `encode` and `write_positions` both funnel through here. The framing
    /// layer decides which bits arrive; it never decides where they land
    /// (invariant 4, SPEC_CORE_V2 §5).
    fn place_bits(cover: &str, bits: &[u8]) -> String {
        let sequence: Vec<char> = bits
            .iter()
            .map(|bit| if *bit == 1 { ONE } else { ZERO })
            .collect();
        crate::stego::placement::place_at_word_boundaries(cover, &sequence)
    }

    /// The bit-extraction routine of this carrier, and the only one.
    ///
    /// `decode` and `read_positions` both funnel through here.
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
}

/// The position-addressed view of the same placement routine, SPEC_CORE_V2 §3.
///
/// `StegoMethod` speaks bytes, which cannot express a frame whose bit count is
/// not a whole number of bytes. This speaks positions.
impl PositionChannel for ZeroWidth {
    /// One position per word-boundary slot the text offers, since a bit is
    /// placed at a boundary rather than after every character (backlog F22). It
    /// is a floor rather than a ceiling: this carrier appends whatever does not
    /// fit, so `write_positions` never refuses for want of room.
    fn positions(&self, text: &str) -> usize {
        crate::stego::placement::boundary_slots(text)
    }

    fn read_positions(&self, text: &str) -> Vec<u8> {
        Self::extract_bits(text)
    }

    /// A cover already holding characters of this carrier's alphabet is
    /// refused by name.
    ///
    /// Reading returns every zero-width character in document order, so
    /// pre-existing ones would be read as payload bits and shift everything
    /// after them. Refusing is the only honest answer.
    fn check_writable(&self, cover: &str) -> Result<()> {
        let occupied = cover.chars().filter(|c| matches!(*c, ZERO | ONE)).count();
        if occupied == 0 {
            return Ok(());
        }
        Err(recognition::cover_already_occupied("zero_width", occupied))
    }

    fn write_positions(&self, cover: &str, bits: &[u8]) -> Result<String> {
        self.check_writable(cover)?;
        Ok(Self::place_bits(cover, bits))
    }
}

impl StegoMethod for ZeroWidth {
    fn id(&self) -> &str {
        "zero_width"
    }

    fn name(&self) -> &str {
        "Zero-Width Characters"
    }

    /// Encode comme le Python original :
    /// - 1 bit ZW après chaque char visible
    /// - Les bits restants débordent à la fin
    /// - PAS de limite de capacité (le texte peut être plus long que le cover)
    fn encode(&self, cover: &str, payload: &[u8]) -> Result<String> {
        if payload.is_empty() {
            return Err(SteganoError::InvalidInput("empty payload".into()));
        }

        // Backlog F26: the byte path used to skip this, so a cover already
        // holding this carrier's alphabet was refused by one guard on one path
        // and a different guard on the other, giving two explanations for one
        // situation (backlog F20).
        self.check_writable(cover)?;

        Ok(Self::place_bits(cover, &bytes_to_bits(payload)))
    }

    /// Read every channel character and rebuild the bytes.
    ///
    /// This carrier inserts exactly the bits it is handed and a frame is
    /// always a whole number of bytes, so a channel that ends mid-byte is
    /// never something this carrier wrote: it is damage, or characters that
    /// belong to the cover. The reader used to discard the remainder, which
    /// hid that difference (backlog F13b, F20).
    fn decode(&self, stego: &str) -> Result<Vec<u8>> {
        let bits = Self::extract_bits(stego);

        if bits.is_empty() {
            return Err(SteganoError::NothingDetected);
        }
        if bits.len() % 8 != 0 {
            return Err(recognition::channel_ends_mid_byte("zero_width", bits.len()));
        }
        let usable = bits.len();

        Ok(bits[..usable]
            .chunks_exact(8)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(0u8, |acc, (i, &bit)| acc | (bit << (7 - i)))
            })
            .collect())
    }

    fn detect(&self, text: &str) -> f64 {
        let zw_count = text.chars().filter(|c| *c == ZERO || *c == ONE).count();
        if zw_count == 0 {
            return 0.0;
        }
        let total = text.chars().count().max(1);
        let density = zw_count as f64 / total as f64;
        (density * 5.0).min(1.0)
    }

    fn strip(&self, text: &str) -> String {
        text.chars()
            .filter(|c| !matches!(*c, ZERO | ONE))
            .collect()
    }

    fn channel(&self) -> &'static [char] {
        &CHANNEL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALREADY_CARRYING: &str = include_str!("../../../../tests/corpus/already_carrying.txt");

    // ─── Attribution: the cover's own characters are not free slots ───

    /// Backlog F20 and F26. `encode` never asked `check_writable`, so a cover
    /// already holding this carrier's alphabet was refused by one guard on one
    /// path and by a different guard on the other, giving two explanations for
    /// one situation.
    #[test]
    fn encode_and_the_position_path_refuse_an_occupied_cover_in_the_same_words() {
        let zw = ZeroWidth::new();
        let cover = format!("A cover text with room enough for a byte or two of payload{ZERO}");

        let via_bytes = zw
            .encode(&cover, b"x")
            .expect_err("the cover already holds this carrier's alphabet")
            .to_string();
        let via_positions = zw
            .write_positions(&cover, &[0u8; 8])
            .expect_err("the cover already holds this carrier's alphabet")
            .to_string();

        assert_eq!(via_bytes, via_positions);
    }

    /// The corpus document that arrives already carrying is refused, and its
    /// stray characters are not counted as room.
    #[test]
    fn the_document_that_arrives_carrying_is_refused_and_offers_no_room_for_what_it_holds() {
        let zw = ZeroWidth::new();
        let without: String = ALREADY_CARRYING
            .chars()
            .filter(|c| !matches!(*c, ZERO | ONE))
            .collect();

        assert_eq!(zw.capacity(ALREADY_CARRYING), zw.capacity(&without));
        assert!(zw.encode(ALREADY_CARRYING, b"x").is_err());
        assert!(zw.decode(ALREADY_CARRYING).is_err());
    }

    /// A group that ends mid-byte is damage or somebody else's characters.
    /// This carrier inserts exactly the bits it is handed, so a partial group
    /// is never something it wrote.
    #[test]
    fn decode_refuses_a_group_that_ends_mid_byte_rather_than_discarding_it() {
        let zw = ZeroWidth::new();
        let ten_bits = format!("x{ZERO}").repeat(10);
        let message = zw
            .decode(&ten_bits)
            .expect_err("ten bits are not a whole number of bytes")
            .to_string();
        assert!(
            message.contains("10"),
            "the refusal must name what it found: {message}"
        );
    }

    #[test]
    fn channel_is_the_zero_width_alphabet() {
        let zw = ZeroWidth::new();
        assert_eq!(zw.channel(), &[ZERO, ONE]);
    }

    #[test]
    fn the_byte_path_and_the_position_path_place_the_same_characters() {
        // Handing the carrier a byte payload and handing it the same bits
        // through the position channel must produce the same text. If these
        // ever diverge, the framing layer has grown a placement rule of its
        // own, which invariant 4 forbids.
        let zw = ZeroWidth::new();
        let cover = "A cover text long enough to take a payload and then some more besides";

        for payload in [b"x".as_slice(), b"two bytes", b"a longer payload than the cover holds"] {
            let through_bytes = zw.encode(cover, payload).unwrap();
            let through_bits = zw.write_positions(cover, &bytes_to_bits(payload)).unwrap();
            assert_eq!(through_bytes, through_bits, "payload {payload:?}");

            let read_back = zw.read_positions(&through_bits);
            assert_eq!(read_back, bytes_to_bits(payload));
        }
    }

    #[test]
    fn a_cover_already_holding_the_alphabet_is_refused_by_name() {
        let zw = ZeroWidth::new();
        match zw.check_writable("already\u{200B}carrying") {
            Err(SteganoError::EncodingFailed { method, reason }) => {
                assert_eq!(method, "zero_width");
                assert!(reason.contains("alphabet"), "reason was: {reason}");
            }
            other => panic!("expected a named refusal, got {other:?}"),
        }
        assert!(zw.check_writable("nothing here yet").is_ok());
    }

    #[test]
    fn positions_count_one_slot_per_word_boundary() {
        let zw = ZeroWidth::new();
        // One word of five letters: only the two document edges are boundaries.
        assert_eq!(zw.positions("abcde"), 2);
        // Two words: the two edges and the two gaps around the space.
        assert_eq!(zw.positions("ab cd"), 4);
        // Pre-existing channel characters are occupancy, not slots. Stripped to
        // the same visible skeleton, the count does not move (backlog F13b).
        assert_eq!(zw.positions("ab\u{200B}cd\u{200C}e"), zw.positions("abcde"));
    }

    #[test]
    fn roundtrip_ascii() {
        let zw = ZeroWidth::new();
        let cover = "The quick brown fox jumps over the lazy dog near the river bank today";
        let secret = b"Hello";
        let stego = zw.encode(cover, secret).unwrap();
        let decoded = zw.decode(&stego).unwrap();
        assert_eq!(decoded, secret);
    }

    #[test]
    fn roundtrip_unicode() {
        let zw = ZeroWidth::new();
        let cover = "Un texte en francais avec des accents et des caracteres speciaux pour tester";
        let secret = "Bonjour le monde!".as_bytes();
        let stego = zw.encode(cover, secret).unwrap();
        let decoded = zw.decode(&stego).unwrap();
        assert_eq!(decoded, secret);
    }

    #[test]
    fn overflow_longer_than_cover() {
        // Le secret peut être plus long que le cover (débordement à la fin)
        let zw = ZeroWidth::new();
        let cover = "Hi";
        let secret = b"This is much longer than the cover text!";
        let stego = zw.encode(cover, secret).unwrap();
        let decoded = zw.decode(&stego).unwrap();
        assert_eq!(decoded, secret);
    }

    #[test]
    fn detection_positive() {
        let zw = ZeroWidth::new();
        let cover = "A simple test text with enough characters for encoding";
        let stego = zw.encode(cover, b"Hi").unwrap();
        assert!(zw.detect(&stego) > 0.0);
    }

    #[test]
    fn detection_negative() {
        let zw = ZeroWidth::new();
        assert_eq!(zw.detect("Just a normal text with no hidden data"), 0.0);
    }

    #[test]
    fn strip_cleans_text() {
        let zw = ZeroWidth::new();
        let cover = "Hello world from the steganography test suite today";
        let stego = zw.encode(cover, b"Secret").unwrap();
        assert_eq!(zw.strip(&stego), cover);
    }

    #[test]
    fn visual_identity() {
        let zw = ZeroWidth::new();
        let cover = "This text should look exactly the same after steganography";
        let stego = zw.encode(cover, b"x").unwrap();
        assert_eq!(zw.strip(&stego), cover);
    }
}
