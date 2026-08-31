//! Document format: preamble, resync markers, envelope. SPEC_CORE_V2 §3 and §4.
//!
//! This layer sits between a payload and a carrier. It decides *what* bits a
//! carrier receives; the carrier alone decides *where* they go. The
//! bit-placement algorithms are untouched by everything here, which is what
//! invariant 4 requires and what the carriers' own tests still prove.
//!
//! The reason it exists: a carrier reading every substitutable position it can
//! find returns the payload followed by one zero byte per unused position, so
//! any cover larger than its payload produced an unparseable result. The
//! preamble's `payload_bits` field ends that. The reader reads the bits that
//! were written and stops.
//!
//! Read and write are asymmetric on purpose (§8). This build writes v2 only.
//! It reads v2 and, through `extract_compat`, documents written before the
//! format existed. Which of the two was read is always stated, never inferred
//! and never quietly patched over.

pub mod crc;
pub mod envelope;
pub mod frame;
pub mod frame_light;
pub mod preamble;

pub use crc::{crc16_ccitt, crc32};
pub use envelope::{ChainStep, Envelope, ENVELOPE_VERSION};
pub use frame::{
    build, is_framed, locate_preamble, locate_resync, marker_spacing, read, scan_resync,
    FrameContents, Layout, PreambleSource, ResyncHit, MARKER_BITS, MARKER_LEN,
};
pub use preamble::{Flags, Mission, Preamble, MAGIC, PREAMBLE_BITS, PREAMBLE_LEN, VERSION_V2};

use crate::crypto::keytree::SALT_LEN;
use crate::error::{Result, SteganoError};

/// A carrier that exposes its substitutable slots as an addressable bit channel.
///
/// `StegoMethod::encode` and `decode` speak bytes, which cannot express the
/// trailing positions of a cover that a frame must leave empty. This trait
/// speaks positions instead. It is deliberately a second view of the same
/// placement routine, not a second placement routine.
pub trait PositionChannel {
    /// How many substitutable positions this cover offers.
    fn positions(&self, text: &str) -> usize;

    /// One bit per substitutable position, in document order.
    fn read_positions(&self, text: &str) -> Vec<u8>;

    /// Can this text host a frame at all, size aside?
    ///
    /// A carrier whose written and read position sets could diverge on some
    /// covers says so here rather than producing a document that will not
    /// decode. The default is that any cover is acceptable.
    fn check_writable(&self, _cover: &str) -> Result<()> {
        Ok(())
    }

    /// Write one bit per substitutable position, in document order.
    ///
    /// Raises when `bits` is longer than the cover can hold. Positions beyond
    /// `bits` keep their unsubstituted form, which reads back as bit 0.
    fn write_positions(&self, cover: &str, bits: &[u8]) -> Result<String>;
}

/// Which format a document turned out to be in.
///
/// Returned rather than resolved silently: a caller that decoded a v1 document
/// must be able to say so, offer re-encoding, and never present the result as
/// though the current format had been read (§8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatRead {
    /// A framed v2 document.
    V2(FrameContents),
    /// A document with no preamble, read through the pre-format path.
    ///
    /// `bytes` covers every substitutable position in the document, including
    /// the ones nothing was ever written to. Trimming them needs a length the
    /// format did not record, which is exactly what v2 added.
    V1 { bytes: Vec<u8> },
}

/// Payload capacity in bytes for this carrier on this cover, framing deducted.
///
/// The figure is what fits inside the positions the cover itself offers. For a
/// carrier the cover bounds, that is also the figure the engine accepts and one
/// byte more is refused. For a carrier that creates the positions it writes it
/// is a different and still useful figure: past it the document grows, so it is
/// the point where the mark stops looking like its cover (invariant 4b). Ask
/// `cover_bounds_writes` which of the two a carrier is; never guess from its id.
pub fn capacity_bytes<C: PositionChannel + ?Sized>(carrier: &C, cover: &str) -> Result<usize> {
    carrier.check_writable(cover)?;
    frame::payload_capacity_bytes(carrier.positions(cover))
}

/// Does the cover's position count bound what this carrier will write?
///
/// Measured through the carrier's own position channel rather than declared on
/// the trait, so it cannot drift away from the placement routine it describes:
/// the carrier is offered one bit more than the cover has slots for and asked
/// to write it. A carrier that refuses holds itself to the cover. A carrier
/// that accepts creates the positions it needs and extends the document
/// instead, which is what zero-width has always done. Its overflow tail is
/// that carrier's identity, and invariant 4 says to reinforce the placement
/// algorithms, never redesign them.
///
/// A cover the carrier refuses outright is reported as bounded, because the
/// refusal is the answer and `capacity_bytes` will name it.
pub fn cover_bounds_writes<C: PositionChannel + ?Sized>(carrier: &C, cover: &str) -> bool {
    let one_too_many = vec![0u8; carrier.positions(cover) + 1];
    carrier.write_positions(cover, &one_too_many).is_err()
}

/// Frame `payload` and place it in `cover` with `carrier`.
pub fn embed<C: PositionChannel + ?Sized>(
    carrier: &C,
    cover: &str,
    flags: Flags,
    salt: [u8; SALT_LEN],
    payload: &[u8],
) -> Result<String> {
    carrier.check_writable(cover)?;
    let bits = build(carrier.positions(cover), flags, salt, payload)?;
    carrier.write_positions(cover, &bits)
}

/// Read a framed document. Raises when it is not one.
pub fn extract<C: PositionChannel + ?Sized>(carrier: &C, stego: &str) -> Result<FrameContents> {
    let bits = carrier.read_positions(stego);
    if bits.is_empty() {
        return Err(SteganoError::NothingDetected);
    }
    read(&bits)
}

/// Read a document in whichever format it is in, and say which that was.
pub fn extract_compat<C: PositionChannel + ?Sized>(
    carrier: &C,
    stego: &str,
) -> Result<FormatRead> {
    let bits = carrier.read_positions(stego);
    if bits.is_empty() {
        return Err(SteganoError::NothingDetected);
    }

    if is_framed(&bits) {
        // A preamble is present, so this is a v2 document. If the frame is
        // nonetheless unreadable it is damaged, and saying so is the answer.
        // Falling back to the v1 path here would be exactly the silent
        // degradation invariant 2 forbids.
        return read(&bits).map(FormatRead::V2);
    }

    Ok(FormatRead::V1 {
        bytes: frame::bits_to_bytes(&bits),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stego::Homoglyph;
    use crate::traits::StegoMethod;

    const LONG_ARTICLE: &str = include_str!("../../../../tests/corpus/en_long_article.txt");
    const FR_ACCENTED: &str = include_str!("../../../../tests/corpus/fr_accented.txt");
    const MINIMAL_TINY: &str = include_str!("../../../../tests/corpus/minimal_tiny.txt");
    const CJK_JAPANESE: &str = include_str!("../../../../tests/corpus/cjk_japanese.txt");
    const CYRILLIC_RUSSIAN: &str = include_str!("../../../../tests/corpus/cyrillic_russian.txt");

    const SALT: [u8; SALT_LEN] = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
        0xAF,
    ];

    /// Character index of every substitutable position, using only the
    /// carrier's published alphabet.
    fn position_char_indices(text: &str) -> Vec<usize> {
        let channel = Homoglyph::new().channel();
        text.chars()
            .enumerate()
            .filter(|(_, c)| channel.contains(c))
            .map(|(i, _)| i)
            .collect()
    }

    fn slice_chars(text: &str, from: usize, to: usize) -> String {
        text.chars().skip(from).take(to - from).collect()
    }

    // ─── The corpus is what the manifest says it is ───

    #[test]
    fn the_corpus_measurements_still_hold() {
        // The manifest counts Latin positions a cover offers for writing.
        let hg = Homoglyph::new();
        assert_eq!(hg.capacity(LONG_ARTICLE), 1130, "en_long_article.txt");
        assert_eq!(hg.capacity(MINIMAL_TINY), 3, "minimal_tiny.txt");
        assert_eq!(hg.capacity(CJK_JAPANESE), 0, "cjk_japanese.txt");
        assert_eq!(hg.capacity(CYRILLIC_RUSSIAN), 0, "cyrillic_russian.txt");

        // With no pre-existing Cyrillic, the readable position set matches.
        assert_eq!(hg.positions(LONG_ARTICLE), 1130);
    }

    // ─── The defect ───

    /// The live defect, pinned so it cannot come back.
    ///
    /// The pre-format read path returns one zero byte per unused position. On
    /// the long article that is 139 trailing zeros after a two byte secret,
    /// and the package parser rejects the result. The framed path returns two
    /// bytes.
    #[test]
    fn unused_positions_no_longer_reach_the_reader() {
        let hg = Homoglyph::new();
        let secret = b"Hi";

        let unframed = hg.encode(LONG_ARTICLE, secret).unwrap();
        let unframed_back = hg.decode(&unframed).unwrap();
        assert_eq!(
            unframed_back.len(),
            141,
            "the pre-format path reads every position, which is the defect"
        );
        assert_eq!(&unframed_back[..2], secret);
        assert!(
            unframed_back[2..].iter().all(|b| *b == 0),
            "the defect is a run of trailing zero bytes"
        );

        let framed = embed(&hg, LONG_ARTICLE, Flags::conceal(), SALT, secret).unwrap();
        let contents = extract(&hg, &framed).unwrap();
        assert_eq!(
            contents.payload, secret,
            "the framed path returns exactly what was written"
        );
        assert_eq!(contents.payload.len(), 2);
    }

    #[test]
    fn a_two_byte_secret_round_trips_on_the_long_article() {
        let hg = Homoglyph::new();
        let secret = b"Hi";

        let framed = embed(&hg, LONG_ARTICLE, Flags::conceal(), SALT, secret).unwrap();
        let contents = extract(&hg, &framed).unwrap();

        assert_eq!(contents.payload, secret);
        assert_eq!(contents.preamble.salt, SALT);
        assert_eq!(contents.preamble.version, VERSION_V2);
    }

    #[test]
    fn a_full_capacity_secret_round_trips_on_the_long_article() {
        let hg = Homoglyph::new();
        let capacity = capacity_bytes(&hg, LONG_ARTICLE).unwrap();
        assert_eq!(capacity, 73, "framing deducted from 141 raw bytes");

        let secret: Vec<u8> = (0..capacity).map(|i| b'a' + (i % 26) as u8).collect();
        let framed = embed(&hg, LONG_ARTICLE, Flags::conceal(), SALT, &secret).unwrap();
        assert_eq!(extract(&hg, &framed).unwrap().payload, secret);
    }

    #[test]
    fn a_hundred_byte_secret_round_trips_on_a_cover_that_can_hold_one() {
        // The long article cannot: 1130 positions is 141 bytes, and the two
        // preamble replicas alone cost 48 of them. A hundred byte payload
        // needs roughly 1376 positions, about 3330 characters of English.
        let hg = Homoglyph::new();
        let cover = format!("{LONG_ARTICLE}\n\n{LONG_ARTICLE}");
        assert!(capacity_bytes(&hg, &cover).unwrap() >= 100);

        let secret: Vec<u8> = (0..100u8).collect();
        let framed = embed(&hg, &cover, Flags::conceal(), SALT, &secret).unwrap();
        let contents = extract(&hg, &framed).unwrap();

        assert_eq!(contents.payload, secret);
        assert_eq!(contents.preamble.payload_bits, 800);
    }

    #[test]
    fn the_long_article_refuses_a_hundred_byte_secret_by_the_numbers() {
        // No truncation, no partial write, and the message carries the
        // arithmetic a caller needs to pick a longer cover.
        let hg = Homoglyph::new();
        match embed(&hg, LONG_ARTICLE, Flags::conceal(), SALT, &[0u8; 100]) {
            Err(SteganoError::CapacityExceeded { needed, available }) => {
                assert_eq!(needed, 800);
                assert_eq!(available, 584);
            }
            other => panic!("expected CapacityExceeded, got {other:?}"),
        }
    }

    // ─── Covers that cannot carry a frame ───

    #[test]
    fn the_tiny_cover_raises_rather_than_producing_a_document() {
        let hg = Homoglyph::new();
        assert!(matches!(
            embed(&hg, MINIMAL_TINY, Flags::conceal(), SALT, b"x"),
            Err(SteganoError::CapacityExceeded { .. })
        ));
        assert!(capacity_bytes(&hg, MINIMAL_TINY).is_err());
    }

    #[test]
    fn a_non_latin_script_raises_rather_than_falling_back() {
        // Japanese offers this carrier nothing. It must not silently hand the
        // work to another carrier or return the cover unchanged. Choosing a
        // viable carrier is the caller's decision, not this layer's.
        let hg = Homoglyph::new();
        match embed(&hg, CJK_JAPANESE, Flags::conceal(), SALT, b"x") {
            Err(SteganoError::CapacityExceeded { available, .. }) => assert_eq!(available, 0),
            other => panic!("expected CapacityExceeded, got {other:?}"),
        }
        assert!(capacity_bytes(&hg, CJK_JAPANESE).is_err());
    }

    #[test]
    fn cyrillic_prose_is_refused_by_name_and_left_alone() {
        // Russian text is full of the carrier's own alphabet. Reading counts
        // those as positions and writing cannot touch them, so the two index
        // spaces would diverge. Refusing is the only honest answer, and it is
        // the answer that also keeps the author's text intact.
        let hg = Homoglyph::new();

        match embed(&hg, CYRILLIC_RUSSIAN, Flags::conceal(), SALT, b"x") {
            Err(SteganoError::EncodingFailed { method, reason }) => {
                assert_eq!(method, "homoglyph");
                assert!(reason.contains("alphabet"), "reason was: {reason}");
            }
            other => panic!("expected a named refusal, got {other:?}"),
        }
        assert!(capacity_bytes(&hg, CYRILLIC_RUSSIAN).is_err());
    }

    // ─── Excerpts and truncation ───

    #[test]
    fn a_mid_document_excerpt_of_about_160_characters_locates_a_resync_marker() {
        let hg = Homoglyph::new();
        let framed = embed(&hg, LONG_ARTICLE, Flags::conceal(), SALT, b"resync").unwrap();

        let layout = Layout::for_positions(hg.positions(&framed)).unwrap();
        let marker = layout.markers()[0];
        let indices = position_char_indices(&framed);

        // The marker spans positions [marker, marker + 32). Take a window of
        // about 160 characters around it, as an excerpt of a quoted paragraph.
        let span_start = indices[marker];
        let span_end = indices[marker + MARKER_BITS - 1] + 1;
        let padding = (160 - (span_end - span_start)) / 2;
        let from = span_start - padding;
        let to = span_end + padding;

        let excerpt = slice_chars(&framed, from, to);
        assert!(
            (150..=175).contains(&excerpt.chars().count()),
            "excerpt was {} characters",
            excerpt.chars().count()
        );

        let hit = locate_resync(&hg.read_positions(&excerpt))
            .expect("a 160 character excerpt spanning a marker must locate it");
        assert_eq!(hit.occurrence, 2);
        assert_eq!(hit.document_position(1130), marker);
    }

    #[test]
    fn a_head_truncated_document_still_finds_a_preamble_replica() {
        let hg = Homoglyph::new();
        let framed = embed(&hg, LONG_ARTICLE, Flags::conceal(), SALT, b"truncated").unwrap();
        let total = framed.chars().count();

        for cut in [700usize, 1000, 1400] {
            let excerpt = slice_chars(&framed, cut, total);
            let (preamble, source) = locate_preamble(&hg.read_positions(&excerpt))
                .unwrap_or_else(|e| panic!("cutting {cut} characters lost both replicas: {e}"));
            assert_eq!(source, PreambleSource::Tail);
            assert_eq!(preamble.salt, SALT);
            assert_eq!(preamble.payload_bits, 72);
        }
    }

    #[test]
    fn a_tail_truncated_document_still_finds_a_preamble_replica() {
        let hg = Homoglyph::new();
        let framed = embed(&hg, LONG_ARTICLE, Flags::conceal(), SALT, b"truncated").unwrap();

        for keep in [600usize, 1400, 2000] {
            let excerpt = slice_chars(&framed, 0, keep);
            let (preamble, source) = locate_preamble(&hg.read_positions(&excerpt))
                .unwrap_or_else(|e| panic!("keeping {keep} characters lost both replicas: {e}"));
            assert_eq!(source, PreambleSource::Head);
            assert_eq!(preamble.salt, SALT);
        }
    }

    #[test]
    fn an_accented_cover_round_trips() {
        // Multi-byte characters must not shift position counting, which walks
        // characters and never bytes.
        let hg = Homoglyph::new();
        let secret = "accents changent rien".as_bytes();

        let framed = embed(&hg, FR_ACCENTED, Flags::conceal(), SALT, secret).unwrap();
        assert_eq!(extract(&hg, &framed).unwrap().payload, secret);
        assert_eq!(hg.strip(&framed), FR_ACCENTED);
    }

    #[test]
    fn a_framed_document_survives_nfc_normalisation() {
        // This is why homoglyph is the carrier provenance work wants, and the
        // frame must not cost that property. Word processors normalise on
        // save; the preamble, the markers and the payload all have to survive.
        use unicode_normalization::UnicodeNormalization;

        let hg = Homoglyph::new();
        let secret = b"survives the round trip";

        let framed = embed(&hg, LONG_ARTICLE, Flags::conceal(), SALT, secret).unwrap();
        let normalised: String = framed.nfc().collect();

        let contents = extract(&hg, &normalised).unwrap();
        assert_eq!(contents.payload, secret);
        assert_eq!(contents.preamble.salt, SALT);
        assert!(locate_resync(&hg.read_positions(&normalised)).is_some());
    }

    // ─── Envelope through a carrier ───

    #[test]
    fn an_envelope_survives_the_whole_stack() {
        let hg = Homoglyph::new();
        let secret = b"the payload the chain produced";
        let envelope = Envelope::new(
            vec![
                ChainStep::new("deflate", vec![]),
                ChainStep::new("chacha20_poly1305", vec![7; 12]),
            ],
            secret.to_vec(),
        );

        let framed = embed(
            &hg,
            LONG_ARTICLE,
            Flags::conceal(),
            SALT,
            &envelope.to_bytes().unwrap(),
        )
        .unwrap();

        let recovered = Envelope::parse(&extract(&hg, &framed).unwrap().payload).unwrap();
        assert_eq!(recovered, envelope);
        assert_eq!(recovered.v, 2);
        assert_eq!(recovered.payload, secret);
        assert!(
            !recovered.chain.iter().any(|s| s.id == "homoglyph"),
            "carriers transport the envelope, they are never steps inside it"
        );
    }

    // ─── Backward compatibility, SPEC_CORE_V2 §8 ───

    #[test]
    fn a_document_written_before_the_format_reads_as_v1_and_says_so() {
        let hg = Homoglyph::new();
        let unframed = hg.encode(LONG_ARTICLE, b"Hi").unwrap();

        match extract_compat(&hg, &unframed).unwrap() {
            FormatRead::V1 { bytes } => {
                assert_eq!(&bytes[..2], b"Hi");
                assert_eq!(bytes.len(), 141);
            }
            FormatRead::V2(_) => panic!("an unframed document must not read as v2"),
        }
    }

    #[test]
    fn a_framed_document_reads_as_v2_and_says_so() {
        let hg = Homoglyph::new();
        let framed = embed(&hg, LONG_ARTICLE, Flags::conceal(), SALT, b"v2 only").unwrap();

        match extract_compat(&hg, &framed).unwrap() {
            FormatRead::V2(contents) => assert_eq!(contents.payload, b"v2 only"),
            FormatRead::V1 { .. } => panic!("a framed document must not read as v1"),
        }
    }

    #[test]
    fn a_damaged_frame_is_named_rather_than_read_as_v1() {
        let hg = Homoglyph::new();
        let framed = embed(&hg, LONG_ARTICLE, Flags::conceal(), SALT, b"damaged").unwrap();
        let total = framed.chars().count();
        let head_only = slice_chars(&framed, 0, total - 600);

        match extract_compat(&hg, &head_only) {
            Err(SteganoError::DecodingFailed { method, reason }) => {
                assert_eq!(method, "frame");
                assert!(!reason.is_empty());
            }
            other => panic!("expected a named refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_text_with_no_positions_at_all_is_refused() {
        let hg = Homoglyph::new();
        assert!(matches!(
            extract(&hg, CJK_JAPANESE),
            Err(SteganoError::NothingDetected)
        ));
        assert!(matches!(
            extract_compat(&hg, CJK_JAPANESE),
            Err(SteganoError::NothingDetected)
        ));
    }

    // ─── Placement is untouched ───

    #[test]
    fn framing_changes_no_character_outside_the_carrier_alphabet() {
        let hg = Homoglyph::new();
        let framed = embed(&hg, LONG_ARTICLE, Flags::conceal(), SALT, b"unchanged").unwrap();

        assert_eq!(framed.chars().count(), LONG_ARTICLE.chars().count());
        assert_eq!(
            hg.positions(&framed),
            hg.positions(LONG_ARTICLE),
            "substitution must not change the position set"
        );
        assert_eq!(
            hg.strip(&framed),
            LONG_ARTICLE,
            "stripping a framed document must restore the cover exactly"
        );
    }

    #[test]
    fn the_frame_writes_through_the_carrier_placement_routine() {
        // Handing the carrier a byte payload and handing it the same bits
        // through the position channel must produce the same text. If these
        // ever diverge, the framing layer has grown a placement rule of its
        // own, which invariant 4 forbids.
        let hg = Homoglyph::new();
        let payload = b"same placement";

        let through_bytes = hg.encode(LONG_ARTICLE, payload).unwrap();
        let through_bits = hg
            .write_positions(LONG_ARTICLE, &frame::bytes_to_bits(payload))
            .unwrap();

        assert_eq!(through_bytes, through_bits);
    }
}
