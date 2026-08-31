//! Invariant 4, proven for the placement change of backlog F22 and F23.
//!
//! Word-boundary placement moved *where* each channel character lands. It must
//! not have moved *which* bit lands or *in what order*. These golden vectors
//! pin the bit-to-character mapping of each carrier: for a fixed payload on a
//! fixed cover, the bits read back out are exactly the bits that went in, in the
//! same order, and the decoded bytes are unchanged. A test that only round-trips
//! would pass even if the mapping had been rewritten; these fail unless the
//! sequence itself is preserved.
//!
//! The companion checks show the positions did move: no channel character lands
//! between two letters of a word (F22), and every fenced block and inline code
//! span is left byte-identical (F23).

use stegano_core::fidelity::{self, CheckVerdict, FidelityOptions};
use stegano_core::format::{Mission, PositionChannel};
use stegano_core::stego::{Bidi, Homoglyph, WhitespaceVar, ZeroWidth};
use stegano_core::traits::StegoMethod;

const EN_LONG: &str = include_str!("../../../tests/corpus/en_long_article.txt");
const TECHNICAL_MD: &str = include_str!("../../../tests/corpus/technical_markdown.md");

/// `b"Hi"` most-significant-bit first: the sequence every carrier must place.
///
/// `H` is `0x48` = `0100_1000`, `i` is `0x69` = `0110_1001`.
const HI_BITS: [u8; 16] = [0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1];

// ---------------------------------------------------------------------------
// Golden vectors: the bit sequence is preserved, only its positions moved
// ---------------------------------------------------------------------------

/// The three inserting carriers read back exactly the bits they were handed, in
/// order, delimiters skipped. Whitespace and bidi interleave a delimiter every
/// eight bits; `read_positions` skips it, so the payload bits are what remains.
#[test]
fn the_inserting_carriers_preserve_the_bit_sequence() {
    let zw = ZeroWidth::new();
    let ws = WhitespaceVar::new();
    let bidi = Bidi::new();

    for (id, marked) in [
        ("zero_width", zw.encode(EN_LONG, b"Hi").unwrap()),
        ("whitespace_var", ws.encode(EN_LONG, b"Hi").unwrap()),
        ("bidi", bidi.encode(EN_LONG, b"Hi").unwrap()),
    ] {
        let bits = match id {
            "zero_width" => zw.read_positions(&marked),
            "whitespace_var" => ws.read_positions(&marked),
            _ => bidi.read_positions(&marked),
        };
        assert_eq!(bits, HI_BITS, "{id}: the bit sequence changed, not only its positions");
    }

    assert_eq!(zw.decode(&zw.encode(EN_LONG, b"Hi").unwrap()).unwrap(), b"Hi");
    assert_eq!(ws.decode(&ws.encode(EN_LONG, b"Hi").unwrap()).unwrap(), b"Hi");
    assert_eq!(bidi.decode(&bidi.encode(EN_LONG, b"Hi").unwrap()).unwrap(), b"Hi");
}

/// Homoglyph substitutes in place, so it does not move for F22; its golden
/// vector is that code-region exclusion (F23) did not disturb the mapping. The
/// leading positions carry the payload bits in order; the rest read back as the
/// unsubstituted zero they always were.
#[test]
fn homoglyph_preserves_the_bit_sequence() {
    let hg = Homoglyph::new();
    let marked = hg.encode(EN_LONG, b"Hi").unwrap();

    let bits = hg.read_positions(&marked);
    assert_eq!(&bits[..16], &HI_BITS, "the substitution sequence changed");
    assert!(
        bits[16..].iter().all(|b| *b == 0),
        "positions past the payload must read back as the zero they always were"
    );
    // The pre-format read returns one byte per position; the payload leads it.
    let decoded = hg.decode(&marked).unwrap();
    assert_eq!(&decoded[..2], b"Hi");
}

// ---------------------------------------------------------------------------
// The positions did move: F22, no interior insertions
// ---------------------------------------------------------------------------

/// The same load placed by the same carriers now breaks no word. Proven against
/// the naive placement it replaced: after every visible character, `b"Hi"` would
/// have put channel characters inside words all through the head of the article.
#[test]
fn the_moved_positions_land_at_word_boundaries() {
    let zw = ZeroWidth::new();
    let ws = WhitespaceVar::new();
    let bidi = Bidi::new();

    for (id, marked) in [
        ("zero_width", zw.encode(EN_LONG, b"Hi").unwrap()),
        ("whitespace_var", ws.encode(EN_LONG, b"Hi").unwrap()),
        ("bidi", bidi.encode(EN_LONG, b"Hi").unwrap()),
    ] {
        let report =
            fidelity::assess(EN_LONG, &marked, &FidelityOptions::for_mission(Mission::Sign));
        assert_eq!(
            report.word_selection.interior_insertions, 0,
            "{id}: a channel character landed inside a word"
        );
        assert!(
            report.word_selection.boundary_insertions > 0,
            "{id}: nothing was placed"
        );
        assert_eq!(report.word_selection.verdict, CheckVerdict::Clean, "{id}");
    }
}

// ---------------------------------------------------------------------------
// The code regions are byte-identical: F23, all four carriers
// ---------------------------------------------------------------------------

/// Encoding `technical_markdown.md` leaves every fenced command byte-identical,
/// on all four carriers. The commands a reader pastes into a shell survive, and
/// the fidelity paste-safety check confirms nothing landed in machine input.
#[test]
fn every_carrier_leaves_the_fenced_commands_byte_identical() {
    let carriers: Vec<(&str, Box<dyn StegoMethod>)> = vec![
        ("zero_width", Box::new(ZeroWidth::new())),
        ("whitespace_var", Box::new(WhitespaceVar::new())),
        ("bidi", Box::new(Bidi::new())),
        ("homoglyph", Box::new(Homoglyph::new())),
    ];

    for (id, carrier) in carriers {
        // A payload sized to half the carrier's slots, so the sweep exercises a
        // real load rather than a token byte.
        let positions = carrier.positions(TECHNICAL_MD);
        let bytes = (positions / 2 / 8).max(1);
        let payload: Vec<u8> = (0..bytes).map(|i| (i * 37 % 251) as u8).collect();
        let marked = carrier
            .encode(TECHNICAL_MD, &payload)
            .unwrap_or_else(|e| panic!("{id} refused a half-capacity payload: {e}"));

        assert!(
            marked.contains("systemctl status app.service"),
            "{id} altered the first fenced command"
        );
        assert!(
            marked.contains("curl -sf http://127.0.0.1:8787/health"),
            "{id} altered the second fenced command"
        );

        let report =
            fidelity::assess(TECHNICAL_MD, &marked, &FidelityOptions::for_mission(Mission::Sign));
        assert_eq!(
            report.paste_safety.marks_inside_code, 0,
            "{id} put {} marks in machine input: {:?}",
            report.paste_safety.marks_inside_code, report.paste_safety.sites
        );
        assert_eq!(report.paste_safety.verdict, CheckVerdict::Clean, "{id}");
    }
}
