//! The capacity a surface reports must be the capacity the engine accepts.
//!
//! Backlog F19. A figure the engine will not honour is worse than no figure,
//! because every pre-flight check in the interfaces is built on it. Two
//! figures were measured wrong before this suite existed:
//!
//! - `StegoMethod::capacity` reports what the *carrier* can place, before the
//!   frame of SPEC_CORE_V2 §3 takes its two preamble replicas and its resync
//!   markers out. On `technical_markdown.md` homoglyph reported sixty bytes
//!   while the engine accepted none.
//! - The four carriers do not report `capacity()` in the same unit (F25), so a
//!   caller budgeting from it hands one of them eight times its real load.
//!
//! Both are answered the same way: one call on `&dyn StegoMethod` that returns
//! the framed figure, and one call on the pipeline that returns the secret
//! figure with the envelope deducted as well. This suite holds both to the
//! only standard that matters: place exactly that many bytes and it works,
//! place one more and it is refused by name.

use stegano_core::error::SteganoError;
use stegano_core::format::frame_light;
use stegano_core::pipeline;
use stegano_core::stego::{Bidi, Homoglyph, WhitespaceVar, ZeroWidth};
use stegano_core::traits::StegoMethod;

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

const EN_LONG: &str = include_str!("../../../tests/corpus/en_long_article.txt");
const FR_ACCENTED: &str = include_str!("../../../tests/corpus/fr_accented.txt");
const TECHNICAL_MD: &str = include_str!("../../../tests/corpus/technical_markdown.md");
const MIXED: &str = include_str!("../../../tests/corpus/mixed_multilingual.txt");
const EN_SHORT: &str = include_str!("../../../tests/corpus/en_short.txt");
const MINIMAL: &str = include_str!("../../../tests/corpus/minimal_tiny.txt");
const CJK: &str = include_str!("../../../tests/corpus/cjk_japanese.txt");
const CYRILLIC: &str = include_str!("../../../tests/corpus/cyrillic_russian.txt");
const ALREADY_CARRYING: &str = include_str!("../../../tests/corpus/already_carrying.txt");

fn corpus() -> Vec<(&'static str, &'static str)> {
    vec![
        ("en_long_article.txt", EN_LONG),
        ("fr_accented.txt", FR_ACCENTED),
        ("technical_markdown.md", TECHNICAL_MD),
        ("mixed_multilingual.txt", MIXED),
        ("en_short.txt", EN_SHORT),
        ("minimal_tiny.txt", MINIMAL),
        ("cjk_japanese.txt", CJK),
        ("cyrillic_russian.txt", CYRILLIC),
        ("already_carrying.txt", ALREADY_CARRYING),
    ]
}

fn carriers() -> Vec<(&'static str, Box<dyn StegoMethod>)> {
    vec![
        ("zero_width", Box::new(ZeroWidth::new())),
        ("whitespace_var", Box::new(WhitespaceVar::new())),
        ("bidi", Box::new(Bidi::new())),
        ("homoglyph", Box::new(Homoglyph::new())),
    ]
}

// ---------------------------------------------------------------------------
// One call, from a trait object
// ---------------------------------------------------------------------------

/// The framed figure is reachable from `&dyn StegoMethod` with one call.
///
/// No downcast, no sizing probe, no separate trait the caller has to know to
/// ask for. That is the whole of F19: a surface holding a carrier as a trait
/// object could reach the raw figure and not the honest one.
#[test]
fn a_framed_capacity_is_reachable_from_a_dyn_stego_method() {
    let hg = Homoglyph::new();
    let method: &dyn StegoMethod = &hg;

    let framed = method
        .framed_capacity_bytes(EN_LONG)
        .expect("the long article can hold a frame");

    // The raw figure is what the carrier can place; the framed figure is what
    // survives the two preamble replicas and the resync markers.
    assert_eq!(method.capacity(EN_LONG) / 8, 141, "raw carrier figure");
    assert_eq!(framed, 73, "framed figure, SPEC_CORE_V2 §3.3");
    assert!(framed < 141, "the frame is not free");
}

/// Every carrier answers the question, and answers it in bytes.
#[test]
fn every_carrier_answers_the_framed_question_on_a_cover_that_can_hold_a_frame() {
    for (id, carrier) in carriers() {
        let framed = carrier
            .framed_capacity_bytes(EN_LONG)
            .unwrap_or_else(|e| panic!("{id} could not size the long article: {e}"));
        assert!(framed > 0, "{id} reports no room in the long article");
    }
}

/// A capacity that cannot be computed says so by name rather than returning
/// zero (invariant 2).
#[test]
fn a_capacity_that_cannot_be_computed_names_itself() {
    let hg = Homoglyph::new();

    // Cyrillic prose is full of this carrier's own alphabet, so written and
    // read positions would not line up. The carrier refuses and names itself.
    match hg.framed_capacity_bytes(CYRILLIC) {
        Err(SteganoError::EncodingFailed { method, reason }) => {
            assert_eq!(method, "homoglyph");
            assert!(reason.contains("alphabet"), "reason was: {reason}");
        }
        other => panic!("expected a named refusal, got {other:?}"),
    }

    // Japanese offers this carrier nothing at all. The arithmetic is reported
    // rather than a bare zero.
    match hg.framed_capacity_bytes(CJK) {
        Err(SteganoError::CapacityExceeded { needed, available }) => {
            assert!(needed > 0);
            assert_eq!(available, 0);
        }
        other => panic!("expected the arithmetic, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The measured gap this task was opened on
// ---------------------------------------------------------------------------

/// The light frame is what closes the gap: the same short cover that the heavy
/// frame left unusable now carries a real secret.
///
/// The raw carrier figure is fifty-seven bytes (down from sixty once code-region
/// exclusion, F23, stopped counting the letters inside the fenced shell command
/// this carrier must leave byte-identical). Under the heavy frame that 57 fell to
/// 5 after two preamble replicas and the markers, and the envelope took the last
/// of it: zero secret, nothing placeable. The light frame default (§3.2) spends
/// one 8-byte header instead, so the same cover carries a secret that places and
/// reads back, which is the whole reason it is the default for concealment.
#[test]
fn the_technical_markdown_gap_is_closed() {
    let hg = Homoglyph::new();
    let method: &dyn StegoMethod = &hg;

    assert_eq!(
        method.capacity(TECHNICAL_MD) / 8,
        57,
        "the raw carrier figure that was being reported"
    );
    // The heavy frame would leave almost nothing here; the pinned figure records
    // why it is not the default for a cover this short.
    assert_eq!(
        method.framed_capacity_bytes(TECHNICAL_MD).unwrap(),
        5,
        "what the heavy frame would leave after two preamble replicas and markers"
    );

    // The light frame default carries a real secret in the very same cover.
    let secret = pipeline::secret_capacity_bytes(TECHNICAL_MD, &[method], None).unwrap();
    assert!(
        secret > 0,
        "the light frame default must make this short cover usable"
    );

    let exact: Vec<u8> = (0..secret).map(|i| b'a' + (i % 26) as u8).collect();
    let placed = pipeline::encode(TECHNICAL_MD, &exact, &[method], None)
        .expect("the reported figure must place");
    let back = pipeline::decode(&placed.stego_text, &[method], &[], None)
        .expect("the placed secret must read back");
    assert_eq!(
        back.hidden_data, exact,
        "the light frame round-trips exactly the reported figure in this cover"
    );

    let one_more: Vec<u8> = (0..secret + 1).map(|i| b'a' + (i % 26) as u8).collect();
    assert!(
        pipeline::encode(TECHNICAL_MD, &one_more, &[method], None).is_err(),
        "one byte past the reported figure is refused by this bounded carrier"
    );
}

// ---------------------------------------------------------------------------
// The figure is the figure the engine accepts
// ---------------------------------------------------------------------------

/// Exactly the reported figure is placed and read back, and one byte more is
/// refused by every carrier the cover bounds. Every document, every carrier.
///
/// The flag is not an escape hatch. A carrier that creates the positions it
/// writes has no boundary the cover can state, and saying it does would be the
/// same kind of untrue figure this suite exists to end, pointing the other way.
/// What is required of such a carrier is that it says so, and that the figure
/// it does report is placeable and readable. Both are checked here.
#[test]
fn the_reported_secret_capacity_is_the_boundary_the_engine_holds() {
    for (doc, cover) in corpus() {
        for (id, carrier) in carriers() {
            let method = carrier.as_ref();
            let Ok(report) = pipeline::capacity(cover, &[method], None) else {
                // A carrier that cannot size this cover must also refuse to
                // place in it, for the same reason and by name.
                assert!(
                    pipeline::encode(cover, b"x", &[method], None).is_err(),
                    "{doc}/{id}: could not size this cover and placed in it anyway"
                );
                continue;
            };
            let bounded = report.carriers[0].cover_bounds_writes;
            let fits = report.secret_bytes;

            if fits == 0 {
                let one_byte = pipeline::encode(cover, b"x", &[method], None);
                if bounded {
                    assert!(
                        one_byte.is_err(),
                        "{doc}/{id}: reports no room, holds itself to it, and took a byte anyway"
                    );
                } else {
                    assert!(
                        one_byte.is_ok(),
                        "{doc}/{id}: reports that the cover does not bound it, then refused a \
                         single byte. One of the two statements is wrong."
                    );
                }
                continue;
            }

            let exact: Vec<u8> = (0..fits).map(|i| b'a' + (i % 26) as u8).collect();
            let placed = pipeline::encode(cover, &exact, &[method], None)
                .unwrap_or_else(|e| panic!("{doc}/{id}: reported {fits} bytes, refused them: {e}"));
            let back = pipeline::decode(&placed.stego_text, &[method], &[], None)
                .unwrap_or_else(|e| {
                    panic!("{doc}/{id}: placed {fits} bytes and could not read them: {e}")
                });
            assert_eq!(back.hidden_data, exact, "{doc}/{id}");

            let one_more: Vec<u8> = (0..fits + 1).map(|i| b'a' + (i % 26) as u8).collect();
            let past_it = pipeline::encode(cover, &one_more, &[method], None);
            if bounded {
                assert!(
                    past_it.is_err(),
                    "{doc}/{id}: reported {fits} bytes as a limit and accepted {}",
                    fits + 1
                );
            } else {
                assert!(
                    past_it.is_ok(),
                    "{doc}/{id}: reported that the cover does not bound it, then refused {} \
                     bytes. One of the two statements is wrong.",
                    fits + 1
                );
            }
        }
    }
}

/// Which carriers the cover bounds is measured, not assumed, and the answer is
/// the same on every document.
///
/// Three of the four hold themselves to the slots the cover offers. Zero-width
/// inserts one character per bit and appends whatever is left over, so the
/// cover bounds nothing for it. Pinned because the whole capacity contract
/// turns on it: change a carrier's placement routine and this says so.
#[test]
fn the_carriers_the_cover_bounds_are_the_ones_that_refuse_a_bit_too_many() {
    use stegano_core::format::cover_bounds_writes;

    for (doc, cover) in corpus() {
        for (id, carrier) in carriers() {
            let bounded = cover_bounds_writes(carrier.as_ref(), cover);

            // A cover the carrier refuses outright bounds it at nothing, which
            // is a bound like any other and is reported as one.
            let refused = matches!(
                carrier.framed_capacity_bytes(cover),
                Err(SteganoError::EncodingFailed { .. })
            );
            let expected = refused || id != "zero_width";

            assert_eq!(
                bounded, expected,
                "{doc}/{id}: cover_bounds_writes said {bounded}"
            );
        }
    }
}

/// The secret figure is the framed figure with the envelope deducted, and the
/// deduction is stated rather than folded in.
#[test]
fn the_report_states_where_every_deducted_byte_went() {
    for (doc, cover) in corpus() {
        for (id, carrier) in carriers() {
            let method = carrier.as_ref();
            let Ok(estimate) = pipeline::capacity(cover, &[method], None) else {
                continue;
            };
            let carrier_estimate = &estimate.carriers[0];

            assert_eq!(carrier_estimate.carrier, id, "{doc}");
            assert_eq!(
                carrier_estimate.framed_bytes,
                // The report deducts the light frame's header (§3.2), the frame
                // the engine actually writes by default, from the carrier's own
                // positions. `framed_capacity_bytes` is the heavy primitive and
                // reports the other frame; the two are not the same figure, and
                // the report is the one the engine holds itself to.
                frame_light::payload_capacity_bytes(method.positions(cover), false),
                "{doc}/{id}: the report and the carrier disagree"
            );
            assert_eq!(
                carrier_estimate.secret_bytes + carrier_estimate.overhead_bytes,
                carrier_estimate.framed_bytes,
                "{doc}/{id}: the deduction does not add up"
            );
            assert_eq!(estimate.secret_bytes, carrier_estimate.secret_bytes, "{doc}");
        }
    }
}

/// A cipher costs bytes, and the reported figure has already paid them.
#[test]
fn a_protected_secret_is_sized_with_its_cipher_included() {
    use stegano_core::crypto::Aes256;
    use stegano_core::traits::CryptoMethod;

    let hg = Homoglyph::new();
    let method: &dyn StegoMethod = &hg;
    let cipher = Aes256::new();
    let crypto: (&dyn CryptoMethod, &str) = (&cipher, "a passcode that never reaches a log");

    let plain = pipeline::secret_capacity_bytes(EN_LONG, &[method], None).unwrap();
    let sealed = pipeline::secret_capacity_bytes(EN_LONG, &[method], Some(crypto)).unwrap();
    assert!(
        sealed < plain,
        "a cipher expands its input, so it must cost capacity: {sealed} against {plain}"
    );

    let exact: Vec<u8> = (0..sealed).map(|i| b'a' + (i % 26) as u8).collect();
    let placed = pipeline::encode(EN_LONG, &exact, &[method], Some(crypto))
        .unwrap_or_else(|e| panic!("reported {sealed} protected bytes and refused them: {e}"));
    let back = pipeline::decode(
        &placed.stego_text,
        &[method],
        &[&cipher],
        Some("a passcode that never reaches a log"),
    )
    .unwrap();
    assert_eq!(back.hidden_data, exact);

    let one_more: Vec<u8> = (0..sealed + 1).map(|i| b'a' + (i % 26) as u8).collect();
    assert!(
        pipeline::encode(EN_LONG, &one_more, &[method], Some(crypto)).is_err(),
        "reported {sealed} protected bytes and accepted {}",
        sealed + 1
    );
}
