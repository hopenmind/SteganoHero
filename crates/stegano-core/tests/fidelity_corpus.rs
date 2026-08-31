//! Fidelity of a marked document against its cover, measured on the corpus.
//!
//! Invariant 4b: a marked text must look like its cover. `cover_restored` proves
//! stripping returns the original, which is necessary and not sufficient. A
//! document can strip back perfectly while wrapping at different points,
//! selecting wrongly on double click, or displaying reordered text. This suite
//! measures those.
//!
//! The corpus lives in `tests/corpus/` at the workspace root and its
//! `README.md` states what each document is designed to break.

use stegano_core::fidelity::{self, AuditExposure, CheckVerdict, FidelityOptions};
use stegano_core::format::{Mission, PositionChannel};
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

/// Channel slots a carrier offers on this cover.
///
/// Sizing from `positions()` rather than `capacity()` on purpose. The two now
/// agree in unit for every carrier: backlog F25 removed `ZeroWidth::capacity`,
/// which used to return `visible_chars * 8`, so the trait default reports one
/// payload bit per position like the other three. `positions()` is the figure
/// the frame is laid over, so sizing from it measures the document rather than
/// any carrier's overflow tail.
fn positions_of(carrier_id: &str, cover: &str) -> usize {
    match carrier_id {
        "zero_width" => ZeroWidth::new().positions(cover),
        "whitespace_var" => WhitespaceVar::new().positions(cover),
        "bidi" => Bidi::new().positions(cover),
        "homoglyph" => Homoglyph::new().positions(cover),
        other => panic!("unknown carrier {other}"),
    }
}

/// A payload sized to the mission fill ratio, so the sweep exercises what the
/// tool would actually write rather than a token byte.
fn payload_for(carrier_id: &str, cover: &str, ratio: f64) -> Vec<u8> {
    let bytes = ((positions_of(carrier_id, cover) as f64 * ratio) / 8.0).floor() as usize;
    (0..bytes.max(1)).map(|i| (i * 37 % 251) as u8).collect()
}

/// Insert `ch` before each named cover character index.
fn insert_before(cover: &str, positions: &[usize], ch: char) -> String {
    let mut out = String::new();
    for (i, c) in cover.chars().enumerate() {
        if positions.contains(&i) {
            out.push(ch);
        }
        out.push(c);
    }
    out
}

// ---------------------------------------------------------------------------
// The contract: no silent degradation
// ---------------------------------------------------------------------------

/// A document identical to its cover is the only case that may report clean
/// across the board, and it must.
#[test]
fn an_unmodified_document_is_clean_on_every_check() {
    let report = fidelity::assess(EN_LONG, EN_LONG, &FidelityOptions::default());

    assert_eq!(report.reflow.verdict, CheckVerdict::Clean);
    assert_eq!(report.bidi_balance.verdict, CheckVerdict::Clean);
    assert_eq!(report.word_selection.verdict, CheckVerdict::Clean);
    assert_eq!(report.distribution.verdict, CheckVerdict::Clean);
    assert_eq!(report.density.verdict, CheckVerdict::Clean);
    assert_eq!(report.paste_safety.verdict, CheckVerdict::Clean);
    assert_eq!(report.overall.human_reader_verdict, CheckVerdict::Clean);
    assert_eq!(report.overall.human_reader_risk, 0.0);
    assert!(report.overall.checks_not_run.is_empty());
    assert_eq!(report.overall.analyst_exposure, AuditExposure::NotExposed);
}

/// A check that cannot run says so. It never returns a passing verdict by
/// default, and the overall verdict never reads clean while one is missing.
#[test]
fn a_check_that_cannot_run_says_so_and_never_passes() {
    // Two unrelated texts: the alignment walk cannot pair them, so every check
    // that reads insertions and substitutions has nothing to measure.
    let report = fidelity::assess(
        "The quick brown fox jumps over the lazy dog",
        "Entirely different prose with no relation to the cover at all",
        &FidelityOptions::default(),
    );

    assert!(report.alignment.failure.is_some(), "alignment should refuse");
    assert!(
        !report.overall.checks_not_run.is_empty(),
        "at least one check must report that it could not run"
    );
    assert!(
        matches!(
            report.overall.human_reader_verdict,
            CheckVerdict::Indeterminate { .. }
        ),
        "overall verdict was {:?}",
        report.overall.human_reader_verdict
    );
    assert_ne!(report.overall.analyst_exposure, AuditExposure::NotExposed);

    for check in [
        report.word_selection.verdict.clone(),
        report.distribution.verdict.clone(),
    ] {
        assert!(
            matches!(check, CheckVerdict::Indeterminate { .. }),
            "an alignment dependent check reported {check:?} on an unalignable pair"
        );
    }
}

// ---------------------------------------------------------------------------
// Check 1: reflow
// ---------------------------------------------------------------------------

/// U+2060 suppresses a line break. Placed beside a space it removes the wrap
/// opportunity that space offered.
#[test]
fn a_word_joiner_removes_a_wrap_opportunity() {
    let cover = "alpha beta gamma delta epsilon";
    // Cover index 6 is the 'b' of beta, so the joiner lands between the space
    // and the word.
    let marked = insert_before(cover, &[6], '\u{2060}');

    let report = fidelity::assess(cover, &marked, &FidelityOptions::default());
    assert!(
        report.reflow.opportunities_lost >= 1,
        "expected a lost break opportunity, got {:?}",
        report.reflow
    );
    assert_ne!(report.reflow.verdict, CheckVerdict::Clean);
}

/// U+200B creates a line break opportunity where none existed, which lets a
/// renderer wrap inside a word.
#[test]
fn a_zero_width_space_creates_a_wrap_opportunity_inside_a_word() {
    let cover = "internationalisation";
    let marked = insert_before(cover, &[5], '\u{200B}');

    let report = fidelity::assess(cover, &marked, &FidelityOptions::default());
    assert!(
        report.reflow.opportunities_gained >= 1,
        "expected a gained break opportunity, got {:?}",
        report.reflow
    );
}

/// The report names the wrap points that moved, not only how many.
#[test]
fn a_moved_wrap_point_is_reported_with_the_word_it_now_breaks_after() {
    let cover = "the board reviewed the operations of the northern division this quarter";
    let mut options = FidelityOptions::default();
    options.wrap_width = 24;

    // A joiner in front of "operations" glues it to the preceding space, so the
    // line that used to break there has to break earlier.
    let at = cover.find("operations").unwrap();
    let marked = insert_before(cover, &[at], '\u{2060}');

    let report = fidelity::assess(cover, &marked, &options);
    assert!(
        report.reflow.moved_breaks_total >= 1,
        "expected a moved break, got {:?}",
        report.reflow
    );
    let first = &report.reflow.moved_breaks[0];
    assert_ne!(first.cover_break_after, first.marked_break_after);
    assert!(
        !first.cover_break_after.is_empty(),
        "a moved break must name the word it used to follow"
    );
}

// ---------------------------------------------------------------------------
// Check 2: bidi balance
// ---------------------------------------------------------------------------

/// An unclosed embedding reorders visible text. It is reported by position and
/// it is the most conspicuous failure available.
#[test]
fn an_unclosed_embedding_is_reported_by_position() {
    let cover = "the quarterly report is attached for review";
    let marked = insert_before(cover, &[4], '\u{202B}'); // RLE, never popped

    let report = fidelity::assess(cover, &marked, &FidelityOptions::default());
    assert_eq!(report.bidi_balance.unclosed_initiators.len(), 1);
    assert_eq!(report.bidi_balance.unclosed_initiators[0].cover_index, 4);
    assert_eq!(
        report.bidi_balance.unclosed_initiators[0].codepoint,
        "U+202B"
    );
    assert_eq!(report.bidi_balance.verdict, CheckVerdict::Conspicuous);
    assert_eq!(report.overall.human_reader_risk, 1.0);
}

/// A terminator with no opener is unbalanced too, and reported separately: the
/// bidi algorithm ignores it, so it does not reorder anything on its own.
#[test]
fn an_orphan_terminator_is_reported_separately_from_an_unclosed_opener() {
    let cover = "the quarterly report is attached for review";
    let marked = insert_before(cover, &[4], '\u{202C}'); // PDF with no opener

    let report = fidelity::assess(cover, &marked, &FidelityOptions::default());
    assert!(report.bidi_balance.unclosed_initiators.is_empty());
    assert_eq!(report.bidi_balance.orphan_terminators.len(), 1);
    assert_eq!(report.bidi_balance.orphan_terminators[0].cover_index, 4);
    assert_ne!(report.bidi_balance.verdict, CheckVerdict::Clean);
    assert!(
        report.overall.human_reader_risk < 1.0,
        "an orphan terminator must not score as high as an unclosed opener"
    );
}

/// A balanced pair is balanced, whatever else it does.
#[test]
fn a_closed_embedding_is_balanced() {
    let cover = "the quarterly report is attached for review";
    // Opener at cover index 4, its matching terminator at cover index 20.
    let marked: String = {
        let mut out = String::new();
        for (i, c) in cover.chars().enumerate() {
            if i == 4 {
                out.push('\u{202B}');
            }
            if i == 20 {
                out.push('\u{202C}');
            }
            out.push(c);
        }
        out
    };

    let report = fidelity::assess(cover, &marked, &FidelityOptions::default());
    assert!(report.bidi_balance.unclosed_initiators.is_empty());
    assert!(report.bidi_balance.orphan_terminators.is_empty());
}

// ---------------------------------------------------------------------------
// Check 3: word selection
// ---------------------------------------------------------------------------

/// A double click must still select the same word. A channel character inside a
/// word breaks that in most editors, and the report names the word.
#[test]
fn a_channel_character_inside_a_word_is_named_with_its_word() {
    let cover = "the board reviewed the operations of the division";
    let at = cover.find("operations").unwrap() + 4;
    let marked = insert_before(cover, &[at], '\u{200C}');

    let report = fidelity::assess(cover, &marked, &FidelityOptions::default());
    assert_eq!(report.word_selection.words_with_interior_channel_char, 1);
    assert_eq!(report.word_selection.interior_insertions, 1);
    assert_eq!(report.word_selection.boundary_insertions, 0);
    assert_eq!(report.word_selection.broken_words[0].word, "operations");
    assert_ne!(report.word_selection.verdict, CheckVerdict::Clean);
}

/// A channel character at a word boundary leaves selection intact.
#[test]
fn a_channel_character_at_a_word_boundary_leaves_selection_intact() {
    let cover = "the board reviewed the operations of the division";
    let at = cover.find(" operations").unwrap();
    let marked = insert_before(cover, &[at], '\u{200C}');

    let report = fidelity::assess(cover, &marked, &FidelityOptions::default());
    assert_eq!(report.word_selection.words_with_interior_channel_char, 0);
    assert_eq!(report.word_selection.boundary_insertions, 1);
    assert_eq!(report.word_selection.verdict, CheckVerdict::Clean);
}

/// A homoglyph substitution keeps double click selection, and breaks find in
/// page and spell check instead. Both are visible to a reader, so both are
/// reported rather than one standing in for the other.
#[test]
fn a_homoglyph_substitution_is_reported_as_a_mixed_script_word() {
    let cover = "the board reviewed the operations of the division";
    let marked = cover.replacen('o', "\u{043E}", 1);

    let report = fidelity::assess(cover, &marked, &FidelityOptions::default());
    assert_eq!(report.word_selection.words_with_interior_channel_char, 0);
    assert_eq!(report.word_selection.words_with_mixed_script, 1);
    assert_eq!(report.word_selection.mixed_script_words[0].word, "board");
    assert_ne!(report.word_selection.verdict, CheckVerdict::Clean);
}

// ---------------------------------------------------------------------------
// Check 4: distribution evenness
// ---------------------------------------------------------------------------

/// Marks packed into the head of the document fail the uniformity test, and the
/// report names the window they are packed into.
#[test]
fn marks_concentrated_in_the_head_fail_the_uniformity_test() {
    let cover: String = "abcdefghij ".chars().cycle().take(1100).collect();
    let positions: Vec<usize> = (0..100).collect();
    let marked = insert_before(&cover, &positions, '\u{200C}');

    let report = fidelity::assess(&cover, &marked, &FidelityOptions::default());
    assert_eq!(report.distribution.marks, 100);
    assert!(
        report.distribution.ks_statistic > report.distribution.ks_critical_5pct,
        "ks {} should exceed critical {}",
        report.distribution.ks_statistic,
        report.distribution.ks_critical_5pct
    );
    assert!(!report.distribution.uniform_at_5pct);
    assert_ne!(report.distribution.verdict, CheckVerdict::Clean);
    let window = report
        .distribution
        .densest_window
        .as_ref()
        .expect("a concentrated document must name its densest window");
    assert!(window.start < 200, "densest window should sit in the head");
}

/// Marks spread evenly pass it.
#[test]
fn marks_spread_evenly_pass_the_uniformity_test() {
    let cover: String = "abcdefghij ".chars().cycle().take(1100).collect();
    let positions: Vec<usize> = (0..100).map(|i| i * 11 + 5).collect();
    let marked = insert_before(&cover, &positions, '\u{200C}');

    let report = fidelity::assess(&cover, &marked, &FidelityOptions::default());
    assert_eq!(report.distribution.marks, 100);
    assert!(
        report.distribution.uniform_at_5pct,
        "ks {} against critical {}",
        report.distribution.ks_statistic,
        report.distribution.ks_critical_5pct
    );
    assert_eq!(report.distribution.verdict, CheckVerdict::Clean);
}

// ---------------------------------------------------------------------------
// Check 5: density against the mission ceiling
// ---------------------------------------------------------------------------

#[test]
fn density_is_measured_against_the_mission_ceiling() {
    let cover: String = "abcdefghij ".chars().cycle().take(1000).collect();
    let positions: Vec<usize> = (0..400).map(|i| i * 2).collect();
    let marked = insert_before(&cover, &positions, '\u{200C}');

    let conceal = fidelity::assess(
        &cover,
        &marked,
        &FidelityOptions::for_mission(Mission::Conceal),
    );
    assert_eq!(conceal.density.ceiling, 0.25);
    assert!((conceal.density.fill_ratio - 0.40).abs() < 0.001);
    assert!(!conceal.density.clears_ceiling);
    assert_ne!(conceal.density.verdict, CheckVerdict::Clean);

    let sign = fidelity::assess(&cover, &marked, &FidelityOptions::for_mission(Mission::Sign));
    assert_eq!(sign.density.ceiling, 0.50);
    assert!(sign.density.clears_ceiling);

    let mark = fidelity::assess(&cover, &marked, &FidelityOptions::for_mission(Mission::Mark));
    assert_eq!(mark.density.ceiling, 0.85);
    assert!(mark.density.clears_ceiling);
}

// ---------------------------------------------------------------------------
// Check 6: codepoint audit exposure
// ---------------------------------------------------------------------------

/// forensic.rs raises a script mix as soon as Latin and Cyrillic coexist with
/// non zero homoglyph density. One substitution is enough to be flagged.
#[test]
fn one_substitution_is_enough_to_be_flagged_by_a_codepoint_audit() {
    let cover = "the board reviewed the operations of the division";
    let marked = cover.replacen('o', "\u{043E}", 1);

    let report = fidelity::assess(cover, &marked, &FidelityOptions::default());
    assert_eq!(report.codepoint_audit.exposure, AuditExposure::Exposed);
    assert!(report.codepoint_audit.script_mix_fires);
    assert_eq!(report.overall.analyst_exposure, AuditExposure::Exposed);
    assert_eq!(report.codepoint_audit.added_codepoints[0].codepoint, "U+043E");
}

/// The two axes are separate. Surviving a reader is not surviving an analyst,
/// and the report says which is which rather than letting one stand for both.
#[test]
fn human_reader_and_analyst_exposure_are_separate_fields() {
    let cover: String = "the board reviewed the operations "
        .chars()
        .cycle()
        .take(600)
        .collect();
    // One substitution, invisible to a reader, fatal to a codepoint audit.
    let marked = cover.replacen('o', "\u{043E}", 1);

    let report = fidelity::assess(&cover, &marked, &FidelityOptions::default());
    assert_eq!(report.overall.analyst_exposure, AuditExposure::Exposed);
    assert!(
        report.overall.human_reader_risk < 0.5,
        "a single substitution is not a reader visible defect, risk was {}",
        report.overall.human_reader_risk
    );
    assert!(
        !report.overall.scope.is_empty(),
        "the report must state the scope of its own verdict"
    );
}

// ---------------------------------------------------------------------------
// Check 7: paste safety, backlog F9
// ---------------------------------------------------------------------------

/// A channel character inside a fenced code block corrupts a command someone
/// will paste into a shell.
#[test]
fn a_channel_character_inside_a_code_fence_is_reported() {
    let cover = "Run this:\n\n```sh\ncargo test --workspace\n```\n\nThen check the output.\n";
    let at = cover.find("--workspace").unwrap() + 2;
    let marked = insert_before(cover, &[at], '\u{200B}');

    let report = fidelity::assess(cover, &marked, &FidelityOptions::default());
    assert_eq!(report.paste_safety.code_regions, 1);
    assert_eq!(report.paste_safety.marks_inside_code, 1);
    assert_eq!(report.paste_safety.verdict, CheckVerdict::Conspicuous);
    assert!(report.paste_safety.sites[0].excerpt.contains("cargo"));
}

#[test]
fn prose_with_no_code_regions_reports_a_clean_paste_verdict() {
    let cover = "A plain paragraph with no code in it whatsoever.";
    let marked = insert_before(cover, &[5], '\u{200B}');

    let report = fidelity::assess(cover, &marked, &FidelityOptions::default());
    assert_eq!(report.paste_safety.code_regions, 0);
    assert_eq!(report.paste_safety.marks_inside_code, 0);
    assert_eq!(report.paste_safety.verdict, CheckVerdict::Clean);
}

// ---------------------------------------------------------------------------
// Baseline fidelity of a document that already carries
// ---------------------------------------------------------------------------

/// `already_carrying.txt` holds U+2060 and U+FEFF before anything is added, so
/// its fidelity against its own stripped form is imperfect from the start.
#[test]
fn already_carrying_has_an_imperfect_baseline_before_anything_is_added() {
    let report = fidelity::baseline(ALREADY_CARRYING, &FidelityOptions::default());

    assert_eq!(
        report.alignment.insertions.len(),
        4,
        "the document declares four pre existing invisibles"
    );
    let found: Vec<&str> = report
        .codepoint_audit
        .added_codepoints
        .iter()
        .map(|c| c.codepoint.as_str())
        .collect();
    for expected in ["U+200B", "U+200C", "U+2060", "U+FEFF"] {
        assert!(found.contains(&expected), "{expected} missing from {found:?}");
    }
    assert!(
        report.overall.human_reader_risk > 0.0,
        "a document carrying a zero width space has a non zero baseline risk"
    );
    // The U+200B after "meeting" is a break opportunity the clean text does not
    // offer, so this document can already wrap where its cover would not.
    assert!(
        report.reflow.opportunities_gained >= 1,
        "expected the pre existing U+200B to add a wrap opportunity, got {:?}",
        report.reflow
    );

    // A document that carries nothing has a spotless baseline, which is what
    // makes the figure above meaningful.
    let clean = fidelity::baseline(EN_LONG, &FidelityOptions::default());
    assert_eq!(clean.overall.human_reader_risk, 0.0);
    assert_eq!(clean.overall.human_reader_verdict, CheckVerdict::Clean);
}

// ---------------------------------------------------------------------------
// The corpus sweep
// ---------------------------------------------------------------------------

/// Every carrier on every corpus document produces a verdict, and no check ever
/// falls back to a pass. A check that cannot run names itself with a reason and
/// appears in `checks_not_run`; a carrier that refuses is recorded as a refusal.
#[test]
fn every_carrier_on_every_corpus_document_produces_a_named_verdict() {
    let mut assessed = 0usize;
    let mut refused = 0usize;

    for (name, cover) in corpus() {
        for (carrier_id, carrier) in carriers() {
            let payload = payload_for(carrier_id, cover, 0.50);
            let marked = match carrier.encode(cover, &payload) {
                Ok(text) => text,
                Err(_) => {
                    refused += 1;
                    continue;
                }
            };

            let report =
                fidelity::assess(cover, &marked, &FidelityOptions::for_mission(Mission::Sign));
            assessed += 1;

            assert!(
                report.alignment.failure.is_none(),
                "{name} with {carrier_id}: alignment failed with {:?}",
                report.alignment.failure
            );

            for (check, verdict) in report.verdicts() {
                if let CheckVerdict::Indeterminate { reason } = &verdict {
                    assert!(
                        !reason.trim().is_empty(),
                        "{name} with {carrier_id}: {check} could not run and gave no reason"
                    );
                    assert!(
                        report.overall.checks_not_run.contains(&check),
                        "{name} with {carrier_id}: {check} could not run and was not listed"
                    );
                }
            }

            if !report.overall.checks_not_run.is_empty() {
                assert!(
                    matches!(
                        report.overall.human_reader_verdict,
                        CheckVerdict::Indeterminate { .. }
                    ),
                    "{name} with {carrier_id}: an incomplete report claimed a firm verdict"
                );
            }
        }
    }

    assert!(assessed >= 20, "only {assessed} pairs were assessable");
    assert!(refused >= 1, "the tiny documents must refuse at least once");
}

/// The insertion carriers now place every channel character at a word boundary,
/// so none breaks double-click selection (backlog F22). This is the placement
/// fix, held to zero on the corpus documents richest in words.
#[test]
fn insertion_carriers_place_only_at_word_boundaries_across_the_corpus() {
    for (name, cover) in [("en_long_article.txt", EN_LONG), ("fr_accented.txt", FR_ACCENTED)] {
        for (carrier_id, carrier) in carriers() {
            if carrier_id == "homoglyph" {
                continue;
            }
            let payload = payload_for(carrier_id, cover, 0.50);
            let marked = carrier.encode(cover, &payload).unwrap();
            let report =
                fidelity::assess(cover, &marked, &FidelityOptions::for_mission(Mission::Sign));

            assert_eq!(
                report.word_selection.words_with_interior_channel_char, 0,
                "{name} with {carrier_id} still put a channel character inside a word"
            );
            assert_eq!(
                report.word_selection.interior_insertions, 0,
                "{name} with {carrier_id}: {} channel characters landed inside a word",
                report.word_selection.interior_insertions
            );
            assert!(
                report.word_selection.boundary_insertions > 0,
                "{name} with {carrier_id} placed nothing at all"
            );
            assert_eq!(
                report.word_selection.verdict,
                CheckVerdict::Clean,
                "{name} with {carrier_id}"
            );
        }
    }
}

/// The measured table, printed with `-- --nocapture`.
///
/// It is a test rather than a script so the figures cannot drift away from the
/// code that produces them. The assertions at the end are the findings the
/// table is evidence for.
#[test]
fn the_corpus_fidelity_table() {
    println!(
        "\n{:<24} {:<15} {:>6} {:>6}  {:>4} {:>4} {:>5}  {:>3} {:>4}  {:>5} {:>5}  {:>6} {:>6}  {:>4}  {:>5}  {}",
        "document",
        "carrier",
        "marks",
        "fill",
        "gain",
        "lost",
        "moved",
        "unc",
        "orph",
        "brknW",
        "totW",
        "inside",
        "bound",
        "code",
        "ks",
        "reader verdict"
    );

    let mut interior_total = 0usize;
    let mut boundary_total = 0usize;
    let mut code_hits = 0usize;

    for (name, cover) in corpus() {
        for (carrier_id, carrier) in carriers() {
            let payload = payload_for(carrier_id, cover, 0.50);
            let marked = match carrier.encode(cover, &payload) {
                Ok(text) => text,
                Err(error) => {
                    println!("{name:<24} {carrier_id:<15} refused: {error}");
                    continue;
                }
            };
            let report =
                fidelity::assess(cover, &marked, &FidelityOptions::for_mission(Mission::Sign));

            interior_total += report.word_selection.interior_insertions;
            boundary_total += report.word_selection.boundary_insertions;
            code_hits += report.paste_safety.marks_inside_code;

            println!(
                "{:<24} {:<15} {:>6} {:>5.1}%  {:>4} {:>4} {:>5}  {:>3} {:>4}  {:>5} {:>5}  {:>6} {:>6}  {:>4}  {:>5.2}  {} ({:.2})",
                name,
                carrier_id,
                report.alignment.marks(),
                report.density.fill_ratio * 100.0,
                report.reflow.opportunities_gained,
                report.reflow.opportunities_lost,
                report.reflow.moved_breaks_total,
                report.bidi_balance.added_unclosed_initiators,
                report.bidi_balance.added_orphan_terminators,
                report.word_selection.words_with_interior_channel_char,
                report.word_selection.words_total,
                report.word_selection.interior_insertions,
                report.word_selection.boundary_insertions,
                report.paste_safety.marks_inside_code,
                report.distribution.ks_statistic,
                report.overall.human_reader_verdict,
                report.overall.human_reader_risk,
            );
        }
    }

    println!(
        "\ninterior insertions across the corpus: {interior_total}, at boundaries: {boundary_total}, \
         inside code: {code_hits}"
    );

    // The placement fix, stated as the measurement. F22 moved every insertion to
    // a word boundary, so not one channel character across the whole corpus now
    // lands between two letters of a word; every insertion that lands, lands at a
    // boundary. F23 moved every mark clear of machine input, so nothing lands in
    // a fenced block or an inline span.
    assert_eq!(
        interior_total, 0,
        "{interior_total} channel characters still land inside a word after F22"
    );
    assert!(
        boundary_total > 0,
        "the carriers must still place marks, all of them at boundaries"
    );
    assert_eq!(
        code_hits, 0,
        "technical_markdown.md still shows {code_hits} marks landing in machine input after F23"
    );
}

/// The worst finding the corpus produced, pinned as closed.
///
/// A homoglyph substituted inside a fenced shell command was the only defect
/// measured here that a reader could not see at all and that still destroyed
/// what the document is for: a Cyrillic letter inside `systemctl` renders,
/// selects and copies like `systemctl`, then fails in the shell with a message
/// about a command nobody typed. Code-region exclusion (F23) stops it: every
/// carrier now leaves the fenced commands byte-identical, so nothing lands in
/// machine input at all.
#[test]
fn a_substitution_never_lands_inside_a_shell_command() {
    let carrier = Homoglyph::new();
    let payload = payload_for("homoglyph", TECHNICAL_MD, 0.50);
    let marked = carrier.encode(TECHNICAL_MD, &payload).unwrap();
    let report = fidelity::assess(
        TECHNICAL_MD,
        &marked,
        &FidelityOptions::for_mission(Mission::Sign),
    );

    assert_eq!(
        report.paste_safety.marks_inside_code, 0,
        "a mark still landed in a fenced command: {:?}",
        report.paste_safety.sites
    );
    assert_eq!(report.paste_safety.verdict, CheckVerdict::Clean);

    // The commands a reader will paste survive byte for byte.
    assert!(
        marked.contains("systemctl status app.service"),
        "the first fenced command was altered"
    );
    assert!(
        marked.contains("curl -sf http://127.0.0.1:8787/health"),
        "the second fenced command was altered"
    );

    // The substitution still happened, only in the prose around the fence.
    assert_ne!(marked, TECHNICAL_MD, "the carrier must still have marked the document");
}

/// The homoglyph carrier is invisible to a reader in the sense that matters for
/// selection, and exposed to a codepoint audit on the first substitution.
#[test]
fn the_homoglyph_carrier_is_reader_quiet_and_audit_exposed() {
    let carrier = Homoglyph::new();
    let payload = payload_for("homoglyph", EN_LONG, 0.50);
    let marked = carrier.encode(EN_LONG, &payload).unwrap();

    let report = fidelity::assess(
        EN_LONG,
        &marked,
        &FidelityOptions::for_mission(Mission::Sign),
    );

    assert_eq!(report.word_selection.interior_insertions, 0);
    assert_eq!(report.reflow.moved_breaks_total, 0);
    assert_eq!(report.bidi_balance.unclosed_initiators.len(), 0);
    assert_eq!(report.codepoint_audit.exposure, AuditExposure::Exposed);
}
