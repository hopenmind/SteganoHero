//! Document sovereignty over the test corpus (backlog AR-1).
//!
//! Inspect must report the marks on every corpus document, clean must remove
//! the chosen classes and leave the rest byte-identical, and a document with
//! nothing of a class must come back unaltered. The corpus lives in
//! `tests/corpus/` at the workspace root; its `README.md` states what each
//! document is designed to break, including the destructive-strip trap that
//! legitimate Russian must survive.

use stegano_core::sovereignty::{clean, inspect, CleanReport, InspectionReport, MarkClass};
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

/// The eight documents the corpus ships unmarked. `already_carrying.txt` is the
/// only one holding channel characters before any encoding.
fn unmarked_corpus() -> Vec<(&'static str, &'static str)> {
    corpus()
        .into_iter()
        .filter(|(name, _)| *name != "already_carrying.txt")
        .collect()
}

fn class_count(report: &InspectionReport, id: &str) -> usize {
    report
        .classes
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("class {id} must be present"))
        .count
}

fn removed_count(report: &CleanReport, id: &str) -> usize {
    report
        .removed
        .iter()
        .find(|r| r.id == id)
        .map(|r| r.count)
        .unwrap_or(0)
}

fn carrier_for(class: MarkClass) -> Box<dyn StegoMethod> {
    match class {
        MarkClass::ZeroWidth => Box::new(ZeroWidth::new()),
        MarkClass::Homoglyph => Box::new(Homoglyph::new()),
        MarkClass::Bidi => Box::new(Bidi::new()),
        MarkClass::WhitespaceVariation => Box::new(WhitespaceVar::new()),
    }
}

// ---------------------------------------------------------------------------
// Inspect
// ---------------------------------------------------------------------------

#[test]
fn inspect_reports_a_structured_answer_for_every_corpus_document() {
    for (name, text) in corpus() {
        let report = inspect(text);
        assert_eq!(
            report.total_chars,
            text.chars().count(),
            "{name}: character count mismatch"
        );
        assert_eq!(report.classes.len(), 4, "{name}: all four classes listed");
        assert!(
            report.classes.iter().all(|c| c.cleanable),
            "{name}: every listed class is cleanable"
        );
        assert!(!report.summary.is_empty(), "{name}: a summary is produced");
    }
}

#[test]
fn every_unmarked_document_has_no_owned_marks() {
    for (name, text) in unmarked_corpus() {
        let report = inspect(text);
        let total: usize = report.classes.iter().map(|c| c.count).sum();
        assert_eq!(total, 0, "{name}: expected no owned marks, report says {total}");
    }
}

#[test]
fn already_carrying_reports_four_marks_across_two_classes() {
    let report = inspect(ALREADY_CARRYING);
    assert_eq!(class_count(&report, "zero_width"), 2);
    assert_eq!(class_count(&report, "whitespace_var"), 2);
    assert_eq!(class_count(&report, "bidi"), 0);
    assert_eq!(class_count(&report, "homoglyph"), 0);
    assert_eq!(report.invisible_chars, 4);
}

#[test]
fn legitimate_cyrillic_is_never_reported_as_a_homoglyph_payload() {
    let report = inspect(CYRILLIC);
    assert_eq!(class_count(&report, "homoglyph"), 0);
    assert!(report
        .carrier_signatures
        .iter()
        .all(|s| !s.carries_readable_payload));
}

#[test]
fn inspect_and_clean_agree_on_every_class_for_every_document() {
    for (name, text) in corpus() {
        let inspected = inspect(text);
        for class in MarkClass::ALL {
            let cleaned = clean(text, &[class]);
            assert_eq!(
                class_count(&inspected, class.id()),
                removed_count(&cleaned, class.id()),
                "{name}: inspect and clean disagree on {}",
                class.id()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Clean
// ---------------------------------------------------------------------------

#[test]
fn cleaning_an_absent_class_leaves_the_document_byte_identical() {
    for (name, text) in corpus() {
        let inspected = inspect(text);
        for class in MarkClass::ALL {
            if class_count(&inspected, class.id()) != 0 {
                continue;
            }
            let report = clean(text, &[class]);
            assert_eq!(
                report.cleaned_text, text,
                "{name}: cleaning absent class {} altered the document",
                class.id()
            );
            assert!(
                !report.altered,
                "{name}: cleaning absent class {} reported an alteration",
                class.id()
            );
        }
    }
}

#[test]
fn a_full_clean_of_an_unmarked_document_is_byte_identical() {
    for (name, text) in unmarked_corpus() {
        let report = clean(text, &MarkClass::ALL);
        assert_eq!(report.cleaned_text, text, "{name}: full clean altered an unmarked document");
        assert!(!report.altered, "{name}: full clean reported an alteration");
    }
}

#[test]
fn cleaning_all_classes_removes_every_owned_mark_from_already_carrying() {
    let report = clean(ALREADY_CARRYING, &MarkClass::ALL);
    let total: usize = report.removed.iter().map(|r| r.count).sum();
    assert_eq!(total, 4);
    for owned in ['\u{200B}', '\u{200C}', '\u{2060}', '\u{FEFF}'] {
        assert!(!report.cleaned_text.contains(owned));
    }
    assert!(report.altered);
}

#[test]
fn cleaning_one_class_leaves_the_other_present_class_in_place() {
    // already_carrying holds two zero-width and two whitespace-variation marks.
    let report = clean(ALREADY_CARRYING, &[MarkClass::ZeroWidth]);
    assert_eq!(removed_count(&report, "zero_width"), 2);
    // The whitespace-variation pair survives.
    assert!(report.cleaned_text.contains('\u{2060}'));
    assert!(report.cleaned_text.contains('\u{FEFF}'));
    assert!(!report.cleaned_text.contains('\u{200B}'));
}

#[test]
fn legitimate_cyrillic_survives_a_homoglyph_clean_byte_identical() {
    let report = clean(CYRILLIC, &[MarkClass::Homoglyph]);
    assert_eq!(report.cleaned_text, CYRILLIC);
    assert!(!report.altered);
}

#[test]
fn every_clean_carries_the_residual_note() {
    for (name, text) in corpus() {
        let report = clean(text, &MarkClass::ALL);
        assert!(report.residual.len() >= 3, "{name}: residual note missing");
        assert!(
            report.residual.iter().any(|n| n.contains("does not guarantee")),
            "{name}: residual note is not honest about the guarantee"
        );
    }
}

// ---------------------------------------------------------------------------
// Round trip: mark, see it, clean it away
// ---------------------------------------------------------------------------

#[test]
fn each_class_round_trips_mark_inspect_clean_on_a_latin_cover() {
    // en_long is Latin and long enough for every carrier, including homoglyph
    // which needs Latin script to substitute into.
    for class in MarkClass::ALL {
        let carrier = carrier_for(class);
        let marked = carrier
            .encode(EN_LONG, b"trace")
            .unwrap_or_else(|e| panic!("encode with {} failed: {e}", class.id()));
        assert_ne!(marked, EN_LONG, "{}: the mark must actually be present", class.id());

        let inspected = inspect(&marked);
        assert!(
            class_count(&inspected, class.id()) > 0,
            "{}: inspect did not see the mark it carries",
            class.id()
        );

        let cleaned = clean(&marked, &[class]);
        assert_eq!(
            cleaned.cleaned_text,
            EN_LONG,
            "{}: clean did not restore the cover",
            class.id()
        );
        assert!(cleaned.altered, "{}: clean reported no alteration", class.id());
    }
}
