//! Clean: remove the chosen classes and leave everything else byte-identical.
//!
//! Removal is each carrier's own `strip`, applied only for the classes the
//! caller chose, in the canonical carrier order. The report states what was
//! verifiably removed (counts, per class) and, honestly, what a native clean
//! does not address, so a caller never reads "clean" as "guaranteed unmarked".

use crate::forensic;

use super::{count_marks_changed, other_invisible, MarkClass};

/// The outcome of a clean: the cleaned text, what was removed, and what remains
/// possible.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CleanReport {
    /// The document after removing the chosen classes. Every character outside
    /// those classes is byte-identical to the input.
    pub cleaned_text: String,
    /// True when at least one character changed.
    pub altered: bool,
    /// Per requested class: how many marks were verifiably removed.
    pub removed: Vec<ClassRemoval>,
    /// What a native clean does not address. Present so a caller never reads a
    /// clean result as a guarantee of an unmarked document.
    pub residual: Vec<String>,
}

/// The removal outcome for one requested class.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClassRemoval {
    /// Stable class identifier, matching the forensic vocabulary.
    pub id: &'static str,
    /// Plain-language class label.
    pub label: &'static str,
    /// Marks removed, measured by the carrier's own `strip`.
    pub count: usize,
    /// True when this class changed the document. A class with nothing to
    /// remove reports `count: 0` and `altered: false`, not an alteration.
    pub altered: bool,
}

/// Remove exactly the chosen classes from a document.
///
/// Classes not chosen are left untouched, and text outside every chosen class
/// is byte-identical to the input. A chosen class with nothing to remove is
/// reported clean for that class, not altered.
pub fn clean(document: &str, classes: &[MarkClass]) -> CleanReport {
    let mut text = document.to_string();
    let mut removed = Vec::new();

    // Canonical carrier order, so a full clean is deterministic. Only the
    // chosen classes are applied.
    for class in MarkClass::ALL {
        if !classes.contains(&class) {
            continue;
        }

        let stripped = class.strip(&text);
        let count = count_marks_changed(&text, &stripped);
        removed.push(ClassRemoval {
            id: class.id(),
            label: class.label(),
            count,
            altered: stripped != text,
        });
        text = stripped;
    }

    let altered = text != document;

    CleanReport {
        cleaned_text: text,
        altered,
        removed,
        residual: residual_notes(document),
    }
}

/// The outcome of a pristine clean: the maximal, declared opt-in mode.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PristineReport {
    /// The document after removing every mark class AND every remaining
    /// invisible or format-control character.
    pub cleaned_text: String,
    /// True when at least one character changed.
    pub altered: bool,
    /// Per mark class: what the conservative clean removed.
    pub class_removed: Vec<ClassRemoval>,
    /// Invisible / format-control characters removed BEYOND the mark classes,
    /// including any that are meaning-bearing.
    pub invisibles_removed: usize,
    /// The honest caveat and what was removed. Present so the trade-off is
    /// stated, never silent (invariant 2).
    pub notes: Vec<String>,
}

/// The maximal, DECLARED opt-in clean ("as if from 1997"): remove every mark
/// class AND every remaining invisible or format-control character, so the
/// result re-analyses as clean.
///
/// It removes even meaning-bearing invisibles (emoji zero-width joiner
/// sequences, right-to-left runs, Arabic or Indic joiners), which the
/// conservative [`clean`] deliberately leaves. So it NAMES that trade-off and
/// REPORTS what it removed; it never strips them silently (invariant 2). The
/// visible glyphs are otherwise preserved.
pub fn pristine_clean(document: &str) -> PristineReport {
    let class_report = clean(document, &MarkClass::ALL);
    let (cleaned_text, invisibles_removed) =
        forensic::strip_invisibles(&class_report.cleaned_text);
    let altered = cleaned_text != document;

    let mut notes = vec![
        "This pristine clean removes every invisible and format-control character, including ones that can be meaning-bearing: emoji zero-width joiner sequences, right-to-left runs, and Arabic or Indic joiners. It changes how such text renders. It is a declared, opt-in mode, distinct from the conservative clean.".to_string(),
    ];
    if invisibles_removed > 0 {
        notes.push(format!(
            "{invisibles_removed} invisible or format-control character(s) beyond the removable mark classes were removed."
        ));
    }

    PristineReport {
        cleaned_text,
        altered,
        class_removed: class_report.removed,
        invisibles_removed,
        notes,
    }
}

/// The honest limits of a native clean. The first three lines always hold. The
/// last names any invisible character present that no cleanable class owns, so
/// the report never passes over what it left behind (invariant 2).
fn residual_notes(document: &str) -> Vec<String> {
    let mut notes = vec![
        "Statistical or token-sampling watermarks are not removed by this native tool and cannot be removed deterministically here.".to_string(),
        "Marks embedded in pixels, audio, or a container format are out of scope for the text path.".to_string(),
        "A clean result confirms removal of the named classes only. It does not guarantee the document carries no other mark.".to_string(),
    ];

    let report = forensic::analyze(document);
    let others = other_invisible(&report);
    if !others.is_empty() {
        let list = others
            .iter()
            .map(|o| o.codepoint.clone())
            .collect::<Vec<_>>()
            .join(", ");
        notes.push(format!(
            "Invisible characters outside the removable classes are present and were not removed: {list}."
        ));
    }

    notes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stego::{Bidi, Homoglyph, WhitespaceVar, ZeroWidth};
    use crate::traits::StegoMethod;

    const CYRILLIC_RUSSIAN: &str = include_str!("../../../../tests/corpus/cyrillic_russian.txt");
    const EN_LONG_ARTICLE: &str = include_str!("../../../../tests/corpus/en_long_article.txt");
    const EN_SHORT: &str = include_str!("../../../../tests/corpus/en_short.txt");
    const ALREADY_CARRYING: &str = include_str!("../../../../tests/corpus/already_carrying.txt");

    fn removal(report: &CleanReport, id: &str) -> ClassRemoval {
        report
            .removed
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("class {id} must be in the removal list"))
            .clone()
    }

    #[test]
    fn cleaning_a_class_that_is_absent_leaves_the_document_byte_identical() {
        // Legitimate Russian has no homoglyph marks. Choosing that class must
        // not alter a single byte (the destructive-strip trap, backlog F7).
        let report = clean(CYRILLIC_RUSSIAN, &[MarkClass::Homoglyph]);
        assert_eq!(report.cleaned_text, CYRILLIC_RUSSIAN);
        assert!(!report.altered);
        assert_eq!(removal(&report, "homoglyph").count, 0);
        assert!(!removal(&report, "homoglyph").altered);
    }

    #[test]
    fn cleaning_a_chosen_class_removes_it_and_leaves_the_others() {
        // already_carrying holds two zero-width and two whitespace-variation
        // characters. Cleaning only zero-width must remove those two and leave
        // the whitespace-variation pair in place.
        let report = clean(ALREADY_CARRYING, &[MarkClass::ZeroWidth]);
        assert_eq!(removal(&report, "zero_width").count, 2);
        assert!(report.altered);

        // The whitespace-variation characters survive untouched.
        assert!(report.cleaned_text.contains('\u{2060}'));
        assert!(report.cleaned_text.contains('\u{FEFF}'));
        // The zero-width characters are gone.
        assert!(!report.cleaned_text.contains('\u{200B}'));
        assert!(!report.cleaned_text.contains('\u{200C}'));
    }

    #[test]
    fn cleaning_all_classes_removes_every_owned_mark() {
        let report = clean(ALREADY_CARRYING, &MarkClass::ALL);
        let total: usize = report.removed.iter().map(|r| r.count).sum();
        assert_eq!(total, 4);
        for owned in ['\u{200B}', '\u{200C}', '\u{2060}', '\u{FEFF}'] {
            assert!(!report.cleaned_text.contains(owned));
        }
    }

    #[test]
    fn a_marked_document_cleans_back_to_its_cover() {
        let zw = ZeroWidth::new();
        let marked = zw.encode(EN_SHORT, b"x").unwrap();
        assert_ne!(marked, EN_SHORT);

        let report = clean(&marked, &[MarkClass::ZeroWidth]);
        assert_eq!(report.cleaned_text, EN_SHORT);
        assert!(report.altered);
        assert!(removal(&report, "zero_width").count > 0);
    }

    #[test]
    fn a_homoglyph_marked_document_reverts_to_its_cover() {
        let hg = Homoglyph::new();
        let marked = hg.encode(EN_LONG_ARTICLE, b"trace").unwrap();

        let report = clean(&marked, &[MarkClass::Homoglyph]);
        assert_eq!(report.cleaned_text, EN_LONG_ARTICLE);
        assert!(removal(&report, "homoglyph").count > 0);
    }

    #[test]
    fn only_chosen_classes_appear_in_the_removal_list() {
        let report = clean(ALREADY_CARRYING, &[MarkClass::ZeroWidth, MarkClass::Bidi]);
        assert_eq!(report.removed.len(), 2);
        assert!(report.removed.iter().any(|r| r.id == "zero_width"));
        assert!(report.removed.iter().any(|r| r.id == "bidi"));
    }

    #[test]
    fn removal_list_follows_canonical_order() {
        // Requested out of order, reported in canonical order.
        let report = clean(
            ALREADY_CARRYING,
            &[MarkClass::ZeroWidth, MarkClass::Bidi, MarkClass::WhitespaceVariation],
        );
        let ids: Vec<&str> = report.removed.iter().map(|r| r.id).collect();
        assert_eq!(ids, vec!["bidi", "whitespace_var", "zero_width"]);
    }

    #[test]
    fn cleaning_nothing_leaves_the_document_and_reports_no_removal() {
        let report = clean(ALREADY_CARRYING, &[]);
        assert_eq!(report.cleaned_text, ALREADY_CARRYING);
        assert!(!report.altered);
        assert!(report.removed.is_empty());
    }

    #[test]
    fn the_residual_note_is_always_present_and_honest() {
        let report = clean("plain text", &MarkClass::ALL);
        assert!(report.residual.len() >= 3);
        assert!(report
            .residual
            .iter()
            .any(|n| n.contains("does not guarantee")));
        assert!(report
            .residual
            .iter()
            .any(|n| n.to_lowercase().contains("statistical")));
    }

    #[test]
    fn the_residual_note_names_orphan_invisibles_left_behind() {
        // U+200D is invisible, present, and owned by no cleanable class.
        let report = clean("team\u{200D}work", &MarkClass::ALL);
        assert!(report.cleaned_text.contains('\u{200D}'));
        assert!(report
            .residual
            .iter()
            .any(|n| n.contains("U+200D")));
    }

    #[test]
    fn no_residual_or_label_line_uses_an_em_dash() {
        let report = clean("team\u{200D}work", &MarkClass::ALL);
        for note in &report.residual {
            assert!(!note.contains('\u{2014}'), "em dash in residual: {note}");
        }
        for entry in &report.removed {
            assert!(!entry.label.contains('\u{2014}'));
        }
    }

    #[test]
    fn a_full_clean_matches_the_carriers_run_in_canonical_order() {
        // The sovereignty full clean must equal applying the four carrier strips
        // directly, so it reuses removal rather than reimplementing it.
        let hg = Homoglyph::new();
        let marked = hg.encode(EN_LONG_ARTICLE, b"trace").unwrap();

        let bidi = Bidi::new();
        let whitespace = WhitespaceVar::new();
        let zero_width = ZeroWidth::new();
        let mut expected = bidi.strip(&marked);
        expected = hg.strip(&expected);
        expected = whitespace.strip(&expected);
        expected = zero_width.strip(&expected);

        let report = clean(&marked, &MarkClass::ALL);
        assert_eq!(report.cleaned_text, expected);
    }

    #[test]
    fn pristine_clean_removes_orphan_invisibles_and_re_analyses_clean() {
        // U+200D (ZWJ) and U+00AD (soft hyphen) are invisible but owned by no
        // cleanable class, so the conservative clean leaves them. Pristine takes
        // them out, and the result carries no invisible or unusual character.
        let text = "team\u{200D}work\u{00AD}here";
        let report = pristine_clean(text);
        assert!(!report.cleaned_text.contains('\u{200D}'));
        assert!(!report.cleaned_text.contains('\u{00AD}'));
        assert!(report.invisibles_removed >= 2);
        assert!(report.altered);

        let re = forensic::analyze(&report.cleaned_text);
        assert_eq!(re.unicode_analysis.invisible_chars, 0);
        assert!(re.unicode_analysis.unusual_categories.is_empty());
    }

    #[test]
    fn pristine_clean_names_the_trade_off_and_reports_what_it_removed() {
        // A joiner of the kind emoji sequences use is removed, and the note says
        // plainly that meaning-bearing invisibles are taken out.
        let report = pristine_clean("a\u{200D}b");
        assert!(report.invisibles_removed >= 1);
        assert!(report
            .notes
            .iter()
            .any(|n| n.to_lowercase().contains("meaning-bearing")));
    }

    #[test]
    fn pristine_clean_leaves_a_plain_text_unchanged() {
        let report = pristine_clean("plain ordinary text");
        assert_eq!(report.cleaned_text, "plain ordinary text");
        assert!(!report.altered);
        assert_eq!(report.invisibles_removed, 0);
    }
}
