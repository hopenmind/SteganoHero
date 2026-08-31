//! Inspect: a structured, honest answer to "what marks are on my document".
//!
//! This wraps [`crate::forensic::analyze`] and shapes its findings for a person
//! asking about their own document. Per-class counts come from each carrier's
//! own `strip`, so the number inspect reports for a class is exactly the number
//! a clean of that class would remove. The broader forensic view (verdict,
//! carrier signatures, statistics) is surfaced unchanged.

use crate::forensic;

use super::metadata::{read_metadata, ReadableMetadata};
use super::{count_marks_changed, other_invisible, MarkClass};

/// A structured report of every mark this tool can see on a document.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InspectionReport {
    /// Total characters in the document.
    pub total_chars: usize,
    /// Visible characters.
    pub visible_chars: usize,
    /// Invisible or formatting characters.
    pub invisible_chars: usize,
    /// Per-class findings: what this tool can both see and remove.
    pub classes: Vec<ClassFinding>,
    /// Our own carrier signatures, as the forensic detector reports them.
    pub carrier_signatures: Vec<CarrierSignature>,
    /// Invisible characters present that fall outside every cleanable class.
    /// Reported for transparency; the native clean does not remove these.
    pub other_invisible: Vec<OtherInvisible>,
    /// Readable text metadata the format exposes, if any.
    pub metadata: Option<ReadableMetadata>,
    /// The forensic verdict, surfaced unchanged.
    pub verdict: String,
    /// The forensic suspicion score (0.0 clean, 1.0 certainly modified).
    pub suspicion_score: f64,
    /// Plain-language, honest summary lines.
    pub summary: Vec<String>,
}

/// A per-class finding: the marks of one class present on the document.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClassFinding {
    /// Stable class identifier, matching the forensic vocabulary.
    pub id: &'static str,
    /// Plain-language class label.
    pub label: &'static str,
    /// Marks of this class present, measured by the carrier's own `strip`.
    pub count: usize,
    /// True when the native clean can remove this class. Always true for the
    /// four classes here; stated so a surface can distinguish them from the
    /// `other_invisible` and residual entries, which it cannot remove.
    pub cleanable: bool,
}

/// One of our own carrier signatures, as the forensic detector saw it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CarrierSignature {
    /// Carrier identifier (matches a `MarkClass` id).
    pub id: String,
    /// Human-readable carrier name.
    pub name: String,
    /// Detection confidence (0.0 to 1.0).
    pub confidence: f64,
    /// True when a readable payload could be recovered from this channel.
    pub carries_readable_payload: bool,
    /// Estimated payload size in bytes, when a payload reads back.
    pub payload_bytes: Option<usize>,
}

/// An invisible or bidirectional character present that no cleanable class owns.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OtherInvisible {
    /// Codepoint, e.g. `U+200D`.
    pub codepoint: String,
    /// Forensic category, e.g. `invisible/formatting`.
    pub category: String,
    /// Number of occurrences.
    pub count: usize,
}

/// Inspect a document and report every mark this tool can see.
pub fn inspect(document: &str) -> InspectionReport {
    let report = forensic::analyze(document);

    let classes: Vec<ClassFinding> = MarkClass::ALL
        .into_iter()
        .map(|class| {
            let stripped = class.strip(document);
            ClassFinding {
                id: class.id(),
                label: class.label(),
                count: count_marks_changed(document, &stripped),
                cleanable: true,
            }
        })
        .collect();

    let carrier_signatures: Vec<CarrierSignature> = report
        .stego_signatures
        .iter()
        .map(|sig| CarrierSignature {
            id: sig.method.clone(),
            name: sig.name.clone(),
            confidence: sig.confidence,
            carries_readable_payload: sig.decodable,
            payload_bytes: sig.estimated_payload_bytes,
        })
        .collect();

    let other = other_invisible(&report);
    let metadata = read_metadata(document);
    let summary = build_summary(&classes, &carrier_signatures, &other, metadata.as_ref());

    InspectionReport {
        total_chars: report.unicode_analysis.total_chars,
        visible_chars: report.unicode_analysis.visible_chars,
        invisible_chars: report.unicode_analysis.invisible_chars,
        classes,
        carrier_signatures,
        other_invisible: other,
        metadata,
        verdict: report.verdict.to_string(),
        suspicion_score: report.suspicion_score,
        summary,
    }
}

fn build_summary(
    classes: &[ClassFinding],
    carrier_signatures: &[CarrierSignature],
    other: &[OtherInvisible],
    metadata: Option<&ReadableMetadata>,
) -> Vec<String> {
    let mut lines = Vec::new();

    let total_marks: usize = classes.iter().map(|c| c.count).sum();
    let classes_present = classes.iter().filter(|c| c.count > 0).count();

    if total_marks == 0 {
        lines.push("This document carries no marks in the classes this tool can remove.".to_string());
    } else {
        lines.push(format!(
            "This document carries {total_marks} mark(s) across {classes_present} class(es) this tool can recognise and remove."
        ));
        for finding in classes.iter().filter(|c| c.count > 0) {
            lines.push(format!(
                "  {}: {} ({})",
                finding.label, finding.count, finding.id
            ));
        }
    }

    if !other.is_empty() {
        let count: usize = other.iter().map(|o| o.count).sum();
        lines.push(format!(
            "{count} invisible character(s) fall outside the removable classes. They are reported here and left in place by the native clean."
        ));
    }

    if !carrier_signatures.is_empty() {
        if carrier_signatures.iter().any(|s| s.carries_readable_payload) {
            lines.push("A recognised carrier holds a readable payload.".to_string());
        } else {
            lines.push(
                "Carrier-channel characters are present without a readable payload.".to_string(),
            );
        }
    }

    match metadata {
        Some(meta) => {
            if meta.leading_byte_order_mark {
                lines.push("A leading byte-order mark is present.".to_string());
            }
            if meta.front_matter.is_some() {
                lines.push(
                    "A leading front-matter block is present and readable.".to_string(),
                );
            }
        }
        None => {
            lines.push("No readable document metadata was found in this text.".to_string());
        }
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stego::{Homoglyph, ZeroWidth};
    use crate::traits::StegoMethod;

    const CYRILLIC_RUSSIAN: &str = include_str!("../../../../tests/corpus/cyrillic_russian.txt");
    const EN_LONG_ARTICLE: &str = include_str!("../../../../tests/corpus/en_long_article.txt");
    const ALREADY_CARRYING: &str = include_str!("../../../../tests/corpus/already_carrying.txt");

    fn class_count(report: &InspectionReport, id: &str) -> usize {
        report
            .classes
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("class {id} must be present"))
            .count
    }

    #[test]
    fn clean_text_reports_no_marks() {
        let report = inspect("The quick brown fox jumps over the lazy dog.");
        assert_eq!(report.classes.iter().map(|c| c.count).sum::<usize>(), 0);
        assert!(report.carrier_signatures.is_empty());
        assert!(report.other_invisible.is_empty());
        assert!(report.summary[0].contains("no marks"));
    }

    #[test]
    fn every_class_is_always_listed_and_cleanable() {
        let report = inspect("plain text");
        assert_eq!(report.classes.len(), 4);
        assert!(report.classes.iter().all(|c| c.cleanable));
    }

    #[test]
    fn already_carrying_reports_its_two_channels_by_class() {
        let report = inspect(ALREADY_CARRYING);
        // Two zero-width characters (U+200B, U+200C) and two whitespace
        // variation characters (U+2060, U+FEFF) sit in this document.
        assert_eq!(class_count(&report, "zero_width"), 2);
        assert_eq!(class_count(&report, "whitespace_var"), 2);
        assert_eq!(class_count(&report, "bidi"), 0);
        assert_eq!(class_count(&report, "homoglyph"), 0);
        assert_eq!(report.invisible_chars, 4);
    }

    #[test]
    fn legitimate_cyrillic_is_not_reported_as_a_homoglyph_payload() {
        // The recognition work (backlog F7/F16) is reused: monolingual Russian
        // has zero homoglyph marks and no carrier signature.
        let report = inspect(CYRILLIC_RUSSIAN);
        assert_eq!(class_count(&report, "homoglyph"), 0);
        assert!(report
            .carrier_signatures
            .iter()
            .all(|s| !s.carries_readable_payload));
    }

    #[test]
    fn a_marked_document_reports_the_class_and_its_signature() {
        let zw = ZeroWidth::new();
        let marked = zw.encode(EN_LONG_ARTICLE, b"provenance").unwrap();

        let report = inspect(&marked);
        assert!(class_count(&report, "zero_width") > 0);

        let signature = report
            .carrier_signatures
            .iter()
            .find(|s| s.id == "zero_width")
            .expect("the marked document must show a zero-width signature");
        assert!(signature.carries_readable_payload);
    }

    #[test]
    fn inspect_class_count_equals_what_a_strip_would_remove() {
        let hg = Homoglyph::new();
        let marked = hg.encode(EN_LONG_ARTICLE, b"trace").unwrap();

        let report = inspect(&marked);
        let reported = class_count(&report, "homoglyph");
        let actually_reverted = count_marks_changed(&marked, &hg.strip(&marked));
        assert_eq!(reported, actually_reverted);
        assert!(reported > 0);
    }

    #[test]
    fn orphan_invisible_characters_are_reported_but_not_a_class() {
        // U+200D (ZWJ) is invisible but no cleanable class owns it.
        let report = inspect("team\u{200D}work is good");
        assert_eq!(report.classes.iter().map(|c| c.count).sum::<usize>(), 0);
        assert_eq!(report.other_invisible.len(), 1);
        assert_eq!(report.other_invisible[0].codepoint, "U+200D");
    }

    #[test]
    fn summary_states_when_no_metadata_is_present() {
        let report = inspect("plain text with no metadata");
        assert!(report
            .summary
            .iter()
            .any(|l| l.contains("No readable document metadata")));
    }

    #[test]
    fn no_summary_line_uses_an_em_dash() {
        let zw = ZeroWidth::new();
        let marked = zw.encode(EN_LONG_ARTICLE, b"x").unwrap();
        let report = inspect(&marked);
        for line in &report.summary {
            assert!(!line.contains('\u{2014}'), "em dash in summary: {line}");
        }
    }
}
