//! Check 6: codepoint audit exposure.
//!
//! This check exists to stop the rest of the report from being read as
//! reassurance. Fidelity means a document survives a human reader. It has never
//! meant, and cannot mean, that it survives someone who lists its codepoints.
//!
//! `forensic.rs:324` raises a script mix with pattern `homoglyph_substitution`
//! as soon as Latin and Cyrillic coexist and homoglyph density is above zero.
//! One substitution is enough to be flagged. The invisible carriers are no
//! better off: a single U+200B in prose is a codepoint that has no business
//! being there, and any audit that lists format controls finds it.
//!
//! So the report carries two axes that are never collapsed into one figure. A
//! clean reader verdict and an exposed audit verdict is the normal, expected
//! result for this tool, not a contradiction.

use std::collections::BTreeMap;

use crate::forensic;

use super::align::Alignment;
use super::chars;

/// What a codepoint audit would find. Separate from every reader facing
/// verdict in this module, and never derived from one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum AuditExposure {
    /// Nothing was added that a codepoint listing would single out.
    NotExposed,
    /// An audit finds this document. Reader invisibility does not change that.
    Exposed,
    /// The check could not reach a finding. Never read this as not exposed.
    Indeterminate,
}

/// One codepoint the carrier introduced.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CodepointCount {
    pub codepoint: String,
    pub name: &'static str,
    pub count: usize,
    /// First cover index it appears at.
    pub first_cover_index: usize,
}

/// Result of the codepoint audit check.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CodepointAuditCheck {
    /// What an analyst finds.
    pub exposure: AuditExposure,
    /// The verdict `forensic::analyze` returns on the marked document, so the
    /// tool never contradicts itself between two of its own reports.
    pub analyser_verdict: String,
    pub analyser_suspicion: f64,
    /// True when Latin and Cyrillic coexist with non zero homoglyph density,
    /// which is the exact condition `forensic.rs:324` fires on.
    pub script_mix_fires: bool,
    pub homoglyph_density: f64,
    /// Every codepoint the carrier introduced, by frequency.
    pub added_codepoints: Vec<CodepointCount>,
    /// The first position an audit would stop at.
    pub first_flagged_cover_index: Option<usize>,
    /// Stated in the report itself so it cannot be lost in a summary.
    pub scope: &'static str,
}

const SCOPE: &str = "Audit exposure is a separate axis from reader visibility. \
                     A document can be indistinguishable to a reader and still be \
                     found immediately by anyone listing its codepoints.";

impl CodepointAuditCheck {
    /// What an analyst finds, in `0.0..=1.0`.
    ///
    /// There is no middle value. Every codepoint this tool introduces is one an
    /// audit can enumerate, so exposure is total on the first mark and the
    /// figure says so instead of implying a fill ratio could lower it.
    pub fn analyst_risk(&self) -> f64 {
        match self.exposure {
            AuditExposure::Exposed => 1.0,
            AuditExposure::NotExposed | AuditExposure::Indeterminate => 0.0,
        }
    }
}

/// Run the check.
pub fn check(marked_text: &str, alignment: &Alignment, max_locations: usize) -> CodepointAuditCheck {
    let forensic_report = forensic::analyze(marked_text);
    let homoglyph_density = forensic_report.statistics.homoglyph_density;
    let script_mix_fires = forensic_report
        .unicode_analysis
        .mixed_scripts
        .iter()
        .any(|mix| mix.pattern == "homoglyph_substitution");

    if alignment.failure.is_some() {
        return CodepointAuditCheck {
            exposure: AuditExposure::Indeterminate,
            analyser_verdict: forensic_report.verdict.to_string(),
            analyser_suspicion: forensic_report.suspicion_score,
            script_mix_fires,
            homoglyph_density,
            added_codepoints: Vec::new(),
            first_flagged_cover_index: None,
            scope: SCOPE,
        };
    }

    // Count what the carrier introduced, keeping the earliest position of each.
    let mut counts: BTreeMap<char, (usize, usize)> = BTreeMap::new();
    for insertion in &alignment.insertions {
        let entry = counts
            .entry(insertion.character)
            .or_insert((0, insertion.cover_index));
        entry.0 += 1;
        entry.1 = entry.1.min(insertion.cover_index);
    }
    for substitution in &alignment.substitutions {
        let entry = counts
            .entry(substitution.to)
            .or_insert((0, substitution.cover_index));
        entry.0 += 1;
        entry.1 = entry.1.min(substitution.cover_index);
    }

    let mut added: Vec<CodepointCount> = counts
        .into_iter()
        .map(|(character, (count, first))| CodepointCount {
            codepoint: chars::codepoint_label(character),
            name: chars::control_name(character),
            count,
            first_cover_index: first,
        })
        .collect();
    added.sort_by(|a, b| b.count.cmp(&a.count).then(a.codepoint.cmp(&b.codepoint)));

    let first_flagged_cover_index = alignment
        .mark_positions()
        .first()
        .copied()
        .filter(|_| !added.is_empty());

    // Every codepoint this tool introduces is one an audit can enumerate. The
    // honest answer is therefore exposure on the first mark, not on a
    // threshold.
    let exposure = if added.is_empty() {
        AuditExposure::NotExposed
    } else {
        AuditExposure::Exposed
    };
    CodepointAuditCheck {
        exposure,
        analyser_verdict: forensic_report.verdict.to_string(),
        analyser_suspicion: forensic_report.suspicion_score,
        script_mix_fires,
        homoglyph_density,
        added_codepoints: added.into_iter().take(max_locations).collect(),
        first_flagged_cover_index,
        scope: SCOPE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(cover: &str, marked: &str) -> CodepointAuditCheck {
        let cover_chars: Vec<char> = cover.chars().collect();
        let marked_chars: Vec<char> = marked.chars().collect();
        let alignment = Alignment::of(&cover_chars, &marked_chars);
        check(marked, &alignment, 32)
    }

    #[test]
    fn an_untouched_document_is_not_exposed() {
        let text = "the board reviewed the operations of the northern division";
        let report = run(text, text);
        assert_eq!(report.exposure, AuditExposure::NotExposed);
        assert!(report.added_codepoints.is_empty());
        assert_eq!(report.analyst_risk(), 0.0);
    }

    /// SPEC_CORE_V2 section 5.4, and the reason no fill ratio can make homoglyph
    /// invisible to an audit.
    #[test]
    fn one_substitution_is_enough_to_be_flagged() {
        let cover = "the board reviewed the operations";
        let marked = cover.replacen('o', "\u{043E}", 1);
        let report = run(cover, &marked);

        assert_eq!(report.exposure, AuditExposure::Exposed);
        assert!(report.script_mix_fires, "forensic.rs raises the script mix");
        assert!(report.homoglyph_density > 0.0);
        assert_eq!(report.added_codepoints.len(), 1);
        assert_eq!(report.added_codepoints[0].codepoint, "U+043E");
        assert_eq!(report.first_flagged_cover_index, Some(5));
    }

    #[test]
    fn one_invisible_character_is_enough_as_well() {
        let cover = "the board reviewed the operations";
        let marked = "the b\u{200B}oard reviewed the operations";
        let report = run(cover, marked);

        assert_eq!(report.exposure, AuditExposure::Exposed);
        assert!(!report.script_mix_fires, "no script mix without Cyrillic");
        assert_eq!(report.added_codepoints[0].codepoint, "U+200B");
        assert_eq!(report.added_codepoints[0].name, "ZERO WIDTH SPACE");
    }

    #[test]
    fn the_analyser_verdict_travels_with_the_report() {
        let cover = "the board reviewed the operations of the northern division today";
        let marked: String = cover.chars().flat_map(|c| [c, '\u{200C}']).collect();
        let report = run(cover, &marked);

        assert!(
            !report.analyser_verdict.is_empty(),
            "the tool's own analyser verdict must be quoted, not paraphrased"
        );
        assert!(report.analyser_suspicion > 0.0);
    }

    #[test]
    fn a_pairing_failure_is_never_reported_as_not_exposed() {
        let report = run("the quick brown fox", "something else entirely");
        assert_eq!(report.exposure, AuditExposure::Indeterminate);
        assert_ne!(report.exposure, AuditExposure::NotExposed);
    }

    #[test]
    fn the_scope_statement_is_carried_in_the_report_itself() {
        let text = "the board reviewed the operations";
        let report = run(text, text);
        assert!(report.scope.contains("separate axis"));
    }
}
