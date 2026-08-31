//! Fidelity: does a marked document look like its cover.
//!
//! Invariant 4b. A reader must not be able to tell by looking. `cover_restored`
//! proves that stripping a document returns the original, which is necessary
//! and nowhere near sufficient: a document can strip back perfectly while
//! wrapping at different points, selecting the wrong word on a double click, or
//! displaying its text in a different order.
//!
//! This module measures the difference a reader can perceive. It changes no
//! behaviour and touches no carrier. It is a measurement layer.
//!
//! # The two axes, which are never merged
//!
//! A fidelity verdict answers one question: would a reader notice. It does not
//! answer whether an analyst would find the document, and it must never be read
//! as if it did. `forensic.rs:324` raises a script mix as soon as Latin and
//! Cyrillic coexist with non zero homoglyph density, so one substitution is
//! enough to be flagged by a codepoint audit. Every invisible carrier is in the
//! same position: the codepoints it writes have no business being in prose, and
//! anyone listing them finds them.
//!
//! [`Overall`] therefore carries both axes as separate fields, and
//! [`Overall::scope`] states the distinction in the report itself so it cannot
//! be lost in a summary.
//!
//! # No silent degradation
//!
//! A check that cannot run returns [`CheckVerdict::Indeterminate`] with a
//! reason, is listed in [`Overall::checks_not_run`], and never contributes a
//! passing verdict. While any check is missing, the overall verdict is
//! indeterminate too and the reported figure is a lower bound.
//!
//! # The checks
//!
//! 1. [`reflow`] U+2060 suppresses a line break, U+200B creates one. Reports
//!    the change in break opportunities and the wrap points that moved.
//! 2. [`bidi_balance`] every embedding and override closed, by position.
//! 3. [`word_selection`] words that gained an interior channel character.
//! 4. [`distribution`] Kolmogorov-Smirnov distance from uniform placement.
//! 5. [`density`] fill ratio against the mission ceiling, SPEC_CORE_V2 5.3.
//! 6. [`audit`] what a codepoint audit finds, on its own axis.
//! 7. [`paste_safety`] marks landing in machine input, backlog F9.
//!
//! ```rust
//! use stegano_core::fidelity::{self, CheckVerdict, FidelityOptions};
//!
//! let cover = "the board reviewed the operations of the northern division";
//! let marked = "the board reviewed the oper\u{200C}ations of the northern division";
//!
//! let report = fidelity::assess(cover, marked, &FidelityOptions::default());
//! assert_eq!(report.word_selection.broken_words[0].word, "operations");
//! assert_ne!(report.word_selection.verdict, CheckVerdict::Clean);
//! ```

pub mod align;
pub mod audit;
pub mod bidi_balance;
pub mod chars;
pub mod density;
pub mod distribution;
pub mod paste_safety;
pub mod reflow;
pub mod word_selection;

pub use align::{Alignment, Insertion, Substitution};
pub use audit::{AuditExposure, CodepointAuditCheck, CodepointCount};
pub use bidi_balance::{BidiBalanceCheck, ControlSite};
pub use density::{ceiling_for, DensityCheck};
pub use distribution::{DenseWindow, DistributionCheck, LargestGap};
pub use paste_safety::{CodeSite, PasteSafetyCheck};
pub use reflow::{BreakMove, ReflowCheck};
pub use word_selection::{WordSelectionCheck, WordSite};

use crate::format::Mission;

/// What one check concluded.
///
/// `Indeterminate` is not a grade on the same scale as the other three. It
/// means the check could not run, it carries the reason, and it is never a
/// pass.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum CheckVerdict {
    /// The marked document is indistinguishable from its cover on this check.
    Clean,
    /// A difference that shows under some conditions but not the ones measured
    /// here: another column width, another editor, another reader.
    Degraded,
    /// A difference that shows in the document as measured.
    Conspicuous,
    /// The check could not run. Never read this as a pass.
    Indeterminate { reason: String },
}

impl CheckVerdict {
    /// True when the check reached a finding, whatever the finding was.
    pub fn ran(&self) -> bool {
        !matches!(self, CheckVerdict::Indeterminate { .. })
    }
}

impl std::fmt::Display for CheckVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckVerdict::Clean => write!(f, "CLEAN"),
            CheckVerdict::Degraded => write!(f, "DEGRADED"),
            CheckVerdict::Conspicuous => write!(f, "CONSPICUOUS"),
            CheckVerdict::Indeterminate { reason } => write!(f, "INDETERMINATE: {reason}"),
        }
    }
}

/// How to run the assessment.
#[derive(Debug, Clone)]
pub struct FidelityOptions {
    /// Which SPEC_CORE_V2 5.3 ceiling the density check judges against.
    pub mission: Mission,
    /// Column width the reflow check lays the document out at.
    pub wrap_width: usize,
    /// Positions the carrier had available, when it is not one per cover
    /// character. `None` uses the cover character count, which is correct for
    /// all four carriers in this build.
    pub available_positions: Option<usize>,
    /// Cap on how many locations each check lists. The counts are never capped.
    pub max_locations: usize,
}

impl Default for FidelityOptions {
    fn default() -> Self {
        Self {
            mission: Mission::Conceal,
            wrap_width: 80,
            available_positions: None,
            max_locations: 32,
        }
    }
}

impl FidelityOptions {
    /// Defaults, judged against one mission's ceiling.
    pub fn for_mission(mission: Mission) -> Self {
        Self {
            mission,
            ..Self::default()
        }
    }
}

/// The two axes, and what is known about each.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Overall {
    /// Highest risk among the checks that measure what a reader perceives:
    /// reflow, bidi balance, word selection and paste safety.
    ///
    /// The maximum rather than an average, on purpose. One conspicuous defect
    /// ruins a document, and averaging it against four clean checks would hide
    /// exactly the finding worth acting on.
    ///
    /// When [`Overall::complete`] is false this figure is a lower bound.
    pub human_reader_risk: f64,
    /// The worst reader facing verdict, or indeterminate while any check is
    /// missing.
    pub human_reader_verdict: CheckVerdict,
    /// What a codepoint audit finds. A separate question with a separate
    /// answer, and `NotExposed` is only ever reported when it was measured.
    pub analyst_exposure: AuditExposure,
    /// Highest risk among the checks that measure what an analyst finds:
    /// distribution, density and the codepoint audit.
    pub analyst_risk: f64,
    /// Which check contributed [`Overall::human_reader_risk`].
    pub worst_reader_check: Option<&'static str>,
    /// Checks that could not run.
    pub checks_not_run: Vec<&'static str>,
    /// True when every check reached a finding.
    pub complete: bool,
    /// The scope of this verdict, stated in the report rather than the manual.
    pub scope: &'static str,
}

const OVERALL_SCOPE: &str =
    "A fidelity verdict answers whether a reader would notice, and nothing else. \
     It is not a claim that the document survives a codepoint audit: see \
     analyst_exposure for that, which is measured separately and is exposed on \
     the first mark for every carrier in this build.";

/// The full report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FidelityReport {
    /// How the two documents were paired, and whether they could be.
    pub alignment: Alignment,
    pub reflow: ReflowCheck,
    pub bidi_balance: BidiBalanceCheck,
    pub word_selection: WordSelectionCheck,
    pub distribution: DistributionCheck,
    pub density: DensityCheck,
    pub codepoint_audit: CodepointAuditCheck,
    pub paste_safety: PasteSafetyCheck,
    pub overall: Overall,
}

/// Names of the checks that measure what a reader perceives.
const READER_CHECKS: [&str; 4] = ["reflow", "bidi_balance", "word_selection", "paste_safety"];

impl FidelityReport {
    /// Every check with its verdict, in report order, for a caller that wants
    /// to iterate rather than name each field.
    pub fn verdicts(&self) -> Vec<(&'static str, CheckVerdict)> {
        vec![
            ("reflow", self.reflow.verdict.clone()),
            ("bidi_balance", self.bidi_balance.verdict.clone()),
            ("word_selection", self.word_selection.verdict.clone()),
            ("distribution", self.distribution.verdict.clone()),
            ("density", self.density.verdict.clone()),
            ("paste_safety", self.paste_safety.verdict.clone()),
        ]
    }

    /// True when the named check is one a reader would perceive.
    pub fn is_reader_check(name: &str) -> bool {
        READER_CHECKS.contains(&name)
    }
}

/// Measure how far `marked` has moved from `cover`.
///
/// Produces a report in every case. A pair that cannot be measured is named in
/// the report rather than raised, because the answer to "how visible is this"
/// is never an absent report.
pub fn assess(cover: &str, marked: &str, options: &FidelityOptions) -> FidelityReport {
    let cover_chars: Vec<char> = cover.chars().collect();
    let marked_chars: Vec<char> = marked.chars().collect();
    let alignment = Alignment::of(&cover_chars, &marked_chars);

    let reflow = reflow::check(
        &cover_chars,
        &marked_chars,
        &alignment,
        options.wrap_width,
        options.max_locations,
    );
    let bidi_balance = bidi_balance::check(
        &cover_chars,
        &marked_chars,
        &alignment,
        options.max_locations,
    );
    let word_selection = word_selection::check(&cover_chars, &alignment, options.max_locations);
    let distribution = distribution::check(&alignment);
    let density = density::check(
        marked,
        &alignment,
        options.mission,
        options.available_positions,
    );
    let codepoint_audit = audit::check(marked, &alignment, options.max_locations);
    let paste_safety = paste_safety::check(&cover_chars, &alignment, options.max_locations);

    // The reflow risk is computed here from the check's own counters rather
    // than read off it, so the axis weighting lives in one place with the other
    // three reader facing checks. A moved break is the whole defect: the
    // paragraph lays out differently. A changed opportunity that does not move
    // a break at this width is latent, and scores lower rather than zero,
    // because the same document at another width will show it.
    let reflow_risk = if reflow.verdict.ran() {
        if reflow.moved_breaks_total > 0 {
            1.0
        } else if reflow.opportunities_gained + reflow.opportunities_lost > 0 {
            0.4
        } else {
            0.0
        }
    } else {
        0.0
    };

    let reader: Vec<(&'static str, &CheckVerdict, f64)> = vec![
        ("reflow", &reflow.verdict, reflow_risk),
        (
            "bidi_balance",
            &bidi_balance.verdict,
            bidi_balance.reader_risk(),
        ),
        (
            "word_selection",
            &word_selection.verdict,
            word_selection.reader_risk(),
        ),
        (
            "paste_safety",
            &paste_safety.verdict,
            paste_safety.reader_risk(),
        ),
    ];
    let analyst: Vec<(&'static str, &CheckVerdict, f64)> = vec![
        (
            "distribution",
            &distribution.verdict,
            distribution.analyst_risk(),
        ),
        ("density", &density.verdict, density.analyst_risk()),
    ];

    let mut checks_not_run: Vec<&'static str> = reader
        .iter()
        .chain(analyst.iter())
        .filter(|(_, verdict, _)| !verdict.ran())
        .map(|(name, _, _)| *name)
        .collect();
    if codepoint_audit.exposure == AuditExposure::Indeterminate {
        checks_not_run.push("codepoint_audit");
    }

    let mut human_reader_risk = 0.0f64;
    let mut worst_reader_check = None;
    for (name, verdict, risk) in &reader {
        if verdict.ran() && *risk > human_reader_risk {
            human_reader_risk = *risk;
            worst_reader_check = Some(*name);
        }
    }

    let analyst_risk = analyst
        .iter()
        .filter(|(_, verdict, _)| verdict.ran())
        .map(|(_, _, risk)| *risk)
        .fold(codepoint_audit.analyst_risk(), f64::max);

    let complete = checks_not_run.is_empty();
    let human_reader_verdict = if !complete {
        // An incomplete report never claims a firm overall verdict. The
        // per-check verdicts stay usable; this one does not pretend.
        CheckVerdict::Indeterminate {
            reason: format!(
                "these checks could not run: {}",
                checks_not_run.join(", ")
            ),
        }
    } else {
        reader
            .iter()
            .map(|(_, verdict, _)| (*verdict).clone())
            .max_by_key(|verdict| match verdict {
                CheckVerdict::Clean => 0,
                CheckVerdict::Degraded => 1,
                CheckVerdict::Conspicuous => 2,
                CheckVerdict::Indeterminate { .. } => 3,
            })
            .unwrap_or(CheckVerdict::Clean)
    };

    let overall = Overall {
        human_reader_risk,
        human_reader_verdict,
        analyst_exposure: codepoint_audit.exposure,
        analyst_risk,
        worst_reader_check,
        checks_not_run,
        complete,
        scope: OVERALL_SCOPE,
    };

    FidelityReport {
        alignment,
        reflow,
        bidi_balance,
        word_selection,
        distribution,
        density,
        codepoint_audit,
        paste_safety,
        overall,
    }
}

/// Measure a document against its own stripped form.
///
/// For a document with no separate cover to compare against: the cover is
/// synthesised by removing every format control, which is what a reader would
/// see if the carriers had never run. It answers what a document's fidelity
/// already is before anything is added to it, which for
/// `tests/corpus/already_carrying.txt` is not perfect.
///
/// It cannot see homoglyph substitutions, since there is nothing to compare a
/// letter against. That limit is stated here rather than left to be discovered:
/// use [`assess`] with the real cover whenever there is one.
pub fn baseline(text: &str, options: &FidelityOptions) -> FidelityReport {
    let stripped: String = text.chars().filter(|c| !chars::is_format_control(*c)).collect();
    assess(&stripped, text, options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_untouched_document_is_clean_on_both_axes() {
        let text = "the board reviewed the operations of the northern division today";
        let report = assess(text, text, &FidelityOptions::default());

        assert_eq!(report.overall.human_reader_verdict, CheckVerdict::Clean);
        assert_eq!(report.overall.human_reader_risk, 0.0);
        assert_eq!(report.overall.analyst_exposure, AuditExposure::NotExposed);
        assert_eq!(report.overall.analyst_risk, 0.0);
        assert!(report.overall.complete);
        assert!(report.overall.worst_reader_check.is_none());
    }

    #[test]
    fn the_overall_figure_is_the_worst_check_and_names_it() {
        let cover = "the board reviewed the operations of the northern division today";
        let marked = "the board reviewed the oper\u{200C}ations of the northern division today";
        let report = assess(cover, marked, &FidelityOptions::default());

        assert_eq!(report.overall.worst_reader_check, Some("word_selection"));
        assert_eq!(
            report.overall.human_reader_risk,
            report.word_selection.reader_risk()
        );
    }

    #[test]
    fn an_incomplete_report_never_claims_a_firm_verdict() {
        let report = assess(
            "the quick brown fox",
            "entirely unrelated prose here",
            &FidelityOptions::default(),
        );

        assert!(!report.overall.complete);
        assert!(matches!(
            report.overall.human_reader_verdict,
            CheckVerdict::Indeterminate { .. }
        ));
        assert_eq!(report.overall.analyst_exposure, AuditExposure::Indeterminate);
        assert!(report.overall.checks_not_run.len() >= 4);
    }

    #[test]
    fn the_reader_axis_and_the_analyst_axis_disagree_and_that_is_correct() {
        // One homoglyph substitution in a long document: nothing a reader can
        // see, and an immediate finding for anyone listing the codepoints.
        let cover: String = "the board reviewed the operations "
            .chars()
            .cycle()
            .take(680)
            .collect();
        let marked = cover.replacen('b', "\u{0412}", 1);
        let report = assess(&cover, &marked, &FidelityOptions::default());

        assert_eq!(report.overall.analyst_exposure, AuditExposure::Exposed);
        assert_eq!(report.overall.analyst_risk, 1.0);
        assert!(
            report.overall.human_reader_risk < 0.5,
            "reader risk was {}",
            report.overall.human_reader_risk
        );
        assert!(report.overall.scope.contains("codepoint audit"));
    }

    #[test]
    fn every_check_appears_in_the_verdict_listing() {
        let text = "the board reviewed the operations of the northern division today";
        let report = assess(text, text, &FidelityOptions::default());
        let names: Vec<&str> = report.verdicts().into_iter().map(|(name, _)| name).collect();

        for expected in [
            "reflow",
            "bidi_balance",
            "word_selection",
            "distribution",
            "density",
            "paste_safety",
        ] {
            assert!(names.contains(&expected), "{expected} missing from {names:?}");
        }
    }

    #[test]
    fn the_mission_ceiling_follows_the_option() {
        let cover: String = "abcdefghij ".chars().cycle().take(200).collect();
        for (mission, expected) in [
            (Mission::Conceal, 0.25),
            (Mission::Sign, 0.50),
            (Mission::Mark, 0.85),
        ] {
            let report = assess(&cover, &cover, &FidelityOptions::for_mission(mission));
            assert_eq!(report.density.ceiling, expected);
        }
    }

    #[test]
    fn a_baseline_reads_a_document_against_its_own_stripped_form() {
        let carrying = "the committee\u{2060} noted the meeting\u{200B} held today";
        let report = baseline(carrying, &FidelityOptions::default());

        assert_eq!(report.alignment.insertions.len(), 2);
        assert_eq!(report.codepoint_audit.exposure, AuditExposure::Exposed);
        assert!(report.reflow.opportunities_gained >= 1, "{:?}", report.reflow);
    }

    #[test]
    fn a_clean_document_has_a_spotless_baseline() {
        let report = baseline(
            "the board reviewed the operations of the northern division today",
            &FidelityOptions::default(),
        );
        assert_eq!(report.overall.human_reader_risk, 0.0);
        assert_eq!(report.overall.human_reader_verdict, CheckVerdict::Clean);
        assert_eq!(report.overall.analyst_exposure, AuditExposure::NotExposed);
    }

    #[test]
    fn the_report_serialises() {
        let cover = "the board reviewed the operations";
        let marked = "the board revi\u{200C}ewed the operations";
        let report = assess(cover, marked, &FidelityOptions::default());
        let json = serde_json::to_string(&report).expect("the report must serialise");
        assert!(json.contains("human_reader_risk"));
        assert!(json.contains("analyst_exposure"));
    }
}
