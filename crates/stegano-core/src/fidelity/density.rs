//! Check 5: density against the mission ceiling.
//!
//! SPEC_CORE_V2 section 5.3 sets a recommended fill ratio per mission: Conceal
//! 25 percent, Sign 50 percent, Mark 85 percent. This reports the ratio the
//! document actually reached and whether it clears the ceiling for the mission
//! it was built for.
//!
//! The denominator is the number of cover characters, because all four carriers
//! place at most one mark per cover character: the three invisible carriers
//! write one channel character after each visible one, and homoglyph
//! substitutes at most one letter per position. A carrier with a different
//! position model can state its own denominator through
//! `FidelityOptions::available_positions`, and if that figure is smaller than
//! the number of marks actually found, the check refuses rather than reporting
//! a ratio above one.
//!
//! Alongside the ratio, the figures the tool's own analyser would report on the
//! same document, so a fidelity verdict and a forensic verdict can be read side
//! by side instead of being confused for one another.

use crate::format::Mission;
use crate::metrics;

use super::align::Alignment;
use super::CheckVerdict;

/// Recommended fill ratio for a mission, SPEC_CORE_V2 section 5.3.
pub fn ceiling_for(mission: Mission) -> f64 {
    match mission {
        Mission::Conceal => 0.25,
        Mission::Sign => 0.50,
        Mission::Mark => 0.85,
    }
}

/// Result of the density check.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DensityCheck {
    pub verdict: CheckVerdict,
    /// Which ceiling the document is judged against.
    pub mission: String,
    pub marks: usize,
    pub positions_available: usize,
    /// `marks / positions_available`.
    pub fill_ratio: f64,
    /// The recommended ratio for the mission.
    pub ceiling: f64,
    pub clears_ceiling: bool,
    /// `metrics::noise_density` on the marked document, the figure the tool's
    /// own analyser reports.
    pub analyser_noise_density: f64,
    /// `metrics::homoglyph_density` on the marked document, likewise.
    pub analyser_homoglyph_density: f64,
}

impl DensityCheck {
    /// What an analyst finds, in `0.0..=1.0`.
    ///
    /// Zero while the document sits at or under the ceiling for its mission,
    /// then rising with how far past it the document went. Density is an
    /// analyst axis figure: a reader cannot see a fill ratio.
    pub fn analyst_risk(&self) -> f64 {
        if !self.verdict.ran() || self.clears_ceiling {
            return 0.0;
        }
        ((self.fill_ratio - self.ceiling) / (1.0 - self.ceiling)).clamp(0.0, 1.0)
    }

    fn could_not_run(reason: String, mission: Mission) -> Self {
        Self {
            verdict: CheckVerdict::Indeterminate { reason },
            mission: format!("{mission:?}"),
            marks: 0,
            positions_available: 0,
            fill_ratio: 0.0,
            ceiling: ceiling_for(mission),
            clears_ceiling: false,
            analyser_noise_density: 0.0,
            analyser_homoglyph_density: 0.0,
        }
    }
}

/// Run the check.
pub fn check(
    marked_text: &str,
    alignment: &Alignment,
    mission: Mission,
    available_positions: Option<usize>,
) -> DensityCheck {
    if let Some(reason) = &alignment.failure {
        return DensityCheck::could_not_run(
            format!("the cover and the marked document could not be paired: {reason}"),
            mission,
        );
    }

    let marks = alignment.marks();
    let positions = available_positions.unwrap_or(alignment.cover_len);

    if positions == 0 {
        return DensityCheck::could_not_run(
            "the cover offers no positions, so no fill ratio exists".into(),
            mission,
        );
    }
    if marks > positions {
        return DensityCheck::could_not_run(
            format!(
                "{marks} marks were found among {positions} declared positions, so the declared \
                 position count cannot be the one this document was written against"
            ),
            mission,
        );
    }

    let fill_ratio = marks as f64 / positions as f64;
    let ceiling = ceiling_for(mission);
    let clears_ceiling = fill_ratio <= ceiling;

    let overshoot = if clears_ceiling {
        0.0
    } else {
        ((fill_ratio - ceiling) / (1.0 - ceiling)).clamp(0.0, 1.0)
    };

    let verdict = if clears_ceiling {
        CheckVerdict::Clean
    } else if overshoot >= 0.5 {
        CheckVerdict::Conspicuous
    } else {
        CheckVerdict::Degraded
    };

    DensityCheck {
        verdict,
        mission: format!("{mission:?}"),
        marks,
        positions_available: positions,
        fill_ratio,
        ceiling,
        clears_ceiling,
        analyser_noise_density: metrics::noise_density(marked_text),
        analyser_homoglyph_density: metrics::homoglyph_density(marked_text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(cover: &str, marked: &str, mission: Mission) -> DensityCheck {
        let cover_chars: Vec<char> = cover.chars().collect();
        let marked_chars: Vec<char> = marked.chars().collect();
        let alignment = Alignment::of(&cover_chars, &marked_chars);
        check(marked, &alignment, mission, None)
    }

    fn marked_at(cover: &str, every: usize) -> String {
        cover
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                if i % every == 0 {
                    vec!['\u{200C}', c]
                } else {
                    vec![c]
                }
            })
            .collect()
    }

    #[test]
    fn the_three_mission_ceilings_are_the_spec_figures() {
        assert_eq!(ceiling_for(Mission::Conceal), 0.25);
        assert_eq!(ceiling_for(Mission::Sign), 0.50);
        assert_eq!(ceiling_for(Mission::Mark), 0.85);
    }

    #[test]
    fn an_empty_document_clears_every_ceiling() {
        let cover: String = "abcdefghij ".chars().cycle().take(220).collect();
        for mission in [Mission::Conceal, Mission::Sign, Mission::Mark] {
            let report = run(&cover, &cover, mission);
            assert_eq!(report.fill_ratio, 0.0);
            assert!(report.clears_ceiling);
            assert_eq!(report.verdict, CheckVerdict::Clean);
        }
    }

    #[test]
    fn a_document_at_half_fill_clears_sign_and_not_conceal() {
        let cover: String = "abcdefghij ".chars().cycle().take(220).collect();
        let marked = marked_at(&cover, 2);

        let conceal = run(&cover, &marked, Mission::Conceal);
        assert!((conceal.fill_ratio - 0.5).abs() < 0.01);
        assert!(!conceal.clears_ceiling);
        assert_ne!(conceal.verdict, CheckVerdict::Clean);

        let sign = run(&cover, &marked, Mission::Sign);
        assert!(sign.clears_ceiling, "ratio {}", sign.fill_ratio);
        assert_eq!(sign.verdict, CheckVerdict::Clean);
    }

    #[test]
    fn the_analyser_figures_travel_with_the_verdict() {
        let cover: String = "abcdefghij ".chars().cycle().take(220).collect();
        let marked = marked_at(&cover, 2);
        let report = run(&cover, &marked, Mission::Mark);

        assert!(
            report.analyser_noise_density > 0.0,
            "the tool's own analyser sees the channel characters"
        );
        assert!(report.clears_ceiling, "and the mission ceiling is still cleared");
    }

    #[test]
    fn a_declared_position_count_smaller_than_the_marks_found_is_refused() {
        let cover: String = "abcdefghij ".chars().cycle().take(220).collect();
        let marked = marked_at(&cover, 2);
        let cover_chars: Vec<char> = cover.chars().collect();
        let marked_chars: Vec<char> = marked.chars().collect();
        let alignment = Alignment::of(&cover_chars, &marked_chars);

        let report = check(&marked, &alignment, Mission::Sign, Some(10));
        match report.verdict {
            CheckVerdict::Indeterminate { reason } => {
                assert!(reason.contains("declared"), "reason was: {reason}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_check_refuses_when_the_documents_cannot_be_paired() {
        let report = run("the quick brown fox", "something else entirely", Mission::Sign);
        assert!(matches!(report.verdict, CheckVerdict::Indeterminate { .. }));
    }
}
