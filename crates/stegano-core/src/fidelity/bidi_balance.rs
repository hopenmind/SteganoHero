//! Check 2: bidi balance.
//!
//! Every embedding or override must be closed. An unclosed one reorders the
//! visible text that follows it, which is the single most conspicuous failure
//! this tool can produce, so it is reported by position and it is the only
//! finding in the whole module that scores a full one on its own.
//!
//! Three distinct findings, deliberately not merged into one number:
//!
//! - An unclosed initiator reorders what follows it. A reader sees it.
//! - A terminator with no opener is ignored by the bidirectional algorithm, so
//!   it reorders nothing on its own. It is still an unbalanced control and
//!   still a signal to anyone reading the codepoints, so it is reported and
//!   graded lower rather than passed over.
//! - A right to left mark sitting among neutrals is neither of those, and can
//!   still move a run of punctuation. Reported separately again.
//!
//! The cover is measured too. A document that arrives with its own unbalanced
//! control is not something the carrier did, and the report says which is which.

use super::align::Alignment;
use super::chars;
use super::CheckVerdict;

/// One control character, located.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ControlSite {
    /// Where it sits in cover character index space.
    pub cover_index: usize,
    /// Where it sits in the marked document.
    pub marked_index: usize,
    /// `U+202B` style label.
    pub codepoint: String,
    /// The Unicode name, so the report reads without a lookup.
    pub name: &'static str,
}

/// Result of the bidi balance check.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BidiBalanceCheck {
    pub verdict: CheckVerdict,
    /// Embeddings, overrides and isolates that are never closed. These reorder
    /// visible text.
    pub unclosed_initiators: Vec<ControlSite>,
    /// Terminators with no opener. Ignored by the bidirectional algorithm.
    pub orphan_terminators: Vec<ControlSite>,
    /// Right to left marks the carrier added next to punctuation or spaces,
    /// where they can change the order those neutrals display in.
    pub rtl_marks_beside_neutrals: Vec<ControlSite>,
    /// Directional marks added, balanced or not. Marks open nothing.
    pub directional_marks_added: usize,
    /// Imbalance the cover already had, which the carrier did not cause.
    pub cover_unclosed_initiators: usize,
    pub cover_orphan_terminators: usize,
    /// Unclosed initiators the carrier is responsible for.
    pub added_unclosed_initiators: usize,
    /// Orphan terminators the carrier is responsible for.
    pub added_orphan_terminators: usize,
}

impl BidiBalanceCheck {
    /// What a reader would see, in `0.0..=1.0`.
    ///
    /// An unclosed initiator reorders the visible text after it, which is the
    /// worst thing this tool can do to a document, so it takes the whole scale
    /// on its own. The other two findings are graded below it because neither
    /// reorders anything by itself.
    pub fn reader_risk(&self) -> f64 {
        if !self.verdict.ran() {
            return 0.0;
        }
        if self.added_unclosed_initiators > 0 {
            1.0
        } else if !self.rtl_marks_beside_neutrals.is_empty() {
            0.45
        } else if self.added_orphan_terminators > 0 {
            0.35
        } else {
            0.0
        }
    }

    fn could_not_run(reason: String) -> Self {
        Self {
            verdict: CheckVerdict::Indeterminate { reason },
            unclosed_initiators: Vec::new(),
            orphan_terminators: Vec::new(),
            rtl_marks_beside_neutrals: Vec::new(),
            directional_marks_added: 0,
            cover_unclosed_initiators: 0,
            cover_orphan_terminators: 0,
            added_unclosed_initiators: 0,
            added_orphan_terminators: 0,
        }
    }
}

/// Unclosed initiators and orphan terminators in one text, by character index.
///
/// The scope stack is the bidirectional algorithm's own rule: an initiator is
/// matched by the first terminator of its kind that is not already spoken for.
fn scan(text: &[char]) -> (Vec<usize>, Vec<usize>) {
    let mut stack: Vec<(usize, char)> = Vec::new();
    let mut orphans = Vec::new();

    for (index, &c) in text.iter().enumerate() {
        if chars::bidi_initiator_terminator(c).is_some() {
            stack.push((index, c));
            continue;
        }
        if chars::is_bidi_terminator(c) {
            let matching = stack.iter().rposition(|(_, opener)| {
                chars::bidi_initiator_terminator(*opener) == Some(c)
            });
            match matching {
                Some(at) => {
                    stack.truncate(at);
                }
                None => orphans.push(index),
            }
        }
    }

    (stack.into_iter().map(|(index, _)| index).collect(), orphans)
}

fn site(text: &[char], marked_index: usize, alignment: &Alignment) -> ControlSite {
    let c = text[marked_index];
    ControlSite {
        cover_index: alignment
            .marked_to_cover
            .get(marked_index)
            .copied()
            .unwrap_or(alignment.cover_len),
        marked_index,
        codepoint: chars::codepoint_label(c),
        name: chars::control_name(c),
    }
}

/// Run the check.
pub fn check(
    cover: &[char],
    marked: &[char],
    alignment: &Alignment,
    max_locations: usize,
) -> BidiBalanceCheck {
    if let Some(reason) = &alignment.failure {
        return BidiBalanceCheck::could_not_run(format!(
            "the cover and the marked document could not be paired: {reason}"
        ));
    }

    let (cover_unclosed, cover_orphans) = scan(cover);
    let (marked_unclosed, marked_orphans) = scan(marked);

    let unclosed_initiators: Vec<ControlSite> = marked_unclosed
        .iter()
        .take(max_locations)
        .map(|&at| site(marked, at, alignment))
        .collect();
    let orphan_terminators: Vec<ControlSite> = marked_orphans
        .iter()
        .take(max_locations)
        .map(|&at| site(marked, at, alignment))
        .collect();

    let mut directional_marks_added = 0usize;
    let mut rtl_marks_beside_neutrals = Vec::new();
    for insertion in &alignment.insertions {
        if !chars::is_directional_mark(insertion.character) {
            continue;
        }
        directional_marks_added += 1;
        if !chars::is_rtl_mark(insertion.character) {
            continue;
        }
        let before = insertion
            .marked_index
            .checked_sub(1)
            .and_then(|i| marked.get(i))
            .copied();
        let after = marked.get(insertion.marked_index + 1).copied();
        let touches_neutral = before.map(chars::is_bidi_neutral).unwrap_or(false)
            || after.map(chars::is_bidi_neutral).unwrap_or(false);
        if touches_neutral && rtl_marks_beside_neutrals.len() < max_locations {
            rtl_marks_beside_neutrals.push(site(marked, insertion.marked_index, alignment));
        }
    }

    // Only imbalance the carrier introduced counts against it. A cover that
    // arrives unbalanced is a finding about the cover, reported as such.
    let added_unclosed = marked_unclosed.len().saturating_sub(cover_unclosed.len());
    let added_orphans = marked_orphans.len().saturating_sub(cover_orphans.len());

    let verdict = if added_unclosed > 0 {
        CheckVerdict::Conspicuous
    } else if !rtl_marks_beside_neutrals.is_empty() || added_orphans > 0 {
        CheckVerdict::Degraded
    } else {
        CheckVerdict::Clean
    };

    BidiBalanceCheck {
        verdict,
        unclosed_initiators,
        orphan_terminators,
        rtl_marks_beside_neutrals,
        directional_marks_added,
        cover_unclosed_initiators: cover_unclosed.len(),
        cover_orphan_terminators: cover_orphans.len(),
        added_unclosed_initiators: added_unclosed,
        added_orphan_terminators: added_orphans,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(cover: &str, marked: &str) -> BidiBalanceCheck {
        let cover_chars: Vec<char> = cover.chars().collect();
        let marked_chars: Vec<char> = marked.chars().collect();
        let alignment = Alignment::of(&cover_chars, &marked_chars);
        check(&cover_chars, &marked_chars, &alignment, 32)
    }

    #[test]
    fn a_clean_document_is_balanced() {
        let text = "the quarterly report is attached";
        let report = run(text, text);
        assert_eq!(report.verdict, CheckVerdict::Clean);
        assert_eq!(report.reader_risk(), 0.0);
    }

    #[test]
    fn an_unclosed_embedding_scores_the_maximum_on_its_own() {
        let report = run("the report", "the \u{202B}report");
        assert_eq!(report.unclosed_initiators.len(), 1);
        assert_eq!(report.unclosed_initiators[0].codepoint, "U+202B");
        assert_eq!(report.unclosed_initiators[0].name, "RIGHT-TO-LEFT EMBEDDING");
        assert_eq!(report.reader_risk(), 1.0);
        assert_eq!(report.verdict, CheckVerdict::Conspicuous);
    }

    #[test]
    fn an_unclosed_override_is_caught_too() {
        let report = run("the report", "the \u{202E}report");
        assert_eq!(report.unclosed_initiators.len(), 1);
        assert_eq!(report.verdict, CheckVerdict::Conspicuous);
    }

    #[test]
    fn an_unclosed_isolate_needs_its_own_terminator() {
        // A pop directional formatting does not close an isolate.
        let report = run("the report", "the \u{2066}rep\u{202C}ort");
        assert_eq!(report.unclosed_initiators.len(), 1);
        assert_eq!(report.orphan_terminators.len(), 1);
    }

    #[test]
    fn a_matched_pair_is_balanced() {
        let report = run("the report", "the \u{202B}rep\u{202C}ort");
        assert!(report.unclosed_initiators.is_empty());
        assert!(report.orphan_terminators.is_empty());
        assert_eq!(report.verdict, CheckVerdict::Clean);
    }

    #[test]
    fn a_terminator_with_no_opener_is_graded_below_an_unclosed_opener() {
        let report = run("the report", "the \u{202C}report");
        assert!(report.unclosed_initiators.is_empty());
        assert_eq!(report.orphan_terminators.len(), 1);
        assert_eq!(report.orphan_terminators[0].cover_index, 4);
        assert!(report.reader_risk() > 0.0 && report.reader_risk() < 1.0);
        assert_eq!(report.verdict, CheckVerdict::Degraded);
    }

    /// The bidi carrier writes U+202C as a byte delimiter with nothing to pop.
    /// Every document it produces therefore carries orphan terminators, and the
    /// check has to say so rather than pass it as balanced.
    #[test]
    fn the_delimiter_pattern_the_bidi_carrier_writes_is_reported() {
        let cover = "the quarterly report is attached for review by the board";
        let marked: String = cover
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                if i > 0 && i % 9 == 0 {
                    vec![c, '\u{202C}']
                } else {
                    vec![c, '\u{200E}']
                }
            })
            .collect();

        let report = run(cover, &marked);
        assert!(
            report.orphan_terminators.len() >= 5,
            "expected the delimiters to be reported, got {}",
            report.orphan_terminators.len()
        );
        assert_ne!(report.verdict, CheckVerdict::Clean);
    }

    #[test]
    fn a_right_to_left_mark_beside_punctuation_is_reported() {
        let report = run("the report.", "the report\u{200F}.");
        assert_eq!(report.rtl_marks_beside_neutrals.len(), 1);
        assert_eq!(report.directional_marks_added, 1);
        assert_eq!(report.verdict, CheckVerdict::Degraded);
    }

    #[test]
    fn imbalance_the_cover_arrived_with_is_attributed_to_the_cover() {
        let cover = "the \u{202B}report";
        let report = run(cover, cover);
        assert_eq!(report.cover_unclosed_initiators, 1);
        assert_eq!(report.unclosed_initiators.len(), 1);
        assert_eq!(report.added_unclosed_initiators, 0);
        assert_eq!(
            report.reader_risk(),
            0.0,
            "the carrier added nothing, so it is charged nothing"
        );
        assert_eq!(report.verdict, CheckVerdict::Clean);
    }

    #[test]
    fn the_check_refuses_when_the_documents_cannot_be_paired() {
        let report = run("the quick brown fox", "something else entirely");
        assert!(matches!(report.verdict, CheckVerdict::Indeterminate { .. }));
    }
}
