//! Confidence-guided scrub: use a model's per-token log-probabilities to move a
//! text toward model-preferred wording, disrupting a word-choice watermark while
//! measuring the effect.
//!
//! At each synonym position it tries the other variant and keeps the flip only
//! when the model prefers it (lower perplexity). This both breaks the token
//! sequence a watermark rides on and improves fluency, and it reports perplexity
//! before and after. Best-effort by nature: with no key it cannot verify a
//! watermark, so it never claims a removal.

use crate::backend::BackendError;
use crate::logprob::{perplexity, LogprobProvider};
use crate::mark::{matched_positions, rebuild};

/// The result of a confidence-guided scrub: the perturbed text and the measured
/// perplexity on each side.
#[derive(Debug)]
pub struct GuidedScrubReport {
    pub text: String,
    pub before_perplexity: Option<f64>,
    pub after_perplexity: Option<f64>,
    pub positions_changed: usize,
}

/// Flip synonym positions toward the variant the model prefers, up to
/// `max_fraction` of the positions, guided by the provider's log-probabilities.
pub fn scrub_confidence_guided<P: LogprobProvider>(
    text: &str,
    provider: &P,
    max_fraction: f64,
) -> Result<GuidedScrubReport, BackendError> {
    let total = matched_positions(text).len();
    let budget = ((total as f64) * max_fraction.clamp(0.0, 1.0)).round() as usize;

    let before = perplexity(&provider.sequence_logprobs(text)?);
    let mut current = text.to_string();
    let mut current_ppl = before;
    let mut changed = 0usize;

    for k in 0..total {
        if changed >= budget {
            break;
        }
        // The candidate flips only the k-th synonym position to its other
        // variant. Both variants are group words, so the position count and
        // order are stable, and k keeps meaning the same position.
        let candidate = rebuild(&current, |j, _, v| if j == k { Some(1 - v) } else { None });
        let candidate_ppl = perplexity(&provider.sequence_logprobs(&candidate)?);

        // Keep the flip only when the model prefers it (strictly lower
        // perplexity), so the scrub never makes the text less fluent.
        if let (Some(c), Some(p)) = (candidate_ppl, current_ppl) {
            if c < p {
                current = candidate;
                current_ppl = candidate_ppl;
                changed += 1;
            }
        }
    }

    Ok(GuidedScrubReport {
        text: current,
        before_perplexity: before,
        after_perplexity: current_ppl,
        positions_changed: changed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A text-aware mock scorer: it penalizes the variant-1 synonym words, so
    /// flipping them to their canonical form lowers perplexity. This lets the
    /// guidance be tested deterministically without a model.
    struct WordScorer;

    impl LogprobProvider for WordScorer {
        fn sequence_logprobs(&self, text: &str) -> Result<Vec<f64>, BackendError> {
            let dispreferred = ["large", "little", "quick", "start", "finish", "purchase"];
            let logprobs = text
                .split_whitespace()
                .map(|word| {
                    let clean = word
                        .trim_matches(|c: char| !c.is_alphanumeric())
                        .to_lowercase();
                    if dispreferred.contains(&clean.as_str()) {
                        -3.0
                    } else {
                        -0.3
                    }
                })
                .collect();
            Ok(logprobs)
        }
    }

    #[test]
    fn guided_scrub_moves_toward_model_preference() {
        let text = "The large fox and the quick hound start early.";
        let report = scrub_confidence_guided(text, &WordScorer, 1.0).unwrap();

        // The dispreferred variants (large, quick, start) are flipped to their
        // canonical forms, which the scorer prefers.
        assert_eq!(report.positions_changed, 3);
        assert!(!report.text.contains("large"));
        assert!(!report.text.contains("quick"));

        // Perplexity strictly improved, and it is measured, not asserted.
        let before = report.before_perplexity.unwrap();
        let after = report.after_perplexity.unwrap();
        assert!(after < before, "after {after} should be below before {before}");
    }

    #[test]
    fn a_clean_text_is_left_alone() {
        // No dispreferred variant present, so no flip lowers perplexity.
        let text = "The big fox and the fast hound begin early.";
        let report = scrub_confidence_guided(text, &WordScorer, 1.0).unwrap();
        assert_eq!(report.positions_changed, 0);
        assert_eq!(report.text, text);
    }

    /// Live check with a real model. Ignored by default: set
    /// STEGANO_WM_TEST_MODEL to a GGUF path and run with
    /// `--features embedded-llama -- --ignored`.
    #[cfg(feature = "embedded-llama")]
    #[test]
    #[ignore = "needs a real GGUF (STEGANO_WM_TEST_MODEL)"]
    fn live_guided_scrub_does_not_worsen_perplexity() {
        use crate::EmbeddedLlamaBackend;
        let path = std::env::var("STEGANO_WM_TEST_MODEL")
            .expect("set STEGANO_WM_TEST_MODEL to a GGUF path");
        let model = EmbeddedLlamaBackend::load(&path, "You rewrite text.")
            .expect("the model loads");
        let text =
            "We begin the large project to help numerous people and start the small work quickly.";
        let report = scrub_confidence_guided(text, &model, 1.0).expect("the scrub runs");
        let before = report.before_perplexity.unwrap();
        let after = report.after_perplexity.unwrap();
        assert!(after <= before + 1e-6, "guided scrub must not worsen perplexity: before {before}, after {after}");
    }
}
