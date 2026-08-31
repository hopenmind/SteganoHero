//! Per-token log-probabilities and the perplexity built from them.
//!
//! This is the signal the keyless detectors need. A model that can score a
//! sequence implements [`LogprobProvider`]; the pure math here turns those
//! log-probabilities into perplexity and is tested without a model. The real
//! provider is the embedded llama.cpp backend (feature `embedded-llama`); tests
//! use a deterministic mock, which is the correct way to test the math.

use crate::backend::BackendError;

/// A model that can score a sequence: the per-token natural-log probability of
/// each actual token given its preceding context. One value per scored token.
///
/// A backend that cannot provide this (a plain chat endpoint, an online model)
/// simply does not implement the trait; the detectors that need it then require
/// a provider that does, rather than degrading silently.
pub trait LogprobProvider {
    fn sequence_logprobs(&self, text: &str) -> Result<Vec<f64>, BackendError>;
}

/// Mean negative log-likelihood (the cross-entropy) of the scored tokens, in
/// nats. `None` when there is nothing to score.
pub fn mean_neg_logprob(logprobs: &[f64]) -> Option<f64> {
    if logprobs.is_empty() {
        return None;
    }
    let sum: f64 = logprobs.iter().map(|lp| -lp).sum();
    Some(sum / logprobs.len() as f64)
}

/// Perplexity: the exponential of the mean negative log-likelihood. Lower means
/// the text was more predictable to the model. `None` for an empty sequence.
pub fn perplexity(logprobs: &[f64]) -> Option<f64> {
    mean_neg_logprob(logprobs).map(f64::exp)
}

/// The log-softmax value at index `token` of a logit vector: the natural-log
/// probability the model assigned to that token. Numerically stable (shifts by
/// the max before exponentiating). Used by the embedded provider to turn raw
/// logits into a per-token log-probability; only that feature and the tests use
/// it, so it is dead in a plain default build.
#[cfg_attr(not(any(feature = "embedded-llama", test)), allow(dead_code))]
pub(crate) fn token_logprob(logits: &[f32], token: usize) -> f64 {
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max) as f64;
    let lse = max
        + logits
            .iter()
            .map(|&x| ((x as f64) - max).exp())
            .sum::<f64>()
            .ln();
    (logits[token] as f64) - lse
}

#[cfg(test)]
pub(crate) mod mock {
    use super::*;

    /// A deterministic logprob provider for tests: it returns the logprobs it
    /// was given, ignoring the text. This lets the detector math be tested with
    /// known inputs and no model.
    pub struct MockLogprobs(pub Vec<f64>);

    impl LogprobProvider for MockLogprobs {
        fn sequence_logprobs(&self, _text: &str) -> Result<Vec<f64>, BackendError> {
            Ok(self.0.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certain_tokens_have_perplexity_one() {
        // logprob 0 means probability 1 for every token, so perplexity is 1.
        assert_eq!(perplexity(&[0.0, 0.0, 0.0]), Some(1.0));
    }

    #[test]
    fn perplexity_rises_as_the_model_is_more_surprised() {
        let confident = perplexity(&[-0.1, -0.1, -0.1]).unwrap();
        let surprised = perplexity(&[-2.0, -2.0, -2.0]).unwrap();
        assert!(surprised > confident, "surprised={surprised} confident={confident}");
    }

    #[test]
    fn an_empty_sequence_has_no_perplexity() {
        assert_eq!(perplexity(&[]), None);
        assert_eq!(mean_neg_logprob(&[]), None);
    }

    #[test]
    fn token_logprob_is_a_stable_log_softmax() {
        // Two equal logits: each token has probability 1/2, so the log is ln(0.5).
        assert!((token_logprob(&[0.0, 0.0], 0) - 0.5_f64.ln()).abs() < 1e-9);
        // Skewed logits ln(3) vs ln(1): softmax is [0.75, 0.25].
        let skewed = [3.0_f32.ln(), 1.0_f32.ln()];
        assert!((token_logprob(&skewed, 0) - 0.75_f64.ln()).abs() < 1e-6);
        assert!((token_logprob(&skewed, 1) - 0.25_f64.ln()).abs() < 1e-6);
    }

    #[test]
    fn the_mock_returns_its_logprobs() {
        use super::mock::MockLogprobs;
        let provider = MockLogprobs(vec![-0.5, -1.5]);
        assert_eq!(provider.sequence_logprobs("anything").unwrap(), vec![-0.5, -1.5]);
    }
}
