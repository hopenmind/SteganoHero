//! A green-list watermark configuration and the exact z-score that detects it.

use crate::prf::{derive_key, prf64};

/// One green-list watermark configuration: a keyed partition of the vocabulary
/// biased at generation time (the marked model favours "green" tokens).
/// Detection replays the partition and counts how many tokens landed green.
///
/// This is the KGW / n-gram family (Kirchenbauer et al. 2023). With `h == 1`
/// it mirrors the `lefthash` scheme; with `h == 4` it is the structural analog
/// of a SynthID-Text five-gram.
///
/// Honesty about scope: the partition uses our own keyed SHA-256 PRF, so this
/// detects marks made with the SAME scheme, that is, the entries of our public
/// registry. Bit-exact compatibility with a specific library layout (for
/// example transformers `lefthash`: `hashing_key * prev_token_id`, then an
/// MT19937 vocabulary permutation) is a separate, separately tested slice. A
/// secret production key never appears at all: without it the test has no power.
#[derive(Clone, Debug)]
pub struct WmConfig {
    /// A stable, technique-neutral name shown in a report when this config hits.
    pub name: String,
    key: [u8; 32],
    /// Target green fraction under H0 (a typical public default is 0.25).
    pub gamma: f64,
    /// Context width: the number of preceding tokens that seed the partition.
    pub h: usize,
}

impl WmConfig {
    /// Build a config from a public seed and a name (the key is derived from
    /// both, so a shared seed with distinct names yields independent configs).
    pub fn new(name: &str, seed: u64, gamma: f64, h: usize) -> Self {
        Self {
            name: name.to_string(),
            key: derive_key(seed, name),
            gamma,
            h,
        }
    }

    /// True when `tok` falls in the green partition for the given context.
    pub fn is_green(&self, ctx: &[u32], tok: u32) -> bool {
        let threshold = (self.gamma * u64::MAX as f64) as u64;
        prf64(&self.key, ctx, tok) < threshold
    }
}

/// Exact green-list z-score of a token sequence under one config.
///
/// Under H0 (unmarked text, or the wrong key) `z ~ N(0, 1)`; a text marked with
/// this exact config pushes `z` up in proportion to the bias and the length.
/// Positions `[0, h)` have no full context and are not scored. A sequence too
/// short to score returns `0.0`.
pub fn detect_z(config: &WmConfig, tokens: &[u32]) -> f64 {
    let h = config.h;
    if tokens.len() <= h {
        return 0.0;
    }
    let n = tokens.len() - h;
    let mut green = 0usize;
    for i in h..tokens.len() {
        if config.is_green(&tokens[i - h..i], tokens[i]) {
            green += 1;
        }
    }
    let g = green as f64;
    let nn = n as f64;
    let gamma = config.gamma;
    (g - gamma * nn) / (nn * gamma * (1.0 - gamma)).sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_fraction_tracks_gamma() {
        // Over many tokens the green fraction approaches gamma (the PRF is
        // uniform), which is the whole basis of the z-test's calibration.
        let config = WmConfig::new("test", 1, 0.25, 1);
        let ctx = [42u32];
        let mut green = 0usize;
        let total = 8000u32;
        for tok in 0..total {
            if config.is_green(&ctx, tok) {
                green += 1;
            }
        }
        let fraction = green as f64 / total as f64;
        assert!((fraction - 0.25).abs() < 0.03, "green fraction was {fraction}");
    }

    #[test]
    fn unmarked_sequence_scores_near_zero() {
        // A sequence that was NOT biased toward green scores near zero, so an
        // ordinary text never reads as a false positive hit.
        let config = WmConfig::new("test", 1, 0.25, 1);
        let tokens: Vec<u32> = (0..400u32).collect();
        let z = detect_z(&config, &tokens);
        assert!(z.abs() < 4.0, "unmarked sequence scored z={z}");
    }

    #[test]
    fn too_short_is_zero() {
        let config = WmConfig::new("test", 1, 0.25, 4);
        assert_eq!(detect_z(&config, &[1, 2, 3]), 0.0);
    }
}
