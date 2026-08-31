//! The model-free scrub floor: perturb the token sequence a word-choice
//! watermark rides on, without a model and without a key.
//!
//! This is deliberately the WEAK, always-available tier. With no model it cannot
//! measure a watermark, and with no key it cannot verify one, so it never claims
//! to have removed anything. It flips a strided fraction of synonym choices,
//! which changes the tokens (and the hashed context that follows), and it
//! reports exactly what it changed. A guaranteed rewrite is the model's job, in
//! a later tier; this floor only disrupts, and says so.

use crate::mark::{matched_positions, rebuild};

/// How aggressively the scrub perturbs synonym positions.
#[derive(Clone, Copy, Debug)]
pub enum Aggression {
    /// Every third synonym position.
    Light,
    /// Every second synonym position.
    Medium,
    /// Every synonym position.
    Heavy,
}

impl Aggression {
    fn stride(self) -> usize {
        match self {
            Aggression::Light => 3,
            Aggression::Medium => 2,
            Aggression::Heavy => 1,
        }
    }
}

/// The result of a model-free scrub: the perturbed text and an honest count.
/// No z-score, because without the key there is none to report.
#[derive(Debug)]
pub struct ScrubReport {
    pub text: String,
    pub positions_total: usize,
    pub positions_changed: usize,
}

/// Flip a strided fraction of synonym choices to their other variant. The
/// insertion stays surgical (only group words change), so the canonical form is
/// preserved. Best-effort disruption, never a claimed removal.
pub fn scrub_synonyms(text: &str, aggression: Aggression) -> ScrubReport {
    let total = matched_positions(text).len();
    let stride = aggression.stride();
    let mut changed = 0usize;
    let out = rebuild(text, |k, _, v| {
        if k % stride == 0 {
            changed += 1;
            Some(1 - v)
        } else {
            None
        }
    });
    ScrubReport {
        text: out,
        positions_total: total,
        positions_changed: changed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_synonyms_means_no_change() {
        let report = scrub_synonyms("nothing here to touch at all", Aggression::Heavy);
        assert_eq!(report.positions_total, 0);
        assert_eq!(report.positions_changed, 0);
        assert_eq!(report.text, "nothing here to touch at all");
    }

    #[test]
    fn heavy_flips_every_position() {
        let report = scrub_synonyms("big small fast", Aggression::Heavy);
        assert_eq!(report.positions_total, 3);
        assert_eq!(report.positions_changed, 3);
        assert_eq!(report.text, "large little quick");
    }
}
