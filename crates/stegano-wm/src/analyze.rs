//! The word-mark analysis capstone: run the pure-Rust detections and report
//! them under an honest verdict taxonomy.
//!
//! Every surface (GUI, CLI, MCP, REST) reports through this taxonomy, so the
//! certainty of a finding is never blurred. The one thing this tier cannot do,
//! name a secret-key token-sampling watermark, is emitted as an explicit
//! IMPOSSIBLE finding on every analysis, so the limit is stated, never implied.

use serde::Serialize;

use crate::lexical::{acrostic_contains, read_lexical_channel};
use crate::mark::has_signature;
use crate::registry::default_registry;
use crate::tokenize::toy_tokenize;

/// The epistemic level of a finding, from certain to honestly out of reach.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Exact test replayed or crypto verified locally.
    Certain,
    /// Calibrated detector with a stated false-positive rate. Reserved for the
    /// model-bearing tier; the pure-Rust floor does not emit it.
    Probable,
    /// A heuristic symptom, high false-positive rate.
    Indication,
    /// Structurally out of local reach, named for honesty.
    Impossible,
}

/// One finding in a word-mark analysis.
#[derive(Debug, Serialize)]
pub struct Finding {
    pub verdict: Verdict,
    pub label: String,
    pub detail: String,
}

/// The full pure-Rust analysis of a text for word-choice marks.
#[derive(Debug, Serialize)]
pub struct WordmarkReport {
    pub findings: Vec<Finding>,
}

/// Inputs that unlock certain checks: our own key, a suspected acrostic.
pub struct AnalyzeOptions {
    /// If set, test for our own keyed mark under this key.
    pub our_key: Option<[u8; 32]>,
    /// If set, test whether an acrostic contains this target.
    pub acrostic_target: Option<String>,
    /// Named-hit threshold for the public-config registry.
    pub tau: f64,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        Self {
            our_key: None,
            acrostic_target: None,
            tau: 5.0,
        }
    }
}

/// Analyze `text` for word-choice marks, pure-Rust tier. Emits certain findings
/// where the pattern, table, or key is known, an indication where a channel is
/// merely present, and always one impossible finding naming the structural wall.
pub fn analyze(text: &str, opts: &AnalyzeOptions) -> WordmarkReport {
    let mut findings = Vec::new();

    // Certain: a public-config watermark whose partition we can replay.
    if let Some((name, z)) = default_registry().best_hit(&toy_tokenize(text), opts.tau) {
        findings.push(Finding {
            verdict: Verdict::Certain,
            label: "public-config watermark".to_string(),
            detail: format!("matches registry config {name} (z={z:.2})"),
        });
    }

    // Certain: our own keyed mark, if a key was supplied.
    if let Some(key) = &opts.our_key {
        if has_signature(text, key) {
            findings.push(Finding {
                verdict: Verdict::Certain,
                label: "our keyed mark".to_string(),
                detail: "our own signature is present under the given key".to_string(),
            });
        }
    }

    // Certain: a suspected acrostic, if a target was supplied.
    if let Some(target) = &opts.acrostic_target {
        if acrostic_contains(text, target) {
            findings.push(Finding {
                verdict: Verdict::Certain,
                label: "acrostic".to_string(),
                detail: format!("an acrostic contains \"{target}\""),
            });
        }
    }

    // Indication: a synonym channel is present. Presence is not proof of intent.
    let channel = read_lexical_channel(text);
    if !channel.is_empty() {
        findings.push(Finding {
            verdict: Verdict::Indication,
            label: "synonym channel".to_string(),
            detail: format!(
                "{} synonym positions carry a readable channel; deliberate placement not proven",
                channel.len()
            ),
        });
    }

    // Impossible, on every analysis: the structural wall, stated not implied.
    findings.push(Finding {
        verdict: Verdict::Impossible,
        label: "secret-key watermark".to_string(),
        detail: "a token-sampling watermark with a secret vendor key cannot be certainly \
                 detected, proven absent, or attributed, without that key"
            .to_string(),
    });

    WordmarkReport { findings }
}
