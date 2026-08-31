//! SEC-WM2 core: the pluggable inference backend and the rewrite orchestration.
//!
//! A word-choice watermark can only be reduced by rewriting the wording, which
//! is a model's job. This module abstracts "a thing that rewrites text" behind
//! one trait, so the same orchestration drives an embedded model, a local server
//! (Ollama, LM Studio), or an online model reached over REST or MCP. Two rules,
//! both load-bearing:
//!
//! 1. The model is an UNTRUSTED transform. Its output is validated (refusal,
//!    bloat, collapse) and, if unusable, discarded in favour of the pure-Rust
//!    floor, never passed through as if it were a faithful rewrite (invariant 2).
//!    This is the A-typik `IsUnusable` pattern.
//! 2. The online re-mark parade (owner directive): after a backend rewrite, a
//!    LOCAL re-clean pass runs on the output, so a model that re-watermarks its
//!    own output at the character or metadata layer is neutralized behind it.
//!
//! The choice of backend, and the labeling of an online one ("this sends your
//! text to X"), is the caller's policy; local is the sovereign default. This
//! trait is neutral about where the model runs.

use crate::scrub::{scrub_synonyms, Aggression};

/// Anything that can rewrite text: embedded model, local server, or online.
pub trait InferenceBackend {
    fn rewrite(&self, text: &str) -> Result<String, BackendError>;

    /// Where this backend runs. Defaults to `Online`, the fail-safe assumption:
    /// a backend is treated as external (disclaimer required) until it declares
    /// itself local. Ollama, LM Studio and embedded llama.cpp return `Local`.
    fn locality(&self) -> Locality {
        Locality::Online
    }
}

/// Why a backend could not produce a rewrite at all.
#[derive(Debug, PartialEq, Eq)]
pub enum BackendError {
    /// The backend is not reachable or not configured.
    Unavailable(String),
    /// The backend answered, but with nothing usable.
    Empty,
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::Unavailable(reason) => write!(f, "backend unavailable: {reason}"),
            BackendError::Empty => write!(f, "the backend returned nothing usable"),
        }
    }
}

impl std::error::Error for BackendError {}

/// Where a backend runs, which decides whether a call leaves the machine.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Locality {
    /// On the user's own machine: an embedded model, or a local server (Ollama,
    /// LM Studio, llama.cpp). Content never leaves the device.
    Local,
    /// A third-party service reached over the network. Content leaves the
    /// machine, so the user must be shown the disclaimer before the call.
    Online,
}

/// Whether a call to this locality must surface the disclaimer before content
/// leaves the machine. Local backends are exempt (owner directive); online
/// backends are not.
pub fn requires_disclaimer(locality: Locality) -> bool {
    matches!(locality, Locality::Online)
}

/// Refusal raised by the orchestration when a gate is not satisfied.
#[derive(Debug, PartialEq, Eq)]
pub enum GateError {
    /// An online backend was asked to run without the disclaimer being shown.
    DisclaimerRequired,
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateError::DisclaimerRequired => {
                write!(f, "an online backend requires the disclaimer to be shown first")
            }
        }
    }
}

impl std::error::Error for GateError {}

/// Why a model's output was rejected as an unfaithful transform.
#[derive(Debug, PartialEq, Eq)]
pub enum RewriteReject {
    /// The model refused or lectured instead of transforming.
    Refusal,
    /// The output is much longer than the input: added commentary.
    Bloat,
    /// The output is far shorter than the input: dropped content.
    Collapse,
    /// The output is empty.
    Empty,
}

/// Signatures that mean the model refused or added framing rather than
/// transforming. Small instruct models do this; the app must not pass it on.
const REFUSAL_MARKERS: &[&str] = &[
    "i can't",
    "i cannot",
    "i can not",
    "i'm sorry",
    "i am sorry",
    "i apologize",
    "as an ai",
    "as a language model",
    "i'm unable",
    "i am unable",
    "i won't",
    "i will not",
    "i must decline",
    "i must refuse",
    "cannot assist",
    "can't assist",
];

/// Validate a model rewrite against its input. Returns the trimmed output when
/// it looks like a faithful transform, or a named rejection otherwise.
pub fn validate_rewrite(input: &str, output: &str) -> Result<String, RewriteReject> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Err(RewriteReject::Empty);
    }
    let low = trimmed.to_lowercase();
    if REFUSAL_MARKERS.iter().any(|m| low.contains(m)) {
        return Err(RewriteReject::Refusal);
    }
    let out_len = trimmed.chars().count() as f64;
    let in_len = input.chars().count() as f64;
    if out_len > in_len * 1.5 + 40.0 {
        return Err(RewriteReject::Bloat);
    }
    if in_len > 0.0 && out_len < in_len * 0.3 {
        return Err(RewriteReject::Collapse);
    }
    Ok(trimmed.to_string())
}

/// Where the returned text came from.
#[derive(Debug, PartialEq, Eq)]
pub enum ScrubSource {
    /// A validated backend rewrite, followed by the local re-clean parade.
    Backend,
    /// The pure-Rust floor, used because the backend failed or was rejected.
    Floor,
}

/// The result of a backend-driven scrub.
#[derive(Debug)]
pub struct BackendScrubReport {
    pub text: String,
    pub source: ScrubSource,
    /// True when the local re-clean parade ran (only on the backend path).
    pub reclean_applied: bool,
    /// Where the backend that produced this ran.
    pub locality: Locality,
}

/// Rewrite `text` with `backend`, validate the output, and on success run the
/// local re-clean `reclean` over it (the parade). If the backend fails or its
/// output is rejected, fall back to the pure-Rust floor at `floor` aggression.
/// Never returns unvalidated model output.
///
/// The disclaimer gate is enforced here, before any content leaves the machine:
/// an online backend refuses with `GateError::DisclaimerRequired` unless
/// `disclaimer_shown` is true, so a surface cannot make an external call without
/// first surfacing the disclaimer. Local backends ignore the flag.
pub fn scrub_via_backend<B, C>(
    text: &str,
    backend: &B,
    reclean: C,
    floor: Aggression,
    disclaimer_shown: bool,
) -> Result<BackendScrubReport, GateError>
where
    B: InferenceBackend,
    C: Fn(&str) -> String,
{
    let locality = backend.locality();
    if requires_disclaimer(locality) && !disclaimer_shown {
        return Err(GateError::DisclaimerRequired);
    }

    let usable = backend
        .rewrite(text)
        .ok()
        .and_then(|out| validate_rewrite(text, &out).ok());

    let report = match usable {
        Some(valid) => BackendScrubReport {
            text: reclean(&valid),
            source: ScrubSource::Backend,
            reclean_applied: true,
            locality,
        },
        None => BackendScrubReport {
            text: scrub_synonyms(text, floor).text,
            source: ScrubSource::Floor,
            reclean_applied: false,
            locality,
        },
    };
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_a_faithful_rewrite() {
        let input = "We begin the big project to help many people today.";
        let output = "We start the large effort to assist numerous folks today.";
        assert_eq!(validate_rewrite(input, output), Ok(output.to_string()));
    }

    #[test]
    fn validate_rejects_refusal_bloat_collapse_empty() {
        let input = "Rewrite this sentence with different wording please now.";
        assert_eq!(
            validate_rewrite(input, "I'm sorry, I can't help with that."),
            Err(RewriteReject::Refusal)
        );
        let bloat = "word ".repeat(200);
        assert_eq!(validate_rewrite(input, &bloat), Err(RewriteReject::Bloat));
        assert_eq!(validate_rewrite(input, "ok"), Err(RewriteReject::Collapse));
        assert_eq!(validate_rewrite(input, "   "), Err(RewriteReject::Empty));
    }

    #[test]
    fn disclaimer_is_required_only_for_online() {
        assert!(requires_disclaimer(Locality::Online));
        assert!(!requires_disclaimer(Locality::Local));
    }
}
