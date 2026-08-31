//! `stegano-wm`: the word-choice (statistical / token-sampling) watermark layer.
//!
//! This is the pure-Rust, no-model floor of the SEC-WM work. It replays PUBLIC
//! green-list watermark configurations to detect a mark EXACTLY at the level of
//! the test (a CERTAIN verdict), and stays honestly silent on a secret-key mark
//! it cannot reach without the vendor key. No LLM, no weight, fully offline.
//!
//! What it is NOT, and cannot be, stated up front because the honesty is the
//! product: it does not certainly detect a production secret-key watermark
//! (production text-watermarking systems), it does not prove a text is unmarked, and it
//! does not prove authorship. Those limits are structural, not an engineering
//! gap: without the key the marginal test has zero power, and distortion-free
//! schemes are provably undetectable without it (Christ, Gunn, Zamir 2023).
//!
//! The later tiers (an `InferenceBackend` for local or online rewrite, and an
//! opt-in embedded-model detector) live in separate slices; this crate carries
//! only what is exact and weightless.

mod analyze;
mod backend;
mod binoculars;
mod config;
#[cfg(feature = "embedded-llama")]
mod embedded;
mod guided;
mod http;
mod lexical;
mod logprob;
mod mark;
mod prf;
mod registry;
mod scrub;
mod synonyms;
mod tokenize;

pub use analyze::{analyze, AnalyzeOptions, Finding, Verdict, WordmarkReport};
pub use binoculars::{analyze_with_ai_origin, binoculars, binoculars_finding, binoculars_score};
#[cfg(feature = "embedded-llama")]
pub use embedded::EmbeddedLlamaBackend;
pub use logprob::{mean_neg_logprob, perplexity, LogprobProvider};
pub use backend::{
    requires_disclaimer, scrub_via_backend, validate_rewrite, BackendError, BackendScrubReport,
    GateError, InferenceBackend, Locality, RewriteReject, ScrubSource,
};
pub use http::HttpBackend;
pub use config::{detect_z, WmConfig};
pub use guided::{scrub_confidence_guided, GuidedScrubReport};
pub use lexical::{acrostic_contains, line_acrostic, read_lexical_channel, word_acrostic};
pub use mark::{canonical, embed_signature, has_signature, remove_signature, WmError};
pub use registry::{default_registry, Registry};
pub use scrub::{scrub_synonyms, Aggression, ScrubReport};
pub use tokenize::toy_tokenize;
