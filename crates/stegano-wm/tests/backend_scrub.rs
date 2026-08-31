//! SEC-WM2 core: the rewrite orchestration treats the model as untrusted, runs
//! the local re-clean parade after a valid rewrite, falls back to the pure-Rust
//! floor when the backend fails or is rejected, and enforces the disclaimer gate
//! before any content leaves the machine. Mock backends only: no network.

use stegano_wm::{
    scrub_via_backend, Aggression, BackendError, GateError, InferenceBackend, Locality, ScrubSource,
};

/// A local backend (Ollama / LM Studio / llama.cpp analog): exempt from the
/// disclaimer gate because content never leaves the machine.
struct LocalGood;
impl InferenceBackend for LocalGood {
    fn rewrite(&self, text: &str) -> Result<String, BackendError> {
        Ok(text.replace("big", "large").replace("many", "numerous"))
    }
    fn locality(&self) -> Locality {
        Locality::Local
    }
}

/// A local backend that refuses / lectures instead of transforming.
struct LocalRefusing;
impl InferenceBackend for LocalRefusing {
    fn rewrite(&self, _text: &str) -> Result<String, BackendError> {
        Ok("I cannot help with that request.".to_string())
    }
    fn locality(&self) -> Locality {
        Locality::Local
    }
}

/// A local backend that is unreachable.
struct LocalDead;
impl InferenceBackend for LocalDead {
    fn rewrite(&self, _text: &str) -> Result<String, BackendError> {
        Err(BackendError::Unavailable("no server".into()))
    }
    fn locality(&self) -> Locality {
        Locality::Local
    }
}

/// An online backend (default locality): content leaves the machine, so the
/// disclaimer must be shown first.
struct OnlineGood;
impl InferenceBackend for OnlineGood {
    fn rewrite(&self, text: &str) -> Result<String, BackendError> {
        Ok(text.replace("big", "large"))
    }
}

const TEXT: &str = "We begin the big project to help many people every day.";

#[test]
fn a_valid_local_rewrite_is_recleaned_locally() {
    let report =
        scrub_via_backend(TEXT, &LocalGood, |s| format!("{s} <recleaned>"), Aggression::Medium, false)
            .expect("local needs no disclaimer");
    assert_eq!(report.source, ScrubSource::Backend);
    assert_eq!(report.locality, Locality::Local);
    assert!(report.reclean_applied);
    assert!(report.text.ends_with("<recleaned>"));
    assert!(report.text.contains("large"));
}

#[test]
fn a_refusal_falls_back_to_the_floor_not_passed_through() {
    let report = scrub_via_backend(TEXT, &LocalRefusing, |s| s.to_string(), Aggression::Heavy, false)
        .expect("local needs no disclaimer");
    assert_eq!(report.source, ScrubSource::Floor);
    assert!(!report.reclean_applied);
    assert!(!report.text.to_lowercase().contains("cannot"));
}

#[test]
fn an_unavailable_backend_falls_back_to_the_floor() {
    let report = scrub_via_backend(TEXT, &LocalDead, |s| s.to_string(), Aggression::Light, false)
        .expect("local needs no disclaimer");
    assert_eq!(report.source, ScrubSource::Floor);
}

#[test]
fn an_online_call_without_the_disclaimer_is_refused_before_it_leaves() {
    let err = scrub_via_backend(TEXT, &OnlineGood, |s| s.to_string(), Aggression::Medium, false)
        .unwrap_err();
    assert_eq!(err, GateError::DisclaimerRequired);
}

#[test]
fn an_online_call_proceeds_once_the_disclaimer_is_shown() {
    let report = scrub_via_backend(TEXT, &OnlineGood, |s| s.to_string(), Aggression::Medium, true)
        .expect("disclaimer shown, so the call proceeds");
    assert_eq!(report.locality, Locality::Online);
    assert_eq!(report.source, ScrubSource::Backend);
    assert!(report.text.contains("large"));
}
