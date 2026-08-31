//! SEC-WM analysis capstone: the pure-Rust detections reported under the honest
//! verdict taxonomy, and the structural wall named on every analysis.

use stegano_wm::{analyze, embed_signature, AnalyzeOptions, Verdict};

const TEXT: &str = "We begin the big project to help many people, and we also \
need to show that a small team can make fast progress, keep the whole plan \
near the goal, so we often get what we want.";

#[test]
fn every_analysis_names_the_structural_wall() {
    let report = analyze("just some plain ordinary sentences here", &AnalyzeOptions::default());
    assert!(report.findings.iter().any(|f| f.verdict == Verdict::Impossible));
    // Plain text yields no certain finding.
    assert!(!report.findings.iter().any(|f| f.verdict == Verdict::Certain));
}

#[test]
fn our_keyed_mark_is_reported_certain() {
    let key = [7u8; 32];
    let marked = embed_signature(TEXT, &key).expect("capacity");
    let opts = AnalyzeOptions {
        our_key: Some(key),
        ..Default::default()
    };
    let report = analyze(&marked, &opts);
    assert!(report
        .findings
        .iter()
        .any(|f| f.verdict == Verdict::Certain && f.label == "our keyed mark"));
    // The wall is still named, even alongside a certain finding.
    assert!(report.findings.iter().any(|f| f.verdict == Verdict::Impossible));
}

#[test]
fn a_synonym_channel_is_only_an_indication() {
    let report = analyze("big fast help many keep", &AnalyzeOptions::default());
    assert!(report.findings.iter().any(|f| f.verdict == Verdict::Indication));
    // Presence of a channel is never dressed up as a certain detection.
    assert!(!report.findings.iter().any(|f| f.verdict == Verdict::Certain));
}

#[test]
fn a_present_acrostic_target_is_certain() {
    let opts = AnalyzeOptions {
        acrostic_target: Some("hidden".to_string()),
        ..Default::default()
    };
    let report = analyze("Hello indeed dragons dance every night.", &opts);
    assert!(report
        .findings
        .iter()
        .any(|f| f.verdict == Verdict::Certain && f.label == "acrostic"));
}
