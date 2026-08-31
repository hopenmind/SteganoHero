//! SEC-WM1(d): the model-free scrub floor disrupts a word-choice channel
//! without a model or a key, stays surgical, and never claims removal.

use stegano_wm::{
    canonical, embed_signature, has_signature, scrub_synonyms, Aggression,
};

const TEXT: &str = "We begin the big project to help many people, and we also \
need to show that a small team can make fast progress, keep the whole plan \
near the goal, so we often get what we want.";

#[test]
fn scrub_disrupts_a_lexical_channel_and_stays_surgical() {
    let key = [7u8; 32];
    let marked = embed_signature(TEXT, &key).expect("capacity");
    assert!(has_signature(&marked, &key));

    // A heavy scrub perturbs every synonym position: enough to break the mark,
    // used here only as a readable proxy for any word-choice channel.
    let report = scrub_synonyms(&marked, Aggression::Heavy);
    assert_eq!(report.positions_changed, report.positions_total);
    assert!(!has_signature(&report.text, &key), "the lexical channel should be disrupted");

    // Surgical: only synonym words changed, so the canonical form is preserved
    // and every non-group byte is untouched.
    assert_eq!(canonical(&report.text), canonical(TEXT));
}

#[test]
fn aggression_levels_touch_different_amounts() {
    let light = scrub_synonyms(TEXT, Aggression::Light);
    let heavy = scrub_synonyms(TEXT, Aggression::Heavy);
    assert!(light.positions_changed < heavy.positions_changed);
    assert_eq!(heavy.positions_changed, heavy.positions_total);
}
