//! SEC-WM1(b): our own keyed light-mark. Write it, read it back exactly with
//! the key, fail to read it under a wrong key, and remove it completely. This
//! is the CERTAIN side of the word-choice layer: it is our mark, our key.

use stegano_wm::{canonical, embed_signature, has_signature, remove_signature, WmError};

const TEXT: &str = "We begin the big project to help many people, and we also \
need to show that a small team can make fast progress, keep the whole plan \
near the goal, so we often get what we want.";

#[test]
fn light_mark_round_trip_is_exact_keyed_and_removable() {
    let key = [7u8; 32];
    let other = [9u8; 32];

    // The unmarked text carries no signature.
    assert!(!has_signature(TEXT, &key));

    let marked = embed_signature(TEXT, &key).expect("the text has capacity");

    // Present under the right key, absent under a wrong key (keyed: an observer
    // without the key can neither read nor forge it).
    assert!(has_signature(&marked, &key));
    assert!(!has_signature(&marked, &other));

    // Marking touched only synonym choices: the canonical form is unchanged, so
    // every non-group byte of the document is preserved (surgical insertion).
    assert_eq!(canonical(&marked), canonical(TEXT));

    // Removal wipes the mark; the result is the canonical text.
    let cleaned = remove_signature(&marked);
    assert!(!has_signature(&cleaned, &key));
    assert_eq!(cleaned, canonical(TEXT));
}

#[test]
fn capacity_shortfall_is_raised_by_name() {
    let key = [7u8; 32];
    let err = embed_signature("big small fast", &key).unwrap_err();
    assert_eq!(
        err,
        WmError::CapacityExceeded {
            needed: 16,
            available: 3
        }
    );
}
