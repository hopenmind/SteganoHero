//! SEC-WM1(c): certain lexical detection. A planted acrostic is revealed by a
//! literal reading of initials, and the raw synonym channel is read exactly
//! over the known table. No key, no model: these are certain by construction.

use stegano_wm::{acrostic_contains, read_lexical_channel, word_acrostic};

#[test]
fn planted_word_acrostic_is_revealed() {
    // First letters of the words spell the hidden word.
    let text = "Hello indeed dragons dance every night.";
    assert_eq!(word_acrostic(text), "hidden");
    assert!(acrostic_contains(text, "hidden"));
    // A target that is not there is reported absent, exactly.
    assert!(!acrostic_contains(text, "attack"));
}

#[test]
fn raw_synonym_channel_is_read_over_the_known_table() {
    // Alternating canonical / variant words carry a readable raw channel.
    let text = "big large fast quick begin start";
    assert_eq!(read_lexical_channel(text), vec![0, 1, 0, 1, 0, 1]);
}
