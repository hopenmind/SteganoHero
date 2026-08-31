//! Certain detection of lexical marks: acrostics and the raw synonym channel.
//!
//! These are the parts a reader can verify EXACTLY without a model and without a
//! key, because the pattern or the table is known. An acrostic is a literal
//! reading of initials; the synonym channel is the raw variant sequence over our
//! known table. Whether such a channel was placed deliberately is a separate,
//! weaker question; reading what is there is certain.

use crate::mark::matched_positions;

/// The word-initial acrostic: the first letter of each alphabetic word run, in
/// order, lowercased.
pub fn word_acrostic(text: &str) -> String {
    let mut out = String::new();
    let mut in_word = false;
    for c in text.chars() {
        if c.is_alphabetic() {
            if !in_word {
                out.extend(c.to_lowercase());
                in_word = true;
            }
        } else {
            in_word = false;
        }
    }
    out
}

/// The line-initial acrostic: the first alphabetic character of each line that
/// has one, in order, lowercased.
pub fn line_acrostic(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        if let Some(c) = line.chars().find(|c| c.is_alphabetic()) {
            out.extend(c.to_lowercase());
        }
    }
    out
}

/// True when `target` appears in the word-initial or line-initial acrostic
/// (case-insensitive). A certain, literal check for a suspected planted
/// acrostic: the reader supplies what they suspect, the answer is exact.
pub fn acrostic_contains(text: &str, target: &str) -> bool {
    let t = target.to_lowercase();
    if t.is_empty() {
        return false;
    }
    word_acrostic(text).contains(&t) || line_acrostic(text).contains(&t)
}

/// The raw lexical channel over the known synonym table: the variant index
/// (0 or 1) at each group position, in order. Certain because the table is
/// known; this reads whatever bits the choices carry, ours or anyone's, without
/// a key. It does not, by itself, prove the channel was placed on purpose.
pub fn read_lexical_channel(text: &str) -> Vec<u8> {
    matched_positions(text)
        .into_iter()
        .map(|(_, _, _, v)| v)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_acrostic_reads_initials() {
        assert_eq!(word_acrostic("Attack At Dawn!"), "aad");
        assert_eq!(word_acrostic("  one,two ; three  "), "ott");
    }

    #[test]
    fn line_acrostic_reads_line_initials() {
        assert_eq!(line_acrostic("Ship\nOverboard\nSinking"), "sos");
    }

    #[test]
    fn raw_channel_reads_variant_indices() {
        // "big" is variant 0, "large" is variant 1 of the same group.
        assert_eq!(read_lexical_channel("big large big"), vec![0, 1, 0]);
        assert!(read_lexical_channel("no synonyms here at all zzz").is_empty());
    }
}
