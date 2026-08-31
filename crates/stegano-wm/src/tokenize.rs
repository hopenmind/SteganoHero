//! The pure-Rust toy tokenizer.
//!
//! The z-test statistics are independent of the tokenizer choice, so this floor
//! tier maps words to stable ids without a model. A production tier swaps this
//! for the exact BPE tokenizer that a given watermark config was defined
//! against (part of the registry entry, a later slice), because bit-exact
//! detection needs the exact token boundaries the marking model used.

use sha2::{Digest, Sha256};

/// Split on any non-alphanumeric character, lowercase each word, and map it to
/// a stable `u32` via the first four bytes of its SHA-256. Empty pieces from
/// runs of separators are dropped.
pub fn toy_tokenize(text: &str) -> Vec<u32> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| {
            let lower = w.to_lowercase();
            let digest = Sha256::digest(lower.as_bytes());
            let mut head = [0u8; 4];
            head.copy_from_slice(&digest[..4]);
            u32::from_be_bytes(head)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizer_is_case_and_punctuation_stable() {
        // Case and punctuation do not change the token stream; word count does.
        assert_eq!(toy_tokenize("Hello, world!"), toy_tokenize("hello   world"));
        assert_eq!(toy_tokenize("Hello, world!").len(), 2);
    }

    #[test]
    fn empty_text_yields_no_tokens() {
        assert!(toy_tokenize("   ,.;  ").is_empty());
    }
}
