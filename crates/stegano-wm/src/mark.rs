//! Our own keyed light-mark: write, read, and remove a signature carried in
//! synonym choices. Exact in all three directions because we hold the key. The
//! insertion is surgical: only the chosen group words change, every other byte
//! of the document is preserved.

use crate::prf::{derive_doc_key, prf_bit};
use crate::synonyms::{lookup, GROUPS};

/// Bits the signature occupies: a fixed magic pattern, whitened per document.
const MAGIC_BITS: usize = 16;
const MAGIC: u16 = 0xA5C3;

/// Errors this layer raises by name, rather than degrading silently.
#[derive(Debug, PartialEq, Eq)]
pub enum WmError {
    /// The text has fewer synonym-group positions than the signature needs.
    CapacityExceeded { needed: usize, available: usize },
}

impl std::fmt::Display for WmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WmError::CapacityExceeded { needed, available } => write!(
                f,
                "not enough synonym positions to carry the mark: need {needed}, have {available}"
            ),
        }
    }
}

impl std::error::Error for WmError {}

/// Byte spans of maximal alphabetic runs, in order.
fn word_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in text.char_indices() {
        if c.is_alphabetic() {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            spans.push((s, i));
        }
    }
    if let Some(s) = start {
        spans.push((s, text.len()));
    }
    spans
}

/// Matched synonym positions in order: `(start, end, group index, variant)`.
pub(crate) fn matched_positions(text: &str) -> Vec<(usize, usize, usize, u8)> {
    word_spans(text)
        .into_iter()
        .filter_map(|(s, e)| {
            let w = text[s..e].to_lowercase();
            lookup(&w).map(|(gi, v)| (s, e, gi, v))
        })
        .collect()
}

/// Transfer the case pattern of `origin` onto `replacement` (given lowercase).
fn match_case(origin: &str, replacement: &str) -> String {
    let all_upper =
        origin.chars().any(|c| c.is_alphabetic()) && origin.chars().all(|c| c.is_uppercase());
    let first_upper = origin.chars().next().map(|c| c.is_uppercase()).unwrap_or(false);
    if all_upper {
        replacement.to_uppercase()
    } else if first_upper {
        let mut out = String::new();
        let mut rc = replacement.chars();
        if let Some(c0) = rc.next() {
            out.extend(c0.to_uppercase());
        }
        out.push_str(rc.as_str());
        out
    } else {
        replacement.to_string()
    }
}

/// Rebuild `text`, letting `chooser(k, group, current_variant)` return the
/// variant to write at the k-th matched position, or `None` to leave it as is.
/// Untouched positions and all non-group bytes are copied verbatim.
pub(crate) fn rebuild<F: FnMut(usize, usize, u8) -> Option<u8>>(text: &str, mut chooser: F) -> String {
    let positions = matched_positions(text);
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for (k, &(s, e, gi, v)) in positions.iter().enumerate() {
        if let Some(target) = chooser(k, gi, v) {
            out.push_str(&text[cursor..s]);
            out.push_str(&match_case(&text[s..e], GROUPS[gi][target as usize]));
            cursor = e;
        }
    }
    out.push_str(&text[cursor..]);
    out
}

/// Reset every synonym-group word to its canonical (variant 0) form. This is
/// both the per-document key basis and the removal operation.
///
/// Honest caveat: removal is a canonicalization. It cannot tell our mark apart
/// from an ordinary synonym choice a human made, so it also normalizes those.
/// It removes, it never edits toward a chosen false value.
pub fn canonical(text: &str) -> String {
    rebuild(text, |_, _, v| if v != 0 { Some(0) } else { None })
}

/// Remove our light-mark by canonicalization.
pub fn remove_signature(text: &str) -> String {
    canonical(text)
}

/// Embed our keyed signature into the first `MAGIC_BITS` synonym positions.
/// Reads back exactly with the same key. Raised by name when the text is too
/// short to carry it, never a silent partial write.
pub fn embed_signature(text: &str, master_key: &[u8; 32]) -> Result<String, WmError> {
    let available = matched_positions(text).len();
    if available < MAGIC_BITS {
        return Err(WmError::CapacityExceeded {
            needed: MAGIC_BITS,
            available,
        });
    }
    let doc_key = derive_doc_key(master_key, &canonical(text));
    Ok(rebuild(text, |k, _, _| {
        if k < MAGIC_BITS {
            let magic_bit = ((MAGIC >> (MAGIC_BITS - 1 - k)) & 1) as u8;
            Some(magic_bit ^ prf_bit(&doc_key, k as u32))
        } else {
            None
        }
    }))
}

/// True when our keyed signature is present under `master_key`.
pub fn has_signature(text: &str, master_key: &[u8; 32]) -> bool {
    let positions = matched_positions(text);
    if positions.len() < MAGIC_BITS {
        return false;
    }
    let doc_key = derive_doc_key(master_key, &canonical(text));
    let mut recovered: u16 = 0;
    for (k, &(_, _, _, v)) in positions.iter().take(MAGIC_BITS).enumerate() {
        let bit = v ^ prf_bit(&doc_key, k as u32);
        recovered = (recovered << 1) | (bit as u16 & 1);
    }
    recovered == MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_preserves_non_group_bytes_and_is_idempotent() {
        let text = "The large team, quickly, will start.";
        let c = canonical(text);
        // large -> big, quick(ly)? "quickly" is not an exact group word, stays.
        assert_eq!(c, "The big team, quickly, will begin.");
        assert_eq!(canonical(&c), c);
    }

    #[test]
    fn match_case_follows_the_origin() {
        assert_eq!(match_case("big", "large"), "large");
        assert_eq!(match_case("Big", "large"), "Large");
        assert_eq!(match_case("BIG", "large"), "LARGE");
    }
}
