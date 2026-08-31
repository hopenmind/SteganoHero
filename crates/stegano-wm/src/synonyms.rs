//! A small, embedded table of two-variant synonym groups (canonical first).
//!
//! Our own light-mark lives in the CHOICE between the two variants at each
//! group position, whitened by a keyed bit so only the key holder can read or
//! forge it. Unlike a token-sampling watermark, this mark is ours: we can write
//! it, read it, and remove it exactly, because we hold the key.

/// Two-variant groups. Variant 0 is canonical (the form a removal restores).
pub(crate) const GROUPS: &[[&str; 2]] = &[
    ["big", "large"],
    ["small", "little"],
    ["fast", "quick"],
    ["begin", "start"],
    ["end", "finish"],
    ["buy", "purchase"],
    ["help", "assist"],
    ["show", "display"],
    ["near", "close"],
    ["whole", "entire"],
    ["often", "frequently"],
    ["also", "too"],
    ["use", "utilize"],
    ["make", "create"],
    ["keep", "retain"],
    ["need", "require"],
    ["get", "obtain"],
    ["want", "wish"],
    ["many", "numerous"],
    ["so", "thus"],
];

/// Look up a lowercase word: `(group index, variant index)` if it is a known
/// variant, else `None`.
pub(crate) fn lookup(word_lower: &str) -> Option<(usize, u8)> {
    for (gi, g) in GROUPS.iter().enumerate() {
        if word_lower == g[0] {
            return Some((gi, 0));
        }
        if word_lower == g[1] {
            return Some((gi, 1));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_finds_both_variants_and_rejects_others() {
        assert_eq!(lookup("big"), Some((0, 0)));
        assert_eq!(lookup("large"), Some((0, 1)));
        assert_eq!(lookup("elephant"), None);
    }
}
