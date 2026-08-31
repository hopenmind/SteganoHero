use std::collections::BTreeMap;

use crate::stego::Homoglyph;
use crate::traits::NoiseMetrics;

/// Compute Shannon entropy of a string (bits per character).
///
/// H(X) = -sum(p(x) * log2(p(x)))
///
/// Pure ASCII English text: ~4.0-4.5 bits/char
/// Random data: ~8.0 bits/char (maximum for byte-level)
/// Stego text: should be close to original (otherwise detectable)
///
/// Reproducible by construction (backlog F14). Floating-point addition is not
/// associative, so the order the per-codepoint terms are accumulated in decides
/// the low bits of the result. A `HashMap` iterates in an order that differs
/// between map instances, which made the same input report two different
/// figures in the same process. `BTreeMap` fixes the order to codepoint order,
/// so the figure is bit-identical every time it is asked for.
pub fn shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    let mut freq: BTreeMap<char, usize> = BTreeMap::new();
    let mut total: usize = 0;

    for ch in text.chars() {
        *freq.entry(ch).or_default() += 1;
        total += 1;
    }

    let total_f = total as f64;
    let mut entropy = 0.0f64;
    for count in freq.values() {
        let p = *count as f64 / total_f;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Compute noise density: ratio of invisible/zero-width characters to total.
///
/// A normal text has density ~0.0.
/// A steganographically modified text has density > 0.0.
/// Higher density = easier to detect = less secure.
pub fn noise_density(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    let total = text.chars().count() as f64;
    let invisible = text
        .chars()
        .filter(|c| is_invisible_unicode(*c))
        .count() as f64;

    invisible / total
}

/// Check if a character is an "invisible" Unicode character
/// (zero-width, control, formatting).
fn is_invisible_unicode(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'   // ZERO WIDTH SPACE
        | '\u{200C}' // ZERO WIDTH NON-JOINER
        | '\u{200D}' // ZERO WIDTH JOINER
        | '\u{200E}' // LEFT-TO-RIGHT MARK
        | '\u{200F}' // RIGHT-TO-LEFT MARK
        | '\u{202A}' // LEFT-TO-RIGHT EMBEDDING
        | '\u{202B}' // RIGHT-TO-LEFT EMBEDDING
        | '\u{202C}' // POP DIRECTIONAL FORMATTING
        | '\u{202D}' // LEFT-TO-RIGHT OVERRIDE
        | '\u{202E}' // RIGHT-TO-LEFT OVERRIDE
        | '\u{2060}' // WORD JOINER
        | '\u{2061}' // FUNCTION APPLICATION
        | '\u{2062}' // INVISIBLE TIMES
        | '\u{2063}' // INVISIBLE SEPARATOR
        | '\u{2064}' // INVISIBLE PLUS
        | '\u{FEFF}' // ZERO WIDTH NO-BREAK SPACE (BOM)
        | '\u{00AD}' // SOFT HYPHEN
    )
}

/// Homoglyph density: the share of characters this carrier can show it
/// substituted.
///
/// Backlog F16. This used to count every Cyrillic lookalike against its own
/// copy of the substitution table, so ordinary Russian prose reported a
/// homoglyph density of 0.35 and fed a suspicion score in a document nobody
/// had touched. Attribution belongs to the carrier that owns the map, and a
/// second copy of that map here was a drift hazard besides.
pub fn homoglyph_density(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    let total = text.chars().count() as f64;
    Homoglyph::substitutions(text) as f64 / total
}

/// Compute full noise metrics comparing original and stego text.
pub fn compute_metrics(original: &str, stego: &str) -> NoiseMetrics {
    let entropy_before = shannon_entropy(original);
    let entropy_after = shannon_entropy(stego);

    let density = noise_density(stego) + homoglyph_density(stego);

    // Rough perplexity impact estimation:
    // Zero-width chars break tokenizer boundaries → increases perplexity
    // Homoglyphs change token IDs → increases perplexity
    // Both effects scale with density
    let perplexity_delta = density * 10.0; // Empirical scaling factor

    NoiseMetrics {
        shannon_delta: entropy_after - entropy_before,
        noise_density: density,
        perplexity_delta,
        survival_score: 0.0, // Computed separately via survival tests
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn entropy_single_char() {
        // All same char = 0 entropy
        assert_eq!(shannon_entropy("aaaa"), 0.0);
    }

    #[test]
    fn entropy_uniform() {
        // 2 equally likely chars = 1 bit entropy
        let e = shannon_entropy("abababab");
        assert!((e - 1.0).abs() < 0.001);
    }

    #[test]
    fn entropy_english_text() {
        let e = shannon_entropy("The quick brown fox jumps over the lazy dog");
        // English text typically has ~3.5-4.5 bits/char entropy
        assert!(e > 3.0 && e < 5.0, "Expected 3-5, got {e}");
    }

    /// A text with enough distinct codepoints that the order the terms are
    /// summed in is visible in the low bits of the result.
    fn high_cardinality_text() -> String {
        let mut text = String::new();
        for round in 0..7 {
            text.push_str("The quick brown fox jumps over the lazy dog 0123456789 ");
            text.push_str("Portez ce vieux whisky au juge blond qui fume, cent fois. ");
            text.push_str("Съешь же ещё этих мягких французских булок да выпей чаю. ");
            text.push_str("いろはにほへとちりぬるを わかよたれそつねならむ ");
            text.push_str("!@#$%^&*()[]{}<>?/\\|~`+=_-;:'\",. ");
            for step in 0..round {
                text.push(char::from(b'A' + step as u8));
            }
        }
        text
    }

    /// Backlog F14. The figure must be the same figure every time it is asked
    /// for, down to the last bit: a forensic verdict is built on it. Summing
    /// over a `HashMap` made the low bits depend on iteration order, which
    /// varies from one map instance to the next.
    #[test]
    fn entropy_is_bit_identical_across_repeated_calls() {
        let text = high_cardinality_text();
        let first = shannon_entropy(&text);

        for round in 1..=64 {
            let again = shannon_entropy(&text);
            assert_eq!(
                again.to_bits(),
                first.to_bits(),
                "call {round} returned {again:?} where call 0 returned {first:?}"
            );
        }
    }

    /// The same content in a different `String` must also give the same
    /// figure: reproducibility is a property of the text, not of the buffer.
    #[test]
    fn entropy_is_bit_identical_for_equal_texts_in_separate_buffers() {
        let text = high_cardinality_text();
        let copies: Vec<String> = (0..16).map(|_| high_cardinality_text()).collect();
        let reference = shannon_entropy(&text).to_bits();

        for (i, copy) in copies.iter().enumerate() {
            assert_eq!(
                shannon_entropy(copy).to_bits(),
                reference,
                "copy {i} disagreed with the reference text"
            );
        }
    }

    /// Pins the summation order itself: terms are accumulated in codepoint
    /// order, so an independent computation in that order matches bit for bit.
    #[test]
    fn entropy_sums_its_terms_in_codepoint_order() {
        let text = high_cardinality_text();

        let mut counts: std::collections::BTreeMap<char, usize> = std::collections::BTreeMap::new();
        for ch in text.chars() {
            *counts.entry(ch).or_default() += 1;
        }
        let total = text.chars().count() as f64;
        let mut expected = 0.0f64;
        for count in counts.values() {
            let p = *count as f64 / total;
            expected -= p * p.log2();
        }

        assert_eq!(shannon_entropy(&text).to_bits(), expected.to_bits());
    }

    #[test]
    fn noise_density_clean_text() {
        assert_eq!(noise_density("Hello world"), 0.0);
    }

    #[test]
    fn noise_density_with_zwsp() {
        let text = "He\u{200B}ll\u{200C}o";
        let d = noise_density(text);
        assert!(d > 0.0);
    }

    #[test]
    fn metrics_comparison() {
        let original = "Hello world test message";
        let stego = "He\u{200B}ll\u{200C}o w\u{200B}or\u{200C}ld test message";

        let m = compute_metrics(original, stego);
        assert!(m.shannon_delta > 0.0, "Entropy should increase with noise");
        assert!(m.noise_density > 0.0, "Should detect noise");
    }
}
