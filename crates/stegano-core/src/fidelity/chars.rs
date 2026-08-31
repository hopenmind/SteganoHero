//! Character classification shared by the fidelity checks.
//!
//! Nothing here is a policy decision. It is the vocabulary the checks need:
//! which characters a carrier can have inserted, which ones a renderer treats
//! as glue or as a break opportunity, and which ones a double click counts as
//! part of a word.

/// A character a carrier may insert, or a layout control that behaves like one.
///
/// Every one of these renders as nothing. That is precisely why their effect on
/// layout has to be measured rather than assumed: invisible is not the same as
/// inert.
pub fn is_format_control(c: char) -> bool {
    matches!(c,
        '\u{00AD}'                  // SOFT HYPHEN
        | '\u{061C}'                // ARABIC LETTER MARK
        | '\u{200B}'..='\u{200F}'   // ZWSP, ZWNJ, ZWJ, LRM, RLM
        | '\u{202A}'..='\u{202E}'   // LRE, RLE, PDF, LRO, RLO
        | '\u{2060}'..='\u{2064}'   // WORD JOINER and the invisible operators
        | '\u{2066}'..='\u{2069}'   // LRI, RLI, FSI, PDI
        | '\u{FEFF}'                // ZWNBSP, byte order mark
    )
}

/// A bidi control that opens a scope and must be closed.
///
/// An unclosed one reorders every character that follows it, which is the most
/// conspicuous failure this tool can produce.
pub fn bidi_initiator_terminator(c: char) -> Option<char> {
    match c {
        // Embeddings and overrides close with POP DIRECTIONAL FORMATTING.
        '\u{202A}' | '\u{202B}' | '\u{202D}' | '\u{202E}' => Some('\u{202C}'),
        // Isolates close with POP DIRECTIONAL ISOLATE.
        '\u{2066}' | '\u{2067}' | '\u{2068}' => Some('\u{2069}'),
        _ => None,
    }
}

/// A bidi control that closes a scope opened by [`bidi_initiator_terminator`].
pub fn is_bidi_terminator(c: char) -> bool {
    matches!(c, '\u{202C}' | '\u{2069}')
}

/// A directional mark: it opens nothing and closes nothing, but it still counts
/// as a strong direction character when the bidi algorithm resolves the
/// neutrals around it.
pub fn is_directional_mark(c: char) -> bool {
    matches!(c, '\u{200E}' | '\u{200F}' | '\u{061C}')
}

/// A right to left mark. Placed among neutrals it can move punctuation.
pub fn is_rtl_mark(c: char) -> bool {
    matches!(c, '\u{200F}' | '\u{061C}')
}

/// A bidi neutral for the purpose of the adjacency test in the balance check:
/// whitespace and punctuation, whose display order is decided by the strong
/// characters around them.
pub fn is_bidi_neutral(c: char) -> bool {
    if is_format_control(c) {
        return false;
    }
    c.is_whitespace() || (!c.is_alphanumeric() && !c.is_control())
}

/// What a double click selects. A run of these is one word.
///
/// Underscore is included because every editor that implements word selection
/// over source text treats it as a word character. Apostrophes and hyphens are
/// not, which matches the majority behaviour and is stated here rather than
/// left to be discovered.
pub fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Line break class, reduced to the distinctions the reflow check needs.
///
/// This is a deliberate subset of UAX #14. It models the classes the carriers
/// actually move: space, the zero width space that creates a break, the word
/// joiner that forbids one, the controls a renderer skips entirely, hyphens,
/// and ideographs. It does not implement dictionary based breaking for Thai or
/// Khmer, and it does not implement the full pair table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakClass {
    /// A hard line break in the source text.
    Mandatory,
    /// Space, which offers a break after it.
    Space,
    /// U+200B, which offers a break after it anywhere at all.
    ZeroWidthSpace,
    /// U+2060 and U+FEFF, which forbid a break on either side.
    Glue,
    /// Soft hyphen, a break opportunity that renders a hyphen when taken.
    SoftHyphen,
    /// A visible hyphen, which offers a break after it.
    Hyphen,
    /// An ideograph, which offers a break on either side.
    Ideographic,
    /// A control the line breaker resolves as if it were not present.
    Ignored,
    /// Everything else.
    Ordinary,
}

/// Classify one character.
pub fn break_class(c: char) -> BreakClass {
    match c {
        '\n' | '\u{000B}' | '\u{000C}' | '\u{0085}' | '\u{2028}' | '\u{2029}' => {
            BreakClass::Mandatory
        }
        '\r' => BreakClass::Ignored,
        ' ' | '\t' | '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{205F}' | '\u{3000}' => {
            BreakClass::Space
        }
        '\u{200B}' => BreakClass::ZeroWidthSpace,
        '\u{2060}' | '\u{FEFF}' => BreakClass::Glue,
        '\u{00AD}' => BreakClass::SoftHyphen,
        '-' | '\u{2010}' | '\u{2013}' => BreakClass::Hyphen,
        _ if is_format_control(c) => BreakClass::Ignored,
        _ if is_ideographic(c) => BreakClass::Ideographic,
        _ => BreakClass::Ordinary,
    }
}

/// Scripts that break between characters rather than between words.
pub fn is_ideographic(c: char) -> bool {
    matches!(c as u32,
        0x2E80..=0x303E     // CJK radicals and punctuation
        | 0x3041..=0x33FF   // kana, bopomofo, compatibility
        | 0x3400..=0x4DBF   // extension A
        | 0x4E00..=0x9FFF   // unified ideographs
        | 0xF900..=0xFAFF   // compatibility ideographs
        | 0xFF01..=0xFF60   // fullwidth forms
        | 0x20000..=0x2FA1F // extensions B and beyond
    )
}

/// Advance width in columns. Format controls take none, which is what makes
/// them invisible and what makes their effect on wrapping indirect.
pub fn advance_width(c: char) -> usize {
    if is_format_control(c) || c == '\r' {
        0
    } else if is_ideographic(c) {
        2
    } else {
        1
    }
}

/// `U+200C` style label for a codepoint.
pub fn codepoint_label(c: char) -> String {
    format!("U+{:04X}", c as u32)
}

/// The Unicode name of the controls this tool works with, for report text.
pub fn control_name(c: char) -> &'static str {
    match c {
        '\u{00AD}' => "SOFT HYPHEN",
        '\u{061C}' => "ARABIC LETTER MARK",
        '\u{200B}' => "ZERO WIDTH SPACE",
        '\u{200C}' => "ZERO WIDTH NON-JOINER",
        '\u{200D}' => "ZERO WIDTH JOINER",
        '\u{200E}' => "LEFT-TO-RIGHT MARK",
        '\u{200F}' => "RIGHT-TO-LEFT MARK",
        '\u{202A}' => "LEFT-TO-RIGHT EMBEDDING",
        '\u{202B}' => "RIGHT-TO-LEFT EMBEDDING",
        '\u{202C}' => "POP DIRECTIONAL FORMATTING",
        '\u{202D}' => "LEFT-TO-RIGHT OVERRIDE",
        '\u{202E}' => "RIGHT-TO-LEFT OVERRIDE",
        '\u{2060}' => "WORD JOINER",
        '\u{2061}' => "FUNCTION APPLICATION",
        '\u{2062}' => "INVISIBLE TIMES",
        '\u{2063}' => "INVISIBLE SEPARATOR",
        '\u{2064}' => "INVISIBLE PLUS",
        '\u{2066}' => "LEFT-TO-RIGHT ISOLATE",
        '\u{2067}' => "RIGHT-TO-LEFT ISOLATE",
        '\u{2068}' => "FIRST STRONG ISOLATE",
        '\u{2069}' => "POP DIRECTIONAL ISOLATE",
        '\u{FEFF}' => "ZERO WIDTH NO-BREAK SPACE",
        _ => "unnamed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_four_carrier_alphabets_are_all_recognised_as_format_controls() {
        // zero_width, whitespace_var and bidi in turn. Homoglyph substitutes
        // visible letters and so has no entry here by design.
        for c in [
            '\u{200B}', '\u{200C}', // zero_width
            '\u{2060}', '\u{FEFF}', '\u{2063}', // whitespace_var
            '\u{200E}', '\u{200F}', '\u{202C}', // bidi
        ] {
            assert!(is_format_control(c), "{} not recognised", codepoint_label(c));
        }
        assert!(!is_format_control('a'));
        assert!(!is_format_control('\u{0430}'), "a homoglyph is a visible letter");
    }

    #[test]
    fn the_word_joiner_is_glue_and_the_zero_width_space_is_a_break() {
        assert_eq!(break_class('\u{2060}'), BreakClass::Glue);
        assert_eq!(break_class('\u{FEFF}'), BreakClass::Glue);
        assert_eq!(break_class('\u{200B}'), BreakClass::ZeroWidthSpace);
    }

    #[test]
    fn bidi_controls_are_skipped_by_the_line_breaker() {
        // Class BN in UAX #14: resolved as if not present. A carrier writing
        // these therefore moves no wrap point, which the reflow check relies on
        // to tell bidi apart from the other two invisible carriers.
        for c in ['\u{200E}', '\u{200F}', '\u{202C}', '\u{202A}'] {
            assert_eq!(break_class(c), BreakClass::Ignored, "{}", codepoint_label(c));
        }
    }

    #[test]
    fn every_embedding_and_override_names_its_terminator() {
        assert_eq!(bidi_initiator_terminator('\u{202A}'), Some('\u{202C}'));
        assert_eq!(bidi_initiator_terminator('\u{202B}'), Some('\u{202C}'));
        assert_eq!(bidi_initiator_terminator('\u{202D}'), Some('\u{202C}'));
        assert_eq!(bidi_initiator_terminator('\u{202E}'), Some('\u{202C}'));
        assert_eq!(bidi_initiator_terminator('\u{2066}'), Some('\u{2069}'));
        assert_eq!(bidi_initiator_terminator('\u{2069}'), None);
        assert!(is_bidi_terminator('\u{202C}'));
        assert!(is_bidi_terminator('\u{2069}'));
    }

    #[test]
    fn format_controls_have_no_advance_width() {
        assert_eq!(advance_width('\u{200B}'), 0);
        assert_eq!(advance_width('a'), 1);
        assert_eq!(advance_width('\u{4E00}'), 2);
    }

    #[test]
    fn a_word_is_a_run_of_alphanumerics_and_underscores() {
        assert!(is_word_char('a'));
        assert!(is_word_char('7'));
        assert!(is_word_char('_'));
        assert!(is_word_char('\u{0430}'), "a Cyrillic letter is still a letter");
        assert!(!is_word_char('-'));
        assert!(!is_word_char(' '));
        assert!(!is_word_char('\u{200B}'));
    }
}
