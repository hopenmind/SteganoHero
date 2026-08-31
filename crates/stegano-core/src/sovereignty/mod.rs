//! Document sovereignty: see and clean the marks your own document carries.
//!
//! This is the native core of the AI-regulation tool (backlog AR-1). It answers
//! two questions about a document a person holds: what marks are on it, and,
//! for the classes the person chooses, remove exactly those and leave the rest
//! byte for byte.
//!
//! The layer is additive and reuses the frozen core. Detection is
//! [`crate::forensic::analyze`], shaped here into a "what is on my document"
//! answer. Removal is each carrier's own [`StegoMethod::strip`], never a
//! reimplementation. A class this native path cannot address says so by name,
//! and the clean result carries a residual note so a caller never reads "clean"
//! as "guaranteed unmarked". This mirrors the honesty discipline the fidelity
//! and forensic modules already hold to.

pub mod clean;
pub mod inspect;
pub mod metadata;

pub use clean::{clean, pristine_clean, CleanReport, ClassRemoval, PristineReport};
pub use inspect::{inspect, CarrierSignature, ClassFinding, InspectionReport, OtherInvisible};
pub use metadata::{read_metadata, ReadableMetadata};

use crate::stego::{Bidi, Homoglyph, WhitespaceVar, ZeroWidth};
use crate::traits::StegoMethod;

/// A class of mark this native tool can both recognise and remove.
///
/// Each class maps to one carrier. The identifiers match the forensic
/// detector's vocabulary so a surface can line an inspection up against a clean
/// request without a translation table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarkClass {
    /// Invisible zero-width characters.
    ZeroWidth,
    /// Look-alike letter substitutions across scripts.
    Homoglyph,
    /// Bidirectional formatting controls.
    Bidi,
    /// Invisible spacing characters.
    WhitespaceVariation,
}

impl MarkClass {
    /// Every class, in the canonical carrier order (`bidi`, `homoglyph`,
    /// `whitespace_var`, `zero_width`) that `license::strip_all` also uses, so a
    /// full clean is deterministic and matches the rest of the core.
    pub const ALL: [MarkClass; 4] = [
        MarkClass::Bidi,
        MarkClass::Homoglyph,
        MarkClass::WhitespaceVariation,
        MarkClass::ZeroWidth,
    ];

    /// Stable machine identifier, matching the forensic detector's method ids.
    pub fn id(self) -> &'static str {
        match self {
            MarkClass::ZeroWidth => "zero_width",
            MarkClass::Homoglyph => "homoglyph",
            MarkClass::Bidi => "bidi",
            MarkClass::WhitespaceVariation => "whitespace_var",
        }
    }

    /// Plain-language description of the observable phenomenon, capability first.
    pub fn label(self) -> &'static str {
        match self {
            MarkClass::ZeroWidth => "Invisible zero-width characters",
            MarkClass::Homoglyph => "Look-alike letter substitutions",
            MarkClass::Bidi => "Bidirectional formatting controls",
            MarkClass::WhitespaceVariation => "Invisible spacing characters",
        }
    }

    /// Resolve a class from a forensic method id, so a signature the detector
    /// reports lines up with the class that can clean it.
    pub fn from_id(id: &str) -> Option<MarkClass> {
        MarkClass::ALL.into_iter().find(|class| class.id() == id)
    }

    fn carrier(self) -> Box<dyn StegoMethod> {
        match self {
            MarkClass::ZeroWidth => Box::new(ZeroWidth::new()),
            MarkClass::Homoglyph => Box::new(Homoglyph::new()),
            MarkClass::Bidi => Box::new(Bidi::new()),
            MarkClass::WhitespaceVariation => Box::new(WhitespaceVar::new()),
        }
    }

    /// Apply this class's carrier `strip`, returning the cleaned text.
    ///
    /// This is the reused removal: it calls the carrier's own `strip`, which is
    /// attribution-based and non-destructive. In particular
    /// [`Homoglyph::strip`](crate::stego::Homoglyph) reverts only the
    /// substitutions it can attribute as its own and leaves legitimate script
    /// mixing byte for byte (backlog F7).
    pub(crate) fn strip(self, text: &str) -> String {
        self.carrier().strip(text)
    }
}

/// Count the marks a carrier's `strip` changed between input and output.
///
/// The carriers change text in one of two ways: the invisible-character
/// carriers delete their channel characters, so the length shrinks by exactly
/// the count removed; the homoglyph carrier reverts a substitution in place, so
/// the length holds and the changed positions are the count reverted. This
/// measures the reused `strip`, it does not reimplement either operation, and
/// the two disjoint cases cover all four carriers.
pub(crate) fn count_marks_changed(before: &str, after: &str) -> usize {
    let before_len = before.chars().count();
    let after_len = after.chars().count();

    if before_len != after_len {
        before_len.saturating_sub(after_len)
    } else {
        before
            .chars()
            .zip(after.chars())
            .filter(|(a, b)| a != b)
            .count()
    }
}

/// True when any invisible-character carrier's `strip` removes this character,
/// i.e. the character belongs to a cleanable class.
///
/// The homoglyph carrier is not consulted here: its marks are visible
/// look-alikes rather than invisible characters, and its attribution needs
/// surrounding context that a single character in isolation does not carry.
fn carrier_removes(c: char) -> bool {
    let single = c.to_string();
    [
        MarkClass::Bidi,
        MarkClass::WhitespaceVariation,
        MarkClass::ZeroWidth,
    ]
    .into_iter()
    .any(|class| class.strip(&single) != single)
}

/// Reconstruct a character from a forensic `U+XXXX` codepoint string.
fn char_from_codepoint(codepoint: &str) -> Option<char> {
    let hex = codepoint.strip_prefix("U+")?;
    u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
}

/// Invisible or bidirectional characters present that fall outside every
/// cleanable class, taken from the forensic report's own classification.
///
/// The forensic detector already lists every unusual (invisible or bidi)
/// character in `unusual_categories`. This keeps only the ones no carrier
/// removes, so the native clean can name what it leaves behind rather than
/// silently passing over it (invariant 2).
pub(crate) fn other_invisible(report: &crate::forensic::ForensicReport) -> Vec<OtherInvisible> {
    report
        .unicode_analysis
        .unusual_categories
        .iter()
        .filter_map(|unusual| {
            let c = char_from_codepoint(&unusual.codepoint)?;
            if carrier_removes(c) {
                return None;
            }
            Some(OtherInvisible {
                codepoint: unusual.codepoint.clone(),
                category: unusual.category.clone(),
                count: unusual.count,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_ids_match_the_forensic_vocabulary() {
        assert_eq!(MarkClass::ZeroWidth.id(), "zero_width");
        assert_eq!(MarkClass::Homoglyph.id(), "homoglyph");
        assert_eq!(MarkClass::Bidi.id(), "bidi");
        assert_eq!(MarkClass::WhitespaceVariation.id(), "whitespace_var");
    }

    #[test]
    fn from_id_round_trips_every_class() {
        for class in MarkClass::ALL {
            assert_eq!(MarkClass::from_id(class.id()), Some(class));
        }
        assert_eq!(MarkClass::from_id("not_a_class"), None);
    }

    #[test]
    fn count_of_a_deletion_is_the_length_delta() {
        // Two zero-width characters removed.
        let before = "ab\u{200B}cd\u{200C}e";
        let after = "abcde";
        assert_eq!(count_marks_changed(before, after), 2);
    }

    #[test]
    fn count_of_a_substitution_is_the_changed_positions() {
        // Same length, one character reverted.
        assert_eq!(count_marks_changed("w\u{043E}rld", "world"), 1);
    }

    #[test]
    fn count_is_zero_when_nothing_changed() {
        assert_eq!(count_marks_changed("unchanged", "unchanged"), 0);
    }

    #[test]
    fn carrier_owned_and_orphan_invisibles_are_told_apart() {
        // Owned by a carrier.
        assert!(carrier_removes('\u{200B}')); // zero width
        assert!(carrier_removes('\u{FEFF}')); // whitespace variation
        assert!(carrier_removes('\u{202A}')); // bidi embedding
        // Owned by no cleanable class.
        assert!(!carrier_removes('\u{200D}')); // zero width joiner
        assert!(!carrier_removes('\u{00AD}')); // soft hyphen
    }

    #[test]
    fn codepoint_strings_reconstruct_their_character() {
        assert_eq!(char_from_codepoint("U+200B"), Some('\u{200B}'));
        assert_eq!(char_from_codepoint("U+0041"), Some('A'));
        assert_eq!(char_from_codepoint("200B"), None);
    }
}
