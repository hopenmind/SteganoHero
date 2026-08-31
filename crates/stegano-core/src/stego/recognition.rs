//! Attribution: telling a carrier's own work from the cover's own characters.
//!
//! Every carrier owns an alphabet. None of them owns the *text*. The defects
//! this module exists to close were all one mistake wearing different hats: a
//! carrier treated the presence of its codepoints as proof of its own work.
//! From that single assumption came a decoder that read ordinary Russian as a
//! payload, a strip that rewrote Russian prose into Latin, a capacity figure
//! that offered slots the cover had already filled, and two different refusals
//! for one situation.
//!
//! The rule this module states, and which the four carriers apply with
//! whatever evidence their channel affords:
//!
//! **Attribute first, then act.** Before a carrier strips, scores, budgets or
//! reads, it decides which characters of its alphabet it put there. Where it
//! cannot decide, it says so and leaves the text alone; it never guesses in
//! the direction that produces an answer.
//!
//! The evidence differs by channel, and that difference is real rather than an
//! exception:
//!
//! - `homoglyph` borrows an alphabet that belongs to a living script. A
//!   Cyrillic `о` inside a Latin word is a substitution; the same codepoint
//!   inside a Russian word is a letter. Its evidence is therefore the script
//!   of the writing around each character, with the document as the tiebreak.
//! - `zero_width`, `whitespace_var` and `bidi` insert characters that carry no
//!   writing at all, so anything of theirs in a cover is occupancy rather than
//!   prose. Their evidence is structural: a payload is a whole number of
//!   bytes, and a cover that already holds their alphabet cannot be written
//!   into at all.
//!
//! Both refusals below are shared by all four carriers on purpose. One
//! situation must produce one explanation, whichever path reached it.

use crate::error::SteganoError;

/// Which script a stretch of text is written in, as far as it can be told.
///
/// `Undetermined` is a real answer and not a failure: a document holding both
/// scripts, or neither, offers no document-level evidence, and the carrier
/// falls back on what each word shows rather than on a preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Script {
    /// Latin letters present, no unambiguous Cyrillic.
    Latin,
    /// Unambiguous Cyrillic present, no Latin.
    Cyrillic,
    /// Both, or neither. Nothing can be concluded at this level.
    Undetermined,
}

/// Is this a Latin letter?
///
/// ASCII plus the Latin-1, Latin Extended-A, Latin Extended-B and Latin
/// Extended Additional letters, so accented French and Vietnamese count as
/// Latin evidence rather than as nothing.
pub fn is_latin_letter(c: char) -> bool {
    if !c.is_alphabetic() {
        return false;
    }
    matches!(c as u32,
        0x0041..=0x005A
        | 0x0061..=0x007A
        | 0x00C0..=0x024F
        | 0x1E00..=0x1EFF
    )
}

/// Is this a Cyrillic letter?
///
/// The Cyrillic and Cyrillic Supplement blocks. Whether a given one of them is
/// also a Latin lookalike is a question for the carrier that owns that map,
/// not for this predicate.
pub fn is_cyrillic_letter(c: char) -> bool {
    c.is_alphabetic() && matches!(c as u32, 0x0400..=0x052F)
}

/// Decide the script of a text, ignoring characters that could belong to
/// either.
///
/// `ambiguous` names the codepoints that carry no evidence, which for the
/// homoglyph carrier is exactly the substitute side of its map.
pub fn document_script(chars: &[char], ambiguous: impl Fn(char) -> bool) -> Script {
    let mut latin = 0usize;
    let mut cyrillic = 0usize;

    for &c in chars {
        if ambiguous(c) {
            continue;
        }
        if is_latin_letter(c) {
            latin += 1;
        } else if is_cyrillic_letter(c) {
            cyrillic += 1;
        }
    }

    match (latin > 0, cyrillic > 0) {
        (true, false) => Script::Latin,
        (false, true) => Script::Cyrillic,
        _ => Script::Undetermined,
    }
}

/// The one refusal for a cover that already holds a carrier's alphabet.
///
/// Reading counts every character of the alphabet as a position; writing can
/// only act on the free ones. On such a cover the written and read indices do
/// not line up and the document would not decode. Every carrier raises this,
/// in these words, from every path that discovers it: the byte path, the
/// position path and the capacity path. That is what stops one situation from
/// having two explanations.
pub fn cover_already_occupied(method: &str, occupied: usize) -> SteganoError {
    SteganoError::EncodingFailed {
        method: method.into(),
        reason: format!(
            "cover already contains {occupied} characters of this carrier's alphabet, \
             so written and read positions would not line up"
        ),
    }
}

/// The one refusal for a channel that does not end on a byte boundary.
///
/// An inserting carrier writes exactly the bits it is handed, and a frame is
/// always a whole number of bytes, so a partial group is never something this
/// carrier wrote. The readers used to finish the group, one by padding it with
/// zeros and one by discarding it. Padding invents bits nobody wrote and
/// discarding hides that the text was not what it claimed, which is the silent
/// degradation invariant 2 exists to stop.
pub fn channel_ends_mid_byte(method: &str, bits: usize) -> SteganoError {
    SteganoError::DecodingFailed {
        method: method.into(),
        reason: format!(
            "the channel holds {bits} bits, which is not a whole number of bytes, so these \
             characters are not a payload this carrier wrote"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nothing_is_ambiguous(_: char) -> bool {
        false
    }

    #[test]
    fn accented_latin_counts_as_latin_evidence() {
        assert!(is_latin_letter('e'));
        assert!(is_latin_letter('\u{00E9}'));
        assert!(is_latin_letter('\u{0153}'));
        assert!(!is_latin_letter('\u{0430}'));
        assert!(!is_latin_letter('4'));
    }

    #[test]
    fn cyrillic_is_recognised_across_the_block() {
        assert!(is_cyrillic_letter('\u{0430}'));
        assert!(is_cyrillic_letter('\u{044F}'));
        assert!(!is_cyrillic_letter('a'));
    }

    #[test]
    fn a_document_holding_both_scripts_determines_neither() {
        let latin: Vec<char> = "hello".chars().collect();
        let cyrillic: Vec<char> = "\u{043C}\u{0438}\u{0440}".chars().collect();
        let both: Vec<char> = "hello \u{043C}\u{0438}\u{0440}".chars().collect();
        let neither: Vec<char> = "1234".chars().collect();

        assert_eq!(document_script(&latin, nothing_is_ambiguous), Script::Latin);
        assert_eq!(
            document_script(&cyrillic, nothing_is_ambiguous),
            Script::Cyrillic
        );
        assert_eq!(
            document_script(&both, nothing_is_ambiguous),
            Script::Undetermined
        );
        assert_eq!(
            document_script(&neither, nothing_is_ambiguous),
            Script::Undetermined
        );
    }

    #[test]
    fn an_ambiguous_codepoint_carries_no_evidence_either_way() {
        // The Cyrillic small o on its own says nothing when it is the very
        // character whose attribution is in question.
        let only_lookalikes: Vec<char> = "\u{043E}\u{0430}".chars().collect();
        assert_eq!(
            document_script(&only_lookalikes, |c| matches!(c, '\u{043E}' | '\u{0430}')),
            Script::Undetermined
        );
    }

    #[test]
    fn both_refusals_name_the_carrier_and_the_figure() {
        let occupied = cover_already_occupied("zero_width", 3).to_string();
        assert!(occupied.contains("zero_width"), "{occupied}");
        assert!(occupied.contains('3'), "{occupied}");

        let partial = channel_ends_mid_byte("bidi", 5).to_string();
        assert!(partial.contains("bidi"), "{partial}");
        assert!(partial.contains('5'), "{partial}");
    }
}
