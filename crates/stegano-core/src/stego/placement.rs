//! Where a carrier may write, shared by the four carriers.
//!
//! Invariant 4 keeps the bit-placement routines the tool's identity: this
//! module does not decide which bit goes where in the stream, nor change any
//! bit's value or order. It decides only which of the cover's gaps and
//! character positions a carrier is allowed to touch, so that a mark lands at a
//! word boundary rather than between two letters (backlog F22) and never inside
//! machine input (backlog F23). The sequence of bits a carrier is handed comes
//! back out of `read_positions` in the same order; only the character position
//! each one occupies in the cover moves.
//!
//! The two facts a placement needs are already defined once, for measurement,
//! in the fidelity module. This module consumes them rather than restating
//! them, so the routine that avoids a defect and the routine that reports it can
//! never disagree:
//!
//! - A word boundary is the same predicate `word_selection` grades against:
//!   [`crate::fidelity::chars::is_word_char`].
//! - A protected region is machine input or an equation, the same ranges
//!   `paste_safety` defines: [`crate::fidelity::paste_safety::protected_regions`]
//!   (code regions plus LaTeX math). Placement avoids all of them so a mark
//!   never lands inside a code span, a fenced block, or an equation
//!   (backlog F23, extended to math for invariant 4b).

use crate::fidelity::chars::{is_format_control, is_word_char};
use crate::fidelity::paste_safety::protected_regions;

/// For each gap `0..=n` of `cover`, whether an inserting carrier may place a
/// channel character there.
///
/// Gap `k` sits between `cover[k - 1]` and `cover[k]`; gap 0 is before the first
/// character and gap `n` is the overflow point past the last. A gap is writable
/// when both hold:
///
/// - It is a word boundary. `word_selection` counts an insertion at cover index
///   `k` as interior only when `cover[k - 1]` and `cover[k]` are both word
///   characters, so a gap where either side is a non-word character, or either
///   edge of the document, costs word selection nothing. This is exactly that
///   test, immediate neighbours and all.
/// - It is clear of a protected region. `paste_safety` flags a mark at cover
///   index `k` when a protected region (a code span, a fenced block, or a LaTeX
///   equation) covers `[from, to)` with `from <= k < to`. The closed range
///   `from..=to` is excluded here so a character can never land immediately
///   inside either delimiter of a span, a block, or an equation.
fn writable_gaps(cover: &[char]) -> Vec<bool> {
    let n = cover.len();
    let regions = protected_regions(cover);
    let mut gaps = vec![false; n + 1];
    for (k, slot) in gaps.iter_mut().enumerate() {
        let boundary =
            k == 0 || k == n || !(is_word_char(cover[k - 1]) && is_word_char(cover[k]));
        let in_protected = regions.iter().any(|&(from, to, _)| from <= k && k <= to);
        *slot = boundary && !in_protected;
    }
    gaps
}

/// How many gaps an inserting carrier may write into: the slot count it reports
/// through `positions()` and sizes its capacity from.
///
/// Counted over the visible skeleton, with format controls removed. A carrier's
/// own controls, which it is refused for holding at all (`check_writable`), are
/// occupancy rather than structure: taking them out first is what keeps the
/// honest slot count from moving when a cover happens to already carry some
/// (backlog F13b). On a clean cover, the only kind a carrier writes into, the
/// skeleton is the cover, so this count is exactly the gaps
/// `place_at_word_boundaries` will use.
pub fn boundary_slots(cover: &str) -> usize {
    let skeleton: Vec<char> = cover.chars().filter(|c| !is_format_control(*c)).collect();
    writable_gaps(&skeleton).into_iter().filter(|w| *w).count()
}

/// Place `sequence` at the writable gaps of `cover`, in order.
///
/// One character per gap, in document order. Whatever does not fit is appended
/// after the last character: that overflow tail is the inserting carriers'
/// identity and is preserved exactly (invariant 4). A bounded carrier sizes its
/// payload so the tail is never reached; an unbounded one leans on it.
pub fn place_at_word_boundaries(cover: &str, sequence: &[char]) -> String {
    let cover_chars: Vec<char> = cover.chars().collect();
    let gaps = writable_gaps(&cover_chars);
    let mut result = String::with_capacity(cover.len() + sequence.len());
    let mut seq = sequence.iter();
    let mut pending = seq.next();

    for (k, &ch) in cover_chars.iter().enumerate() {
        if gaps[k] {
            if let Some(&c) = pending {
                result.push(c);
                pending = seq.next();
            }
        }
        result.push(ch);
    }

    if gaps[cover_chars.len()] {
        if let Some(&c) = pending {
            result.push(c);
            pending = seq.next();
        }
    }

    // Overflow: whatever did not fit goes after the last character.
    while let Some(&c) = pending {
        result.push(c);
        pending = seq.next();
    }

    result
}

/// For each character `0..n` of `cover`, whether it lies inside a protected
/// region: machine input (a code span or fenced block) or a LaTeX equation.
///
/// Half-open `[from, to)`, matching `paste_safety`. A substituting carrier
/// leaves these characters untouched and does not count them as positions, so a
/// command a reader will paste and an equation a reader will render both survive
/// byte for byte (backlog F23, extended to math for invariant 4b). The name is
/// kept for its callers; the set it returns is now code plus math.
pub fn code_character_flags(cover: &[char]) -> Vec<bool> {
    let mut flags = vec![false; cover.len()];
    for (from, to, _) in protected_regions(cover) {
        for flag in flags.iter_mut().take(to.min(cover.len())).skip(from) {
            *flag = true;
        }
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gaps_of(cover: &str) -> Vec<bool> {
        writable_gaps(&cover.chars().collect::<Vec<_>>())
    }

    #[test]
    fn a_gap_between_two_letters_of_a_word_is_not_writable() {
        // "cat": gaps 0 and 3 are edges, 1 and 2 sit between letters.
        let gaps = gaps_of("cat");
        assert_eq!(gaps, vec![true, false, false, true]);
    }

    #[test]
    fn the_gaps_around_a_space_delimited_word_are_writable() {
        // "a b": every gap is a boundary because neither side pairs two letters.
        let gaps = gaps_of("a b");
        assert_eq!(gaps, vec![true, true, true, true]);
    }

    #[test]
    fn placing_at_boundaries_never_lands_between_two_letters() {
        // Enough channel characters to use every boundary, and not one of them
        // may sit inside a word.
        let cover = "the board reviewed the operations";
        let load: Vec<char> = std::iter::repeat('\u{200C}').take(100).collect();
        let marked = place_at_word_boundaries(cover, &load);

        let cover_chars: Vec<char> = cover.chars().collect();
        let mut i = 0usize; // cover
        let mut previous_visible: Option<char> = None;
        for m in marked.chars() {
            if i < cover_chars.len() && cover_chars[i] == m {
                previous_visible = Some(m);
                i += 1;
            } else {
                // An inserted channel character. Its neighbours must not both be
                // word characters.
                let before_is_word = previous_visible.map(is_word_char).unwrap_or(false);
                let after_is_word = cover_chars.get(i).copied().map(is_word_char).unwrap_or(false);
                assert!(
                    !(before_is_word && after_is_word),
                    "a channel character landed between two letters"
                );
            }
        }
    }

    #[test]
    fn a_fenced_block_offers_no_gaps_inside_its_content() {
        let cover = "run\n\n```sh\ncargo test\n```\n\ndone";
        let cover_chars: Vec<char> = cover.chars().collect();
        let gaps = writable_gaps(&cover_chars);
        let content_start = cover.find("cargo").unwrap();
        let content_end = content_start + "cargo test".len();
        for (k, &writable) in gaps.iter().enumerate() {
            if k > content_start && k < content_end {
                assert!(!writable, "gap {k} inside the fenced command is writable");
            }
        }
    }

    #[test]
    fn an_inline_span_marks_its_characters_as_code() {
        let cover = "call `cargo build` now";
        let flags = code_character_flags(&cover.chars().collect::<Vec<_>>());
        let start = cover.find("cargo build").unwrap();
        for i in start..start + "cargo build".len() {
            assert!(flags[i], "character {i} of the inline span is not flagged");
        }
        // The prose around it is not code.
        assert!(!flags[0]);
    }

    #[test]
    fn an_inline_equation_offers_no_gaps_inside_its_content() {
        // "$E=mc^2$": the dollar-delimited equation is protected exactly like a
        // code span, so no channel character can land inside it.
        let cover = "the value $E=mc^2$ holds across this sentence";
        let cover_chars: Vec<char> = cover.chars().collect();
        let gaps = writable_gaps(&cover_chars);
        let content_start = cover.find("E=mc^2").unwrap();
        let content_end = content_start + "E=mc^2".len();
        for (k, &writable) in gaps.iter().enumerate() {
            if k > content_start && k < content_end {
                assert!(!writable, "gap {k} inside the equation is writable");
            }
        }
    }

    #[test]
    fn an_equation_marks_its_characters_as_protected() {
        // A substituting carrier must leave equation characters untouched, so a
        // reader who renders the maths sees exactly the cover.
        let cover = "energy \\(E=mc^2\\) is famous";
        let flags = code_character_flags(&cover.chars().collect::<Vec<_>>());
        let start = cover.find("E=mc^2").unwrap();
        for i in start..start + "E=mc^2".len() {
            assert!(flags[i], "character {i} of the equation is not protected");
        }
        assert!(!flags[0], "the prose is not protected");
    }

    #[test]
    fn a_marked_cover_keeps_its_equation_intact_and_round_trips() {
        use crate::stego::ZeroWidth;
        use crate::traits::StegoMethod;
        let cover =
            "the result $x^2 + y^2 = z^2$ is shown across a long enough sentence to carry a payload";
        let zw = ZeroWidth::new();
        let marked = zw.encode(cover, b"hi").expect("the cover carries the payload");
        // The equation, delimiters and inner spaces included, survives byte for
        // byte: no channel character was placed inside it.
        assert!(
            marked.contains("$x^2 + y^2 = z^2$"),
            "the mark altered the equation"
        );
        // And the payload still reads back, so protecting the maths did not
        // disturb the bit stream (invariant 4).
        assert_eq!(zw.decode(&marked).expect("the payload reads back"), b"hi");
    }
}
