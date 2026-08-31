//! Pairing a marked document with its cover, character by character.
//!
//! Every fidelity check needs the same thing first: which characters the
//! carrier added, which ones it replaced, and where each of them sits in the
//! cover. That is one walk, done once, and shared.
//!
//! It is not a general diff. The four carriers make exactly two kinds of edit,
//! insert a format control or substitute one visible character for a lookalike,
//! and both preserve document order. A walk that assumes those two edits gives
//! exact positions where a general diff would give a plausible guess. When the
//! assumption does not hold, the walk refuses and names why, so the checks
//! built on it report that they could not run rather than measuring noise.

use super::chars;

/// A character the marked document holds and the cover does not.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Insertion {
    /// The cover character this one was placed in front of. `cover_len` means
    /// it sits past the end of the cover, in the overflow tail.
    pub cover_index: usize,
    /// Where it sits in the marked document.
    pub marked_index: usize,
    /// The character itself.
    pub character: char,
    /// `U+200C` style label, so a report reads without a decoder ring.
    pub codepoint: String,
}

/// A cover character the marked document replaced with another.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Substitution {
    pub cover_index: usize,
    pub marked_index: usize,
    pub from: char,
    pub to: char,
    pub codepoint: String,
}

/// The result of the walk.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Alignment {
    pub cover_len: usize,
    pub marked_len: usize,
    /// For each marked character, the cover index it belongs to. Empty when the
    /// walk failed.
    #[serde(skip)]
    pub marked_to_cover: Vec<usize>,
    pub insertions: Vec<Insertion>,
    pub substitutions: Vec<Substitution>,
    /// Set when the two documents could not be paired. Every check that reads
    /// insertions or substitutions must report itself indeterminate when this
    /// is set, never clean.
    pub failure: Option<String>,
}

impl Alignment {
    /// Pair `marked` against `cover`.
    pub fn of(cover: &[char], marked: &[char]) -> Self {
        let mut insertions = Vec::new();
        let mut substitutions = Vec::new();
        let mut marked_to_cover = Vec::with_capacity(marked.len());

        let mut i = 0usize; // cover
        let mut j = 0usize; // marked

        while j < marked.len() {
            let m = marked[j];

            if i < cover.len() && cover[i] == m {
                marked_to_cover.push(i);
                i += 1;
                j += 1;
                continue;
            }

            if chars::is_format_control(m) {
                // Placed in front of cover character `i`, or past the end of
                // the cover when `i` has run out.
                insertions.push(Insertion {
                    cover_index: i,
                    marked_index: j,
                    character: m,
                    codepoint: chars::codepoint_label(m),
                });
                marked_to_cover.push(i.min(cover.len()));
                j += 1;
                continue;
            }

            if i < cover.len() {
                if chars::is_format_control(cover[i]) {
                    // The cover carries a control the marked text does not. The
                    // carriers only add, never remove, so the pairing has come
                    // apart and anything measured past here would be noise.
                    return Self::refused(
                        cover.len(),
                        marked.len(),
                        format!(
                            "cover character {i} is {} and the marked document does not carry it, \
                             so the two texts cannot be paired",
                            chars::codepoint_label(cover[i])
                        ),
                    );
                }
                substitutions.push(Substitution {
                    cover_index: i,
                    marked_index: j,
                    from: cover[i],
                    to: m,
                    codepoint: chars::codepoint_label(m),
                });
                marked_to_cover.push(i);
                i += 1;
                j += 1;
                continue;
            }

            return Self::refused(
                cover.len(),
                marked.len(),
                format!(
                    "marked character {j} is {:?}, which is visible content the cover does not have",
                    m
                ),
            );
        }

        if i < cover.len() {
            return Self::refused(
                cover.len(),
                marked.len(),
                format!(
                    "{} cover characters from index {i} are absent from the marked document",
                    cover.len() - i
                ),
            );
        }

        Self {
            cover_len: cover.len(),
            marked_len: marked.len(),
            marked_to_cover,
            insertions,
            substitutions,
            failure: None,
        }
    }

    /// A refusal carries no measurements at all. Returning the partial ones
    /// would let a caller read a half walk as a whole one, which is the silent
    /// degradation invariant 2 forbids.
    fn refused(cover_len: usize, marked_len: usize, reason: String) -> Self {
        Self {
            cover_len,
            marked_len,
            marked_to_cover: Vec::new(),
            insertions: Vec::new(),
            substitutions: Vec::new(),
            failure: Some(reason),
        }
    }

    /// Every mark the carrier left, by cover index, in document order.
    pub fn mark_positions(&self) -> Vec<usize> {
        let mut positions: Vec<usize> = self
            .insertions
            .iter()
            .map(|ins| ins.cover_index)
            .chain(self.substitutions.iter().map(|sub| sub.cover_index))
            .collect();
        positions.sort_unstable();
        positions
    }

    /// How many marks in total.
    pub fn marks(&self) -> usize {
        self.insertions.len() + self.substitutions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chars_of(s: &str) -> Vec<char> {
        s.chars().collect()
    }

    #[test]
    fn an_untouched_document_shows_no_marks() {
        let cover = chars_of("the quarterly report");
        let alignment = Alignment::of(&cover, &cover);
        assert!(alignment.failure.is_none());
        assert_eq!(alignment.marks(), 0);
    }

    #[test]
    fn an_inserted_control_is_located_in_the_cover() {
        let cover = chars_of("abcdef");
        let marked = chars_of("abc\u{200B}def");
        let alignment = Alignment::of(&cover, &marked);

        assert!(alignment.failure.is_none());
        assert_eq!(alignment.insertions.len(), 1);
        assert_eq!(alignment.insertions[0].cover_index, 3);
        assert_eq!(alignment.insertions[0].marked_index, 3);
        assert_eq!(alignment.insertions[0].codepoint, "U+200B");
        assert!(alignment.substitutions.is_empty());
    }

    #[test]
    fn a_substituted_letter_is_located_in_the_cover() {
        let cover = chars_of("about");
        let marked = chars_of("\u{0430}bout");
        let alignment = Alignment::of(&cover, &marked);

        assert!(alignment.failure.is_none());
        assert_eq!(alignment.substitutions.len(), 1);
        assert_eq!(alignment.substitutions[0].cover_index, 0);
        assert_eq!(alignment.substitutions[0].from, 'a');
        assert_eq!(alignment.substitutions[0].to, '\u{0430}');
    }

    #[test]
    fn overflow_past_the_end_of_the_cover_is_located_past_the_end() {
        let cover = chars_of("ab");
        let marked = chars_of("a\u{200B}b\u{200B}\u{200C}\u{200C}");
        let alignment = Alignment::of(&cover, &marked);

        assert!(alignment.failure.is_none());
        assert_eq!(alignment.insertions.len(), 4);
        assert_eq!(alignment.insertions[3].cover_index, 2, "past the last cover character");
    }

    #[test]
    fn a_cover_that_already_carries_controls_still_pairs() {
        // `already_carrying.txt` is this case: the cover holds controls of its
        // own before any carrier touches it.
        let cover = chars_of("ab\u{2060}cd");
        let marked = chars_of("a\u{200C}b\u{200C}\u{2060}c\u{200C}d");
        let alignment = Alignment::of(&cover, &marked);

        assert!(alignment.failure.is_none(), "{:?}", alignment.failure);
        assert_eq!(alignment.insertions.len(), 3);
    }

    #[test]
    fn unrelated_texts_are_refused_rather_than_guessed_at() {
        let cover = chars_of("the quick brown fox");
        let marked = chars_of("entirely different prose");
        let alignment = Alignment::of(&cover, &marked);

        assert!(alignment.failure.is_some());
        assert!(alignment.insertions.is_empty(), "a refusal carries no measurements");
        assert!(alignment.substitutions.is_empty());
        assert!(alignment.marked_to_cover.is_empty());
    }

    #[test]
    fn a_truncated_document_is_refused_by_name() {
        let cover = chars_of("the quarterly report");
        let marked = chars_of("the quarterly");
        let alignment = Alignment::of(&cover, &marked);

        let reason = alignment.failure.expect("truncation must be refused");
        assert!(reason.contains("absent"), "reason was: {reason}");
    }

    #[test]
    fn mark_positions_come_back_in_document_order() {
        let cover = chars_of("abcdef");
        let marked = chars_of("\u{0430}b\u{200B}cdef");
        let alignment = Alignment::of(&cover, &marked);
        assert_eq!(alignment.mark_positions(), vec![0, 2]);
    }
}
