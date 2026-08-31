//! Check 3: word selection.
//!
//! A double click must still select the same word. A channel character inside a
//! word breaks that in most editors: the selection stops at the invisible
//! character, so the reader gets half a word and, worse, gets it without seeing
//! why. This counts the words that gained an interior channel character and
//! names them.
//!
//! Two separate findings again, because they fail differently:
//!
//! - An interior insertion splits the word for selection.
//! - A homoglyph substitution leaves selection intact and breaks find in page
//!   and spell check instead. The word still selects as one word, and it no
//!   longer matches itself in a search box, and a spell checker underlines it
//!   in red. A red underline is something a reader sees, so this is a fidelity
//!   finding and not only an audit one.
//!
//! Word boundary here is a run of alphanumerics and underscores. See
//! [`super::chars::is_word_char`] for what that includes and excludes.

use super::align::Alignment;
use super::chars;
use super::CheckVerdict;

/// One word the carrier touched.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WordSite {
    /// Cover character index where the word starts.
    pub cover_index: usize,
    /// The word as the cover spells it.
    pub word: String,
    /// How many marks landed inside it.
    pub marks: usize,
}

/// Result of the word selection check.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WordSelectionCheck {
    pub verdict: CheckVerdict,
    /// Words in the cover.
    pub words_total: usize,
    /// Words that gained a channel character between two of their characters.
    pub words_with_interior_channel_char: usize,
    /// Insertions that landed inside a word.
    pub interior_insertions: usize,
    /// Insertions that landed at a word boundary, where they are harmless to
    /// selection. This is the number a placement change is trying to raise.
    pub boundary_insertions: usize,
    /// Words holding a character from a different script than the rest of the
    /// word.
    pub words_with_mixed_script: usize,
    /// Share of cover words that no longer select as one word.
    pub broken_word_ratio: f64,
    /// The broken words themselves, capped at `FidelityOptions::max_locations`.
    pub broken_words: Vec<WordSite>,
    /// The mixed script words, capped the same way.
    pub mixed_script_words: Vec<WordSite>,
}

impl WordSelectionCheck {
    /// What a reader would see, in `0.0..=1.0`.
    ///
    /// A single broken word is already a defect a reader can hit, so the scale
    /// starts at a half rather than at zero once anything is broken. It then
    /// rises with the share of the document affected, because a document where
    /// most words no longer select is a different order of problem and a figure
    /// that saturated on the first word could not say so.
    ///
    /// A mixed script word selects correctly and fails find in page and spell
    /// check, so it is graded below a broken one rather than beside it.
    pub fn reader_risk(&self) -> f64 {
        if !self.verdict.ran() {
            return 0.0;
        }
        let selection = if self.words_with_interior_channel_char == 0 {
            0.0
        } else {
            (0.5 + self.broken_word_ratio * 0.5).min(1.0)
        };
        let mixed = if self.words_with_mixed_script == 0 {
            0.0
        } else {
            0.4
        };
        selection.max(mixed)
    }

    fn could_not_run(reason: String) -> Self {
        Self {
            verdict: CheckVerdict::Indeterminate { reason },
            words_total: 0,
            words_with_interior_channel_char: 0,
            interior_insertions: 0,
            boundary_insertions: 0,
            words_with_mixed_script: 0,
            broken_word_ratio: 0.0,
            broken_words: Vec::new(),
            mixed_script_words: Vec::new(),
        }
    }
}

/// Half-open cover ranges of every word.
fn words(cover: &[char]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start: Option<usize> = None;
    for (index, &c) in cover.iter().enumerate() {
        match (chars::is_word_char(c), start) {
            (true, None) => start = Some(index),
            (false, Some(from)) => {
                spans.push((from, index));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(from) = start {
        spans.push((from, cover.len()));
    }
    spans
}

/// Which word a cover index falls in, by binary search over the spans.
fn word_at(spans: &[(usize, usize)], index: usize) -> Option<usize> {
    spans
        .binary_search_by(|&(from, to)| {
            if index < from {
                std::cmp::Ordering::Greater
            } else if index >= to {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .ok()
}

/// Run the check.
pub fn check(cover: &[char], alignment: &Alignment, max_locations: usize) -> WordSelectionCheck {
    if let Some(reason) = &alignment.failure {
        return WordSelectionCheck::could_not_run(format!(
            "the cover and the marked document could not be paired: {reason}"
        ));
    }

    let spans = words(cover);
    let mut interior_marks: Vec<usize> = vec![0; spans.len()];
    let mut mixed_marks: Vec<usize> = vec![0; spans.len()];
    let mut interior_insertions = 0usize;
    let mut boundary_insertions = 0usize;

    for insertion in &alignment.insertions {
        let at = insertion.cover_index;
        // The character sits between cover[at - 1] and cover[at]. It is inside
        // a word only when both of those belong to the same word.
        let inside = at > 0
            && at < cover.len()
            && chars::is_word_char(cover[at - 1])
            && chars::is_word_char(cover[at]);

        if inside {
            interior_insertions += 1;
            if let Some(word) = word_at(&spans, at) {
                interior_marks[word] += 1;
            }
        } else {
            boundary_insertions += 1;
        }
    }

    for substitution in &alignment.substitutions {
        let at = substitution.cover_index;
        if !chars::is_word_char(substitution.from) || !chars::is_word_char(substitution.to) {
            continue;
        }
        if let Some(word) = word_at(&spans, at) {
            mixed_marks[word] += 1;
        }
    }

    let mut broken_words = Vec::new();
    let mut words_with_interior = 0usize;
    let mut words_mixed = 0usize;
    let mut mixed_script_words = Vec::new();

    for (index, &(from, to)) in spans.iter().enumerate() {
        if interior_marks[index] > 0 {
            words_with_interior += 1;
            if broken_words.len() < max_locations {
                broken_words.push(WordSite {
                    cover_index: from,
                    word: cover[from..to].iter().collect(),
                    marks: interior_marks[index],
                });
            }
        }
        if mixed_marks[index] > 0 {
            words_mixed += 1;
            if mixed_script_words.len() < max_locations {
                mixed_script_words.push(WordSite {
                    cover_index: from,
                    word: cover[from..to].iter().collect(),
                    marks: mixed_marks[index],
                });
            }
        }
    }

    let broken_word_ratio = if spans.is_empty() {
        0.0
    } else {
        words_with_interior as f64 / spans.len() as f64
    };

    let verdict = if words_with_interior > 0 {
        CheckVerdict::Conspicuous
    } else if words_mixed > 0 {
        CheckVerdict::Degraded
    } else {
        CheckVerdict::Clean
    };

    WordSelectionCheck {
        verdict,
        words_total: spans.len(),
        words_with_interior_channel_char: words_with_interior,
        interior_insertions,
        boundary_insertions,
        words_with_mixed_script: words_mixed,
        broken_word_ratio,
        broken_words,
        mixed_script_words,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(cover: &str, marked: &str) -> WordSelectionCheck {
        let cover_chars: Vec<char> = cover.chars().collect();
        let marked_chars: Vec<char> = marked.chars().collect();
        let alignment = Alignment::of(&cover_chars, &marked_chars);
        check(&cover_chars, &alignment, 32)
    }

    #[test]
    fn a_clean_document_selects_as_it_always_did() {
        let text = "the board reviewed the operations";
        let report = run(text, text);
        assert_eq!(report.verdict, CheckVerdict::Clean);
        assert_eq!(report.words_total, 5);
        assert_eq!(report.reader_risk(), 0.0);
    }

    #[test]
    fn a_channel_character_inside_a_word_names_the_word() {
        let report = run("the operations report", "the oper\u{200C}ations report");
        assert_eq!(report.words_with_interior_channel_char, 1);
        assert_eq!(report.interior_insertions, 1);
        assert_eq!(report.boundary_insertions, 0);
        assert_eq!(report.broken_words[0].word, "operations");
        assert_eq!(report.broken_words[0].marks, 1);
        assert_eq!(report.verdict, CheckVerdict::Conspicuous);
    }

    #[test]
    fn a_channel_character_at_a_boundary_costs_nothing() {
        let report = run("the operations report", "the \u{200C}operations report");
        assert_eq!(report.words_with_interior_channel_char, 0);
        assert_eq!(report.boundary_insertions, 1);
        assert_eq!(report.verdict, CheckVerdict::Clean);
        assert_eq!(report.reader_risk(), 0.0);
    }

    #[test]
    fn a_character_after_the_last_letter_of_a_word_is_a_boundary() {
        let report = run("the operations report", "the operations\u{200C} report");
        assert_eq!(report.interior_insertions, 0);
        assert_eq!(report.boundary_insertions, 1);
    }

    /// The placement finding. A carrier that writes after every visible
    /// character puts a mark inside a word almost every time.
    #[test]
    fn placing_after_every_character_breaks_almost_every_word() {
        let cover = "the board reviewed the operations of the northern division";
        let marked: String = cover.chars().flat_map(|c| [c, '\u{200C}']).collect();
        let report = run(cover, &marked);

        assert_eq!(report.words_total, 9);
        assert_eq!(
            report.words_with_interior_channel_char, 9,
            "every multi character word should be broken"
        );
        assert!(
            report.interior_insertions > report.boundary_insertions,
            "{} interior against {} at boundaries",
            report.interior_insertions,
            report.boundary_insertions
        );
        assert_eq!(report.verdict, CheckVerdict::Conspicuous);
        assert!(report.reader_risk() > 0.9);
    }

    /// The same load placed at word boundaries only costs nothing at all here.
    /// This is the comparison the placement change rests on.
    #[test]
    fn the_same_load_at_word_boundaries_breaks_nothing() {
        let cover = "the board reviewed the operations of the northern division";
        let marked: String = cover
            .chars()
            .flat_map(|c| {
                if c == ' ' {
                    vec!['\u{200C}', c]
                } else {
                    vec![c]
                }
            })
            .collect();
        let report = run(cover, &marked);

        assert_eq!(report.words_with_interior_channel_char, 0);
        assert_eq!(report.interior_insertions, 0);
        assert_eq!(report.boundary_insertions, 8);
        assert_eq!(report.verdict, CheckVerdict::Clean);
    }

    #[test]
    fn a_homoglyph_substitution_is_a_mixed_script_word_not_a_broken_one() {
        let report = run("the board reviewed", "the b\u{043E}ard reviewed");
        assert_eq!(report.words_with_interior_channel_char, 0);
        assert_eq!(report.words_with_mixed_script, 1);
        assert_eq!(report.mixed_script_words[0].word, "board");
        assert_eq!(report.verdict, CheckVerdict::Degraded);
    }

    #[test]
    fn the_check_refuses_when_the_documents_cannot_be_paired() {
        let report = run("the quick brown fox", "something else entirely");
        assert!(matches!(report.verdict, CheckVerdict::Indeterminate { .. }));
        assert_eq!(report.words_total, 0);
    }
}
