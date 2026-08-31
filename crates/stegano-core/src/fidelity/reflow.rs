//! Where the lines wrap.
//!
//! This is the check a reader fails first. Nobody inspects codepoints, but
//! everybody sees a paragraph whose second line starts on a different word, or
//! a word split across two lines with no hyphen.
//!
//! Two of the four carriers move wrap points by construction:
//!
//! - `zero_width` writes U+200B, line break class ZW, which offers a break
//!   after itself anywhere at all. Inside a word it lets the renderer split
//!   that word.
//! - `whitespace_var` writes U+2060 and U+FEFF, both line break class WJ, which
//!   forbid a break on either side. Placed after a space they delete the wrap
//!   opportunity that space offered.
//!
//! The other two do not. U+200C and the bidi controls are resolved by the line
//! breaker as if they were not present, and a homoglyph is a letter of the same
//! advance width as the letter it replaced.
//!
//! Two figures are reported and they answer different questions. The
//! opportunity counts say the set of legal wrap points changed, which holds at
//! any column width. The moved break list says the document actually lays out
//! differently at `FidelityOptions::wrap_width`, which is what a reader sees. A
//! document can change opportunities without moving a single break at one
//! particular width, so that case is a weaker finding and takes a weaker
//! verdict rather than being dismissed.
//!
//! The model is a deliberate subset of UAX #14, stated in `chars::break_class`.
//! It runs over the cover and the marked document identically, so a shortcoming
//! of the model cancels between the two sides and only a real difference
//! survives.

use std::collections::BTreeSet;

use super::align::Alignment;
use super::chars::{self, BreakClass};
use super::CheckVerdict;

/// A wrap point that is not where it was.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BreakMove {
    /// Which laid out line, counting from one.
    pub line: usize,
    /// The word the cover's line ended on.
    pub cover_break_after: String,
    /// The word the marked document's line ends on instead.
    pub marked_break_after: String,
    /// Cover offset where the cover wrapped.
    pub cover_offset: usize,
    /// Cover offset where the marked document wraps.
    pub marked_offset: usize,
}

/// The reflow check.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReflowCheck {
    pub verdict: CheckVerdict,
    /// Legal wrap points the cover offers.
    pub cover_opportunities: usize,
    /// Legal wrap points the marked document offers.
    pub marked_opportunities: usize,
    /// Wrap points the marked document has and the cover does not.
    pub opportunities_gained: usize,
    /// Wrap points the cover has and the marked document lost.
    pub opportunities_lost: usize,
    /// Of the gained ones, those inside a word. These let a renderer split a
    /// word with no hyphen, which is the visible form of the defect.
    pub gained_inside_words: usize,
    /// Of the lost ones, those between two words. These glue two words into an
    /// unbreakable run.
    pub lost_between_words: usize,
    /// Column width the layout comparison used.
    pub wrap_width: usize,
    /// How many wrap points moved at that width.
    pub moved_breaks_total: usize,
    /// The first `max_locations` of them, named.
    pub moved_breaks: Vec<BreakMove>,
}

impl ReflowCheck {
    /// What a reader would see, in `0.0..=1.0`.
    ///
    /// A moved break is the whole defect: the paragraph is laid out
    /// differently. A changed opportunity that moves no break at this width is
    /// latent rather than absent, because the same document at another width
    /// will show it, so it scores below one and above zero.
    pub fn reader_risk(&self) -> f64 {
        if self.moved_breaks_total > 0 {
            1.0
        } else if self.opportunities_gained + self.opportunities_lost > 0 {
            0.4
        } else {
            0.0
        }
    }

    fn could_not_run(reason: String, wrap_width: usize) -> Self {
        Self {
            verdict: CheckVerdict::Indeterminate { reason },
            cover_opportunities: 0,
            marked_opportunities: 0,
            opportunities_gained: 0,
            opportunities_lost: 0,
            gained_inside_words: 0,
            lost_between_words: 0,
            wrap_width,
            moved_breaks_total: 0,
            moved_breaks: Vec::new(),
        }
    }
}

/// Column width of one character in a laid out line.
///
/// A hard break occupies no column: it ends the line rather than filling it.
fn column_width(c: char) -> usize {
    if chars::break_class(c) == BreakClass::Mandatory {
        0
    } else {
        chars::advance_width(c)
    }
}

/// The indices at which a line may break, each meaning "immediately before the
/// character at this index".
///
/// Characters the line breaker resolves as absent are skipped when deciding, so
/// a break is always reported at the position of a character that is really
/// there. That is also why the bidi controls, class BN, produce no entry of
/// their own and shift nothing.
pub fn break_positions(text: &[char]) -> BTreeSet<usize> {
    let present: Vec<usize> = (0..text.len())
        .filter(|&i| chars::break_class(text[i]) != BreakClass::Ignored)
        .collect();

    let mut breaks = BTreeSet::new();
    for pair in present.windows(2) {
        let (prev, here) = (pair[0], pair[1]);
        if allows_break(chars::break_class(text[prev]), chars::break_class(text[here])) {
            breaks.insert(here);
        }
    }
    breaks
}

/// The pair table, reduced to the classes `chars::break_class` produces.
///
/// Rule order follows UAX #14 and matters: the word joiner prohibition (LB11)
/// is tested before the zero width space allowance (LB8), so a joiner beside a
/// zero width space still forbids the break.
fn allows_break(prev: BreakClass, here: BreakClass) -> bool {
    use BreakClass::*;
    match (prev, here) {
        // LB6: never break before a hard break. LB4 and LB5: always after one.
        (_, Mandatory) => false,
        (Mandatory, _) => true,
        // LB11: no break on either side of a word joiner.
        (Glue, _) | (_, Glue) => false,
        // LB8: break after a zero width space. LB7: never before one.
        (ZeroWidthSpace, _) => true,
        (_, ZeroWidthSpace) => false,
        // LB18: break after a space. LB7: never before one.
        (Space, _) => true,
        (_, Space) => false,
        // LB21: break after a hyphen, whether it renders or not.
        (SoftHyphen, _) | (Hyphen, _) => true,
        // Ideographs break between characters rather than between words.
        (Ideographic, _) | (_, Ideographic) => true,
        // LB28 and the other letter rules: no break between two ordinary
        // characters.
        _ => false,
    }
}

/// One run of text between two consecutive wrap opportunities.
struct Segment {
    start: usize,
    /// Columns the whole run occupies, trailing spaces included.
    full: usize,
    /// Columns up to the last character that puts ink on the page.
    ink: usize,
    /// True when the run ends on a hard break.
    mandatory_end: bool,
}

fn segments(text: &[char], breaks: &BTreeSet<usize>) -> Vec<Segment> {
    let mut bounds: Vec<usize> = std::iter::once(0).chain(breaks.iter().copied()).collect();
    bounds.push(text.len());
    bounds.dedup();

    let mut out = Vec::new();
    for pair in bounds.windows(2) {
        let (start, end) = (pair[0], pair[1]);
        if start >= end {
            continue;
        }
        let full: usize = text[start..end].iter().copied().map(column_width).sum();

        let mut ink = full;
        for &c in text[start..end].iter().rev() {
            match chars::break_class(c) {
                BreakClass::Space | BreakClass::Mandatory | BreakClass::Ignored => {
                    ink = ink.saturating_sub(column_width(c));
                }
                _ => break,
            }
        }

        let mandatory_end = text[start..end]
            .iter()
            .rev()
            .find(|c| chars::break_class(**c) != BreakClass::Ignored)
            .map(|c| chars::break_class(*c) == BreakClass::Mandatory)
            .unwrap_or(false);

        out.push(Segment {
            start,
            full,
            ink,
            mandatory_end,
        });
    }
    out
}

/// Greedy first fit, which is what a browser and a plain text viewer both do.
///
/// Returns the offsets the lines wrapped at. Hard breaks are excluded: they are
/// in the source text and are identical on both sides, so including them would
/// pad both sequences with matching entries and nothing else.
fn layout(segs: &[Segment], width: usize) -> Vec<usize> {
    let mut wraps = Vec::new();
    let mut line_full = 0usize;
    let mut line_empty = true;

    for seg in segs {
        if line_empty {
            line_full = seg.full;
            line_empty = false;
        } else if line_full + seg.ink <= width {
            line_full += seg.full;
        } else {
            wraps.push(seg.start);
            line_full = seg.full;
        }
        if seg.mandatory_end {
            line_empty = true;
            line_full = 0;
        }
    }
    wraps
}

/// The word a line ended on, read backwards from a wrap offset.
///
/// Empty when the wrap follows no word, which happens at the very start of a
/// document.
fn word_before(cover: &[char], offset: usize) -> String {
    let mut end = offset.min(cover.len());
    while end > 0 && !chars::is_word_char(cover[end - 1]) {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && chars::is_word_char(cover[start - 1]) {
        start -= 1;
    }
    cover[start..end].iter().collect()
}

/// Run the check.
pub fn check(
    cover: &[char],
    marked: &[char],
    alignment: &Alignment,
    wrap_width: usize,
    max_locations: usize,
) -> ReflowCheck {
    if let Some(reason) = &alignment.failure {
        return ReflowCheck::could_not_run(
            format!("the cover and the marked document could not be paired: {reason}"),
            wrap_width,
        );
    }

    let cover_breaks = break_positions(cover);
    let marked_breaks = break_positions(marked);

    // Both sides expressed in cover offsets, the only space in which two texts
    // of different lengths compare position by position.
    let marked_in_cover: BTreeSet<usize> = marked_breaks
        .iter()
        .filter_map(|&j| alignment.marked_to_cover.get(j).copied())
        .collect();

    let gained: Vec<usize> = marked_in_cover.difference(&cover_breaks).copied().collect();
    let lost: Vec<usize> = cover_breaks.difference(&marked_in_cover).copied().collect();

    let inside_word = |offset: usize| -> bool {
        offset > 0
            && offset < cover.len()
            && chars::is_word_char(cover[offset - 1])
            && chars::is_word_char(cover[offset])
    };
    let between_words = |offset: usize| -> bool {
        offset > 0 && offset <= cover.len() && !chars::is_word_char(cover[offset - 1])
    };

    let gained_inside_words = gained.iter().copied().filter(|&o| inside_word(o)).count();
    let lost_between_words = lost.iter().copied().filter(|&o| between_words(o)).count();

    let cover_wraps = layout(&segments(cover, &cover_breaks), wrap_width);
    let marked_wraps: Vec<usize> = layout(&segments(marked, &marked_breaks), wrap_width)
        .into_iter()
        .filter_map(|j| alignment.marked_to_cover.get(j).copied())
        .collect();

    let mut moved_breaks = Vec::new();
    let mut moved_breaks_total = 0usize;
    let lines = cover_wraps.len().max(marked_wraps.len());
    for line in 0..lines {
        let in_cover = cover_wraps.get(line).copied();
        let in_marked = marked_wraps.get(line).copied();
        if in_cover == in_marked {
            continue;
        }
        moved_breaks_total += 1;
        if moved_breaks.len() < max_locations {
            moved_breaks.push(BreakMove {
                line: line + 1,
                cover_break_after: in_cover.map(|o| word_before(cover, o)).unwrap_or_default(),
                marked_break_after: in_marked.map(|o| word_before(cover, o)).unwrap_or_default(),
                cover_offset: in_cover.unwrap_or(cover.len()),
                marked_offset: in_marked.unwrap_or(cover.len()),
            });
        }
    }

    let verdict = if moved_breaks_total > 0 {
        CheckVerdict::Conspicuous
    } else if !gained.is_empty() || !lost.is_empty() {
        CheckVerdict::Degraded
    } else {
        CheckVerdict::Clean
    };

    ReflowCheck {
        verdict,
        cover_opportunities: cover_breaks.len(),
        marked_opportunities: marked_breaks.len(),
        opportunities_gained: gained.len(),
        opportunities_lost: lost.len(),
        gained_inside_words,
        lost_between_words,
        wrap_width,
        moved_breaks_total,
        moved_breaks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chars_of(s: &str) -> Vec<char> {
        s.chars().collect()
    }

    fn run(cover: &str, marked: &str, width: usize) -> ReflowCheck {
        let c = chars_of(cover);
        let m = chars_of(marked);
        let alignment = Alignment::of(&c, &m);
        check(&c, &m, &alignment, width, 32)
    }

    #[test]
    fn a_space_offers_a_wrap_and_a_letter_does_not() {
        let text = chars_of("alpha beta");
        assert_eq!(break_positions(&text).into_iter().collect::<Vec<_>>(), vec![6]);
    }

    #[test]
    fn the_word_joiner_deletes_the_wrap_the_space_offered() {
        let text = chars_of("alpha \u{2060}beta");
        assert!(break_positions(&text).is_empty());
    }

    #[test]
    fn the_zero_width_space_adds_a_wrap_inside_a_word() {
        let text = chars_of("inter\u{200B}nationalisation");
        assert_eq!(break_positions(&text).into_iter().collect::<Vec<_>>(), vec![6]);
    }

    #[test]
    fn the_bidi_controls_move_nothing() {
        // Class BN: resolved as if not present. This is what separates bidi
        // from the other two invisible carriers on this check.
        let report = run("alpha beta gamma", "a\u{200E}lpha \u{200F}beta\u{202C} gamma", 80);
        assert_eq!(report.opportunities_gained, 0);
        assert_eq!(report.opportunities_lost, 0);
        assert_eq!(report.verdict, CheckVerdict::Clean);
        assert_eq!(report.reader_risk(), 0.0);
    }

    #[test]
    fn a_substitution_moves_nothing() {
        let report = run("the operations", "the \u{043E}perations", 80);
        assert_eq!(report.opportunities_gained, 0);
        assert_eq!(report.opportunities_lost, 0);
        assert_eq!(report.moved_breaks_total, 0);
    }

    #[test]
    fn a_lost_wrap_between_two_words_is_counted_as_such() {
        let report = run("alpha beta gamma", "alpha \u{2060}beta gamma", 80);
        assert_eq!(report.opportunities_lost, 1);
        assert_eq!(report.lost_between_words, 1);
        assert_eq!(report.opportunities_gained, 0);
        assert_eq!(report.verdict, CheckVerdict::Degraded);
    }

    #[test]
    fn a_gained_wrap_inside_a_word_is_counted_as_such() {
        let report = run("alpha beta", "al\u{200B}pha beta", 80);
        assert_eq!(report.opportunities_gained, 1);
        assert_eq!(report.gained_inside_words, 1);
    }

    #[test]
    fn a_hard_break_is_a_break_and_nothing_breaks_before_it() {
        let text = chars_of("one\ntwo");
        assert_eq!(break_positions(&text).into_iter().collect::<Vec<_>>(), vec![4]);
    }

    #[test]
    fn ideographs_break_between_characters() {
        let text = chars_of("\u{65E5}\u{672C}\u{8A9E}");
        assert_eq!(break_positions(&text).len(), 2);
    }

    #[test]
    fn a_moved_break_names_the_word_the_line_used_to_end_on() {
        let cover = "the board reviewed the operations of the northern division this quarter";
        let at = cover.find("operations").unwrap();
        let marked: String = cover
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                let mut out = Vec::new();
                if i == at {
                    out.push('\u{2060}');
                }
                out.push(c);
                out
            })
            .collect();

        let report = run(cover, &marked, 24);
        assert_eq!(report.moved_breaks_total, 1, "{:?}", report.moved_breaks);
        assert_eq!(report.moved_breaks[0].cover_break_after, "the");
        assert_eq!(report.moved_breaks[0].marked_break_after, "reviewed");
        assert_eq!(report.verdict, CheckVerdict::Conspicuous);
        assert_eq!(report.reader_risk(), 1.0);
    }

    #[test]
    fn an_untouched_document_wraps_where_it_always_did() {
        let cover = "the board reviewed the operations of the northern division this quarter";
        let report = run(cover, cover, 24);
        assert_eq!(report.moved_breaks_total, 0);
        assert_eq!(report.verdict, CheckVerdict::Clean);
        assert_eq!(report.reader_risk(), 0.0);
    }

    #[test]
    fn a_pair_that_cannot_be_aligned_reports_that_it_could_not_run() {
        let report = run("the quick brown fox", "entirely unrelated prose", 80);
        assert!(matches!(report.verdict, CheckVerdict::Indeterminate { .. }));
        assert_eq!(report.reader_risk(), 0.0);
    }
}
