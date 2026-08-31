//! Check 7: paste safety, backlog F9.
//!
//! Beyond the five checks invariant 4b names, and here because
//! `tests/corpus/technical_markdown.md` exists to expose it: a channel
//! character inside a fenced code block or an inline code span corrupts
//! something a reader will paste into a shell. The document still looks like
//! its cover, and the command still fails, which is worse than a visible defect
//! because nothing on screen explains it.
//!
//! Code regions are found the way a Markdown reader finds them: a line whose
//! first non-space characters are three backticks opens or closes a fence, and
//! inside ordinary lines a pair of backticks delimits an inline span. Indented
//! code blocks are not detected, and that limit is stated rather than hidden.

use super::align::Alignment;
use super::CheckVerdict;

/// One mark that landed in machine input.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CodeSite {
    pub cover_index: usize,
    /// `fence` or `inline`.
    pub region_kind: &'static str,
    /// The codepoint that landed there.
    pub codepoint: String,
    /// The surrounding cover text, so the report shows what breaks.
    pub excerpt: String,
}

/// Result of the paste safety check.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PasteSafetyCheck {
    pub verdict: CheckVerdict,
    /// Fenced blocks plus inline spans found in the cover.
    pub code_regions: usize,
    /// Cover characters those regions cover.
    pub code_characters: usize,
    pub marks_inside_code: usize,
    pub sites: Vec<CodeSite>,
}

impl PasteSafetyCheck {
    /// What a reader would see, in `0.0..=1.0`.
    ///
    /// Machine input either survives a paste or it does not, so this check has
    /// no middle grade. One mark in a command is the whole failure.
    pub fn reader_risk(&self) -> f64 {
        if !self.verdict.ran() {
            return 0.0;
        }
        if self.marks_inside_code > 0 {
            1.0
        } else {
            0.0
        }
    }

    fn could_not_run(reason: String) -> Self {
        Self {
            verdict: CheckVerdict::Indeterminate { reason },
            code_regions: 0,
            code_characters: 0,
            marks_inside_code: 0,
            sites: Vec::new(),
        }
    }
}

/// Half-open cover ranges of every code region, with its kind.
///
/// Exposed to the crate so placement can consume the exact ranges this check
/// measures against (backlog F23). One definition of a code region, shared by
/// the routine that avoids them and the routine that reports any that were not
/// avoided, so the two can never drift apart.
pub(crate) fn code_regions(cover: &[char]) -> Vec<(usize, usize, &'static str)> {
    let mut regions = Vec::new();

    // Line spans first, so fences can be recognised by their own line.
    let mut line_start = 0usize;
    let mut lines: Vec<(usize, usize)> = Vec::new();
    for (index, &c) in cover.iter().enumerate() {
        if c == '\n' {
            lines.push((line_start, index));
            line_start = index + 1;
        }
    }
    if line_start < cover.len() {
        lines.push((line_start, cover.len()));
    }

    let is_fence = |from: usize, to: usize| {
        let mut cursor = from;
        while cursor < to && (cover[cursor] == ' ' || cover[cursor] == '\t') {
            cursor += 1;
        }
        cursor + 2 < to + 1
            && cover.get(cursor) == Some(&'`')
            && cover.get(cursor + 1) == Some(&'`')
            && cover.get(cursor + 2) == Some(&'`')
    };

    let mut open_fence: Option<usize> = None;
    for &(from, to) in &lines {
        if is_fence(from, to) {
            match open_fence {
                // The fence content is what a reader pastes: the opening line
                // carries the language tag and the closing line carries
                // nothing, so neither belongs to the region.
                Some(content_start) => {
                    regions.push((content_start, from, "fence"));
                    open_fence = None;
                }
                None => open_fence = Some(to + 1),
            }
            continue;
        }

        if open_fence.is_some() {
            continue;
        }

        // Inline spans, one line at a time.
        let mut cursor = from;
        while cursor < to {
            if cover[cursor] == '`' {
                if let Some(close) = (cursor + 1..to).find(|&i| cover[i] == '`') {
                    regions.push((cursor + 1, close, "inline"));
                    cursor = close + 1;
                    continue;
                }
            }
            cursor += 1;
        }
    }

    // An unterminated fence runs to the end of the document, which is what a
    // Markdown reader does with it.
    if let Some(content_start) = open_fence {
        if content_start < cover.len() {
            regions.push((content_start, cover.len(), "fence"));
        }
    }

    regions
}

/// Half-open cover ranges of every LaTeX math region, inline and display.
///
/// The delimiter rules follow the CommonMark-aligned convention proven in the
/// document converter this lab already ships (its inline-math splitter): an
/// opening `$` is not followed by a space or newline and a closing `$` is not
/// preceded by one, `\$` is an escaped literal dollar, `$$` and `\[` open
/// display math, and `$` and `\(` open inline math. The range returned is the
/// content between the delimiters, matching `code_regions`.
///
/// A channel character placed inside an equation breaks it, so placement
/// protects these ranges the same way it protects code (invariant 4b: a marked
/// text must look like its cover). This is detection only; it never rewrites
/// the cover.
pub(crate) fn math_regions(cover: &[char]) -> Vec<(usize, usize, &'static str)> {
    let n = cover.len();
    let mut regions = Vec::new();

    // First index `j >= start` where the two-character delimiter `a b` begins.
    let find_close = |start: usize, a: char, b: char| -> Option<usize> {
        let mut j = start;
        while j + 1 < n {
            if cover[j] == a && cover[j + 1] == b {
                return Some(j);
            }
            j += 1;
        }
        None
    };

    let mut i = 0usize;
    while i < n {
        let c = cover[i];

        // An escaped dollar is a literal, never a delimiter.
        if c == '\\' && i + 1 < n && cover[i + 1] == '$' {
            i += 2;
            continue;
        }

        // Display math: \[ ... \]
        if c == '\\' && i + 1 < n && cover[i + 1] == '[' {
            if let Some(close) = find_close(i + 2, '\\', ']') {
                if close > i + 2 {
                    regions.push((i + 2, close, "math_display"));
                }
                i = close + 2;
                continue;
            }
        }

        // Inline math: \( ... \)
        if c == '\\' && i + 1 < n && cover[i + 1] == '(' {
            if let Some(close) = find_close(i + 2, '\\', ')') {
                if close > i + 2 {
                    regions.push((i + 2, close, "math_inline"));
                }
                i = close + 2;
                continue;
            }
        }

        // Display math: $$ ... $$
        if c == '$' && i + 1 < n && cover[i + 1] == '$' {
            if let Some(close) = find_close(i + 2, '$', '$') {
                if close > i + 2 {
                    regions.push((i + 2, close, "math_display"));
                }
                i = close + 2;
            } else {
                // An unterminated `$$` is a literal pair, not a region.
                i += 2;
            }
            continue;
        }

        // Inline math: $ ... $ with the CommonMark spacing rules.
        if c == '$' {
            let start = i + 1;
            if start < n && cover[start] != ' ' && cover[start] != '\n' && cover[start] != '\r' {
                let mut j = start;
                let mut found = None;
                while j < n {
                    if cover[j] == '$' {
                        if j > start && cover[j - 1] != ' ' && cover[j - 1] != '\n' {
                            found = Some(j);
                        }
                        break;
                    }
                    j += 1;
                }
                if let Some(close) = found {
                    regions.push((start, close, "math_inline"));
                    i = close + 1;
                    continue;
                }
            }
        }

        i += 1;
    }

    regions
}

/// The half-open cover ranges a placement must keep clear: code regions and
/// math regions together.
///
/// Placement avoids all of these so a mark never lands inside machine input or
/// an equation. The paste-safety metric ([`check`]) still measures against
/// `code_regions` alone, so extending what placement protects does not move
/// what the metric reports.
pub(crate) fn protected_regions(cover: &[char]) -> Vec<(usize, usize, &'static str)> {
    let mut regions = code_regions(cover);
    regions.extend(math_regions(cover));
    regions
}

/// Run the check.
pub fn check(cover: &[char], alignment: &Alignment, max_locations: usize) -> PasteSafetyCheck {
    if let Some(reason) = &alignment.failure {
        return PasteSafetyCheck::could_not_run(format!(
            "the cover and the marked document could not be paired: {reason}"
        ));
    }

    let regions = code_regions(cover);
    let code_characters: usize = regions.iter().map(|(from, to, _)| to - from).sum();

    let mut marks_inside_code = 0usize;
    let mut sites = Vec::new();

    let mut record = |at: usize, codepoint: String| {
        let region = regions
            .iter()
            .find(|(from, to, _)| at >= *from && at < *to)
            .map(|(_, _, kind)| *kind);
        if let Some(kind) = region {
            marks_inside_code += 1;
            if sites.len() < max_locations {
                let from = at.saturating_sub(20);
                let to = (at + 20).min(cover.len());
                sites.push(CodeSite {
                    cover_index: at,
                    region_kind: kind,
                    codepoint,
                    excerpt: cover[from..to].iter().collect::<String>().replace('\n', " "),
                });
            }
        }
    };

    for insertion in &alignment.insertions {
        record(insertion.cover_index, insertion.codepoint.clone());
    }
    for substitution in &alignment.substitutions {
        record(substitution.cover_index, substitution.codepoint.clone());
    }

    // Machine input either survives a paste or it does not. There is no partial
    // grade between the two, so this check has one failing verdict.
    let verdict = if marks_inside_code > 0 {
        CheckVerdict::Conspicuous
    } else {
        CheckVerdict::Clean
    };

    PasteSafetyCheck {
        verdict,
        code_regions: regions.len(),
        code_characters,
        marks_inside_code,
        sites,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(cover: &str, marked: &str) -> PasteSafetyCheck {
        let cover_chars: Vec<char> = cover.chars().collect();
        let marked_chars: Vec<char> = marked.chars().collect();
        let alignment = Alignment::of(&cover_chars, &marked_chars);
        check(&cover_chars, &alignment, 32)
    }

    #[test]
    fn prose_has_no_code_regions_and_no_finding() {
        let cover = "A plain paragraph with nothing machine readable in it.";
        let marked = "A plain\u{200B} paragraph with nothing machine readable in it.";
        let report = run(cover, marked);
        assert_eq!(report.code_regions, 0);
        assert_eq!(report.marks_inside_code, 0);
        assert_eq!(report.verdict, CheckVerdict::Clean);
    }

    #[test]
    fn a_mark_inside_a_fence_is_reported_with_the_command_it_breaks() {
        let cover = "Run:\n\n```sh\ncargo test --workspace\n```\n\nDone.\n";
        let marked = cover.replacen("--workspace", "--work\u{200B}space", 1);
        let report = run(cover, &marked);

        assert_eq!(report.code_regions, 1);
        assert_eq!(report.marks_inside_code, 1);
        assert_eq!(report.sites[0].region_kind, "fence");
        assert!(report.sites[0].excerpt.contains("cargo"));
        assert_eq!(report.verdict, CheckVerdict::Conspicuous);
        assert_eq!(report.reader_risk(), 1.0);
    }

    #[test]
    fn a_mark_in_the_prose_around_a_fence_is_not_a_finding() {
        let cover = "Run:\n\n```sh\ncargo test\n```\n\nDone.\n";
        let marked = cover.replacen("Done", "Do\u{200B}ne", 1);
        let report = run(cover, &marked);

        assert_eq!(report.code_regions, 1);
        assert_eq!(report.marks_inside_code, 0);
        assert_eq!(report.verdict, CheckVerdict::Clean);
    }

    #[test]
    fn an_inline_span_counts_as_machine_input_too() {
        let cover = "Call `cargo build` before shipping.";
        let marked = cover.replacen("build", "bu\u{200C}ild", 1);
        let report = run(cover, &marked);

        assert_eq!(report.code_regions, 1);
        assert_eq!(report.marks_inside_code, 1);
        assert_eq!(report.sites[0].region_kind, "inline");
    }

    #[test]
    fn a_homoglyph_substitution_inside_a_command_counts_as_well() {
        // This one is worse than an invisible character: the command reads
        // correctly on screen and fails on paste with no visible cause.
        let cover = "Call `cargo build` before shipping.";
        let marked = cover.replacen("cargo", "carg\u{043E}", 1);
        let report = run(cover, &marked);

        assert_eq!(report.marks_inside_code, 1);
        assert_eq!(report.verdict, CheckVerdict::Conspicuous);
    }

    #[test]
    fn the_check_refuses_when_the_documents_cannot_be_paired() {
        let report = run("the quick brown fox", "something else entirely");
        assert!(matches!(report.verdict, CheckVerdict::Indeterminate { .. }));
    }

    fn math_of(cover: &str) -> Vec<(usize, usize, &'static str)> {
        math_regions(&cover.chars().collect::<Vec<_>>())
    }

    #[test]
    fn inline_dollar_math_is_one_region_of_its_content() {
        let cover = "the value $E=mc^2$ is famous";
        let regions = math_of(cover);
        let start = cover.find("E=mc^2").unwrap();
        assert_eq!(regions, vec![(start, start + "E=mc^2".len(), "math_inline")]);
    }

    #[test]
    fn backslash_paren_and_bracket_are_inline_and_display() {
        assert_eq!(math_of("energy \\(E=mc^2\\) here")[0].2, "math_inline");
        assert_eq!(math_of("block \\[a+b=c\\] here")[0].2, "math_display");
    }

    #[test]
    fn double_dollar_is_display_math() {
        let cover = "before $$a^2+b^2$$ after";
        let regions = math_of(cover);
        let start = cover.find("a^2+b^2").unwrap();
        assert_eq!(regions, vec![(start, start + "a^2+b^2".len(), "math_display")]);
    }

    #[test]
    fn an_escaped_dollar_is_not_math() {
        assert!(math_of("costs \\$5 today").is_empty());
    }

    #[test]
    fn a_dollar_with_a_space_after_it_is_not_math() {
        // The CommonMark spacing rule: "$ x $" is not inline math, and currency
        // with a space before the next dollar is not a closing delimiter.
        assert!(math_of("test $ x $ done").is_empty());
        assert!(math_of("paid $5 and $10 total").is_empty());
    }

    #[test]
    fn protected_regions_is_code_and_math_together() {
        let cover = "run `make` then compute $x+1$ here";
        let chars: Vec<char> = cover.chars().collect();
        let protected = protected_regions(&chars);
        assert!(protected.iter().any(|&(_, _, k)| k == "inline"));
        assert!(protected.iter().any(|&(_, _, k)| k == "math_inline"));
    }
}
