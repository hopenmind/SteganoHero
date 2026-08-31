//! Check 4: distribution evenness.
//!
//! A concentrated block is what an analyst finds first, so this reports a real
//! statistic rather than an impression.
//!
//! The primary figure is a one sample Kolmogorov-Smirnov statistic: the largest
//! distance between the empirical distribution of mark positions and the
//! uniform distribution over the available positions. It is compared against
//! the standard asymptotic 5 percent critical value, `1.36 / sqrt(k)`.
//!
//! It is paired with the gap figures because the two catch different failures.
//! A carrier that writes into the first tenth of a document produces perfectly
//! regular gaps, so a coefficient of variation on the gaps alone reads as
//! flawless while the document is as concentrated as it can be. The
//! Kolmogorov-Smirnov distance catches that, and the mean absolute gap
//! deviation catches it too by comparing the gaps against the spacing a uniform
//! placement would have used.

use super::align::Alignment;
use super::CheckVerdict;

/// The window of the document holding the most marks.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DenseWindow {
    /// First cover index of the window.
    pub start: usize,
    /// One past the last cover index of the window.
    pub end: usize,
    /// Marks inside it.
    pub marks: usize,
    /// Marks a uniform placement would have put in a window this size.
    pub expected: f64,
}

/// The widest run of positions carrying nothing.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LargestGap {
    pub positions: usize,
    pub starts_at: usize,
}

/// Result of the distribution check.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DistributionCheck {
    pub verdict: CheckVerdict,
    /// Marks placed.
    pub marks: usize,
    /// Positions they were placed among.
    pub cover_positions: usize,
    /// Spacing a uniform placement would have used.
    pub uniform_gap: f64,
    pub gap_mean: f64,
    pub gap_stddev: f64,
    /// Standard deviation over mean. Blind to concentration on its own, which
    /// is why it is not the headline figure.
    pub gap_coefficient_of_variation: f64,
    /// Mean of `|gap - uniform_gap|`, as a share of `uniform_gap`.
    pub mean_absolute_gap_deviation: f64,
    /// Kolmogorov-Smirnov distance from uniform.
    pub ks_statistic: f64,
    /// `1.36 / sqrt(marks)`.
    pub ks_critical_5pct: f64,
    /// True when the placement is indistinguishable from uniform at that level.
    pub uniform_at_5pct: bool,
    pub largest_gap: LargestGap,
    /// Where the marks bunch up, when they do.
    pub densest_window: Option<DenseWindow>,
}

impl DistributionCheck {
    /// What an analyst finds, in `0.0..=1.0`.
    ///
    /// Concentration is what an analyst looks for first, not something a reader
    /// can see, so this feeds the analyst axis and never the reader one. The
    /// Kolmogorov-Smirnov statistic is already scaled to `0.0..=1.0`, so it is
    /// used directly rather than passed through a curve nobody can audit.
    pub fn analyst_risk(&self) -> f64 {
        if !self.verdict.ran() || self.uniform_at_5pct {
            return 0.0;
        }
        self.ks_statistic.clamp(0.0, 1.0)
    }

    fn empty(verdict: CheckVerdict, cover_positions: usize) -> Self {
        Self {
            verdict,
            marks: 0,
            cover_positions,
            uniform_gap: 0.0,
            gap_mean: 0.0,
            gap_stddev: 0.0,
            gap_coefficient_of_variation: 0.0,
            mean_absolute_gap_deviation: 0.0,
            ks_statistic: 0.0,
            ks_critical_5pct: 0.0,
            uniform_at_5pct: true,
            largest_gap: LargestGap {
                positions: cover_positions,
                starts_at: 0,
            },
            densest_window: None,
        }
    }
}

/// The smallest sample the statistic has any power on. Below it the check says
/// so instead of returning a figure nobody should act on.
const MINIMUM_SAMPLE: usize = 5;

/// Run the check.
pub fn check(alignment: &Alignment) -> DistributionCheck {
    if let Some(reason) = &alignment.failure {
        return DistributionCheck::empty(
            CheckVerdict::Indeterminate {
                reason: format!(
                    "the marked document could not be paired with its cover: {reason}"
                ),
            },
            alignment.cover_len,
        );
    }

    let positions = alignment.mark_positions();
    let n = alignment.cover_len;
    let k = positions.len();

    if k == 0 {
        // Nothing was placed, so nothing is concentrated.
        return DistributionCheck::empty(CheckVerdict::Clean, n);
    }
    if n == 0 {
        return DistributionCheck::empty(
            CheckVerdict::Indeterminate {
                reason: "the cover holds no positions to distribute marks over".into(),
            },
            n,
        );
    }
    if k < MINIMUM_SAMPLE {
        return DistributionCheck::empty(
            CheckVerdict::Indeterminate {
                reason: format!(
                    "{k} marks is below the {MINIMUM_SAMPLE} the uniformity statistic needs \
                     to have any power, so no uniformity claim is made"
                ),
            },
            n,
        );
    }

    let n_f = n as f64;
    let k_f = k as f64;
    let uniform_gap = n_f / k_f;

    // Kolmogorov-Smirnov against the uniform distribution over 0..n.
    let mut d_plus: f64 = 0.0;
    let mut d_minus: f64 = 0.0;
    for (i, &x) in positions.iter().enumerate() {
        let rank = (i + 1) as f64;
        let empirical = (x as f64 + 1.0) / n_f;
        d_plus = d_plus.max(rank / k_f - empirical);
        d_minus = d_minus.max(empirical - i as f64 / k_f);
    }
    let ks_statistic = d_plus.max(d_minus).max(0.0);
    let ks_critical_5pct = 1.36 / k_f.sqrt();
    let uniform_at_5pct = ks_statistic <= ks_critical_5pct;

    // Inter-mark gaps.
    let gaps: Vec<f64> = positions
        .windows(2)
        .map(|pair| (pair[1] - pair[0]) as f64)
        .collect();
    let (gap_mean, gap_stddev, mean_absolute_gap_deviation) = if gaps.is_empty() {
        (0.0, 0.0, 0.0)
    } else {
        let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
        let variance = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
        let absolute =
            gaps.iter().map(|g| (g - uniform_gap).abs()).sum::<f64>() / gaps.len() as f64;
        (mean, variance.sqrt(), absolute / uniform_gap)
    };
    let gap_coefficient_of_variation = if gap_mean > 0.0 {
        gap_stddev / gap_mean
    } else {
        0.0
    };

    // The widest run of positions carrying nothing, leading and trailing runs
    // included: a payload written into the head leaves its evidence in the
    // trailing run and nowhere else.
    let mut largest_gap = LargestGap {
        positions: positions[0],
        starts_at: 0,
    };
    for pair in positions.windows(2) {
        // Two marks can share a cover index: a carrier that overflows past the
        // end of the cover stacks its tail on the last one, and a cover that
        // already carried a control takes an insertion beside it. The run
        // between them is zero, not negative.
        let run = (pair[1] - pair[0]).saturating_sub(1);
        if run > largest_gap.positions {
            largest_gap = LargestGap {
                positions: run,
                starts_at: pair[0] + 1,
            };
        }
    }
    let trailing = n.saturating_sub(positions[k - 1] + 1);
    if trailing > largest_gap.positions {
        largest_gap = LargestGap {
            positions: trailing,
            starts_at: positions[k - 1] + 1,
        };
    }

    let window = (n / 10).max(32).min(n);
    let expected = k_f * window as f64 / n_f;
    let mut densest: Option<DenseWindow> = None;
    for (i, &start) in positions.iter().enumerate() {
        let end = start + window;
        let count = positions[i..].iter().take_while(|&&x| x < end).count();
        if densest.as_ref().map(|d| count > d.marks).unwrap_or(true) {
            densest = Some(DenseWindow {
                start,
                end: end.min(n),
                marks: count,
                expected,
            });
        }
    }
    // A window no denser than uniform placement predicts is not a finding.
    let densest_window = densest.filter(|d| d.marks as f64 > expected * 1.5);

    let verdict = if uniform_at_5pct {
        CheckVerdict::Clean
    } else if ks_statistic >= 0.5 {
        CheckVerdict::Conspicuous
    } else {
        CheckVerdict::Degraded
    };

    DistributionCheck {
        verdict,
        marks: k,
        cover_positions: n,
        uniform_gap,
        gap_mean,
        gap_stddev,
        gap_coefficient_of_variation,
        mean_absolute_gap_deviation,
        ks_statistic,
        ks_critical_5pct,
        uniform_at_5pct,
        largest_gap,
        densest_window,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marked_with(cover_len: usize, positions: &[usize]) -> DistributionCheck {
        let cover: Vec<char> = std::iter::repeat('a').take(cover_len).collect();
        let mut marked = Vec::with_capacity(cover_len + positions.len());
        for (index, &c) in cover.iter().enumerate() {
            if positions.contains(&index) {
                marked.push('\u{200C}');
            }
            marked.push(c);
        }
        let alignment = Alignment::of(&cover, &marked);
        assert!(alignment.failure.is_none());
        check(&alignment)
    }

    #[test]
    fn nothing_placed_is_nothing_concentrated() {
        let report = marked_with(100, &[]);
        assert_eq!(report.verdict, CheckVerdict::Clean);
        assert_eq!(report.marks, 0);
    }

    #[test]
    fn a_sample_too_small_to_judge_says_so_rather_than_passing() {
        let report = marked_with(1000, &[10, 20, 30]);
        match report.verdict {
            CheckVerdict::Indeterminate { reason } => {
                assert!(reason.contains("power"), "reason was: {reason}");
            }
            other => panic!("expected a refusal on three marks, got {other:?}"),
        }
    }

    #[test]
    fn marks_packed_into_the_head_fail_the_test() {
        let positions: Vec<usize> = (0..100).collect();
        let report = marked_with(1100, &positions);

        assert!(report.ks_statistic > report.ks_critical_5pct);
        assert!(!report.uniform_at_5pct);
        assert_eq!(report.verdict, CheckVerdict::Conspicuous);
        let window = report.densest_window.expect("a dense window must be named");
        assert_eq!(window.start, 0);
        assert!(window.marks as f64 > window.expected * 5.0);
    }

    /// The gap figures alone would call the head-packed case flawless, since
    /// every gap in it is exactly one position wide. This pins the reason both
    /// statistics are reported.
    #[test]
    fn regular_gaps_do_not_mean_even_distribution() {
        let positions: Vec<usize> = (0..100).collect();
        let report = marked_with(1100, &positions);

        assert_eq!(
            report.gap_coefficient_of_variation, 0.0,
            "the gaps are perfectly regular"
        );
        assert!(
            report.mean_absolute_gap_deviation > 0.5,
            "and still nothing like the uniform spacing of {}",
            report.uniform_gap
        );
        assert!(!report.uniform_at_5pct);
    }

    #[test]
    fn evenly_spread_marks_pass_the_test() {
        let positions: Vec<usize> = (0..100).map(|i| i * 11 + 5).collect();
        let report = marked_with(1100, &positions);

        assert!(report.uniform_at_5pct, "ks was {}", report.ks_statistic);
        assert_eq!(report.verdict, CheckVerdict::Clean);
        assert_eq!(report.analyst_risk(), 0.0);
        assert!(report.densest_window.is_none());
    }

    /// Marks stacked on one position are a real case, not a malformed input:
    /// the zero-width carrier appends its overflow past the end of the cover,
    /// so every character of that tail shares one cover index.
    #[test]
    fn marks_stacked_on_a_single_position_do_not_break_the_gap_figures() {
        let cover: Vec<char> = "abcdef".chars().collect();
        let mut marked = cover.clone();
        for _ in 0..12 {
            marked.push('\u{200C}');
        }
        let alignment = Alignment::of(&cover, &marked);
        assert!(alignment.failure.is_none());

        let report = check(&alignment);
        assert_eq!(report.marks, 12);
        assert_eq!(report.gap_mean, 0.0, "every mark shares one position");
        assert!(!report.uniform_at_5pct, "a tail is as concentrated as it gets");
    }

    #[test]
    fn the_largest_empty_run_is_located() {
        let positions: Vec<usize> = (0..20).map(|i| i * 2).collect();
        let report = marked_with(1000, &positions);
        assert_eq!(report.largest_gap.starts_at, 39);
        assert!(report.largest_gap.positions > 900);
    }

    #[test]
    fn the_check_refuses_when_the_documents_cannot_be_paired() {
        let cover: Vec<char> = "the quick brown fox".chars().collect();
        let marked: Vec<char> = "something else entirely".chars().collect();
        let report = check(&Alignment::of(&cover, &marked));
        assert!(matches!(report.verdict, CheckVerdict::Indeterminate { .. }));
    }
}
