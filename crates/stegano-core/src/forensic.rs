//! Forensic Detector, comprehensive text analysis for steganographic artifacts.
//!
//! This is the free "product leader" of SteganoHero: anyone can analyze text
//! for hidden content, Unicode anomalies, and statistical indicators.
//! Revenue comes from the paid modules that CREATE the artifacts.
//!
//! The detector is method-agnostic: it doesn't need to know which specific
//! steganography tool was used. It detects the fingerprints.

use std::collections::HashMap;

use crate::format::{self, PositionChannel};
use crate::metrics;
use crate::stego::{Bidi, Homoglyph, WhitespaceVar, ZeroWidth};
use crate::traits::StegoMethod;

// ─── Forensic Report ────────────────────────────────────────

/// Complete forensic analysis report for a text sample.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ForensicReport {
    /// Summary verdict.
    pub verdict: Verdict,
    /// Overall suspicion score (0.0 = clean, 1.0 = certainly modified).
    pub suspicion_score: f64,
    /// Detected steganographic method signatures.
    pub stego_signatures: Vec<StegoSignature>,
    /// Unicode anomaly analysis.
    pub unicode_analysis: UnicodeAnalysis,
    /// Statistical analysis.
    pub statistics: TextStatistics,
    /// Human-readable summary lines.
    pub summary: Vec<String>,
}

/// High-level verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Verdict {
    /// No steganographic artifacts detected.
    Clean,
    /// Some anomalies found, but could be legitimate.
    Suspicious,
    /// Strong evidence of steganographic modification.
    Modified,
    /// Steganographic content confirmed (decodable).
    Confirmed,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Clean => write!(f, "CLEAN"),
            Verdict::Suspicious => write!(f, "SUSPICIOUS"),
            Verdict::Modified => write!(f, "MODIFIED"),
            Verdict::Confirmed => write!(f, "CONFIRMED"),
        }
    }
}

/// Detected steganographic method signature.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StegoSignature {
    /// Method identifier.
    pub method: String,
    /// Human-readable method name.
    pub name: String,
    /// Detection confidence (0.0–1.0).
    pub confidence: f64,
    /// Can we actually decode data from this?
    pub decodable: bool,
    /// Estimated hidden payload size in bytes (if decodable).
    pub estimated_payload_bytes: Option<usize>,
    /// Description of what was found.
    pub detail: String,
}

/// Unicode anomaly analysis.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UnicodeAnalysis {
    /// Total character count.
    pub total_chars: usize,
    /// Visible character count.
    pub visible_chars: usize,
    /// Invisible/zero-width character count.
    pub invisible_chars: usize,
    /// Breakdown by invisible character type.
    pub invisible_breakdown: HashMap<String, usize>,
    /// Mixed script detection (e.g., Latin + Cyrillic).
    pub mixed_scripts: Vec<ScriptMix>,
    /// Bidirectional control characters found.
    pub bidi_controls: usize,
    /// Word joiners and invisible math operators found (a subset of the
    /// invisible characters, surfaced as their own count).
    pub word_joiners: usize,
    /// Unusual Unicode categories found.
    pub unusual_categories: Vec<UnusualChar>,
}

/// A detected script mixing pattern.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScriptMix {
    /// Primary script (most frequent).
    pub primary: String,
    /// Secondary script detected.
    pub secondary: String,
    /// Number of secondary-script characters.
    pub secondary_count: usize,
    /// Suspicion level: "homoglyph" if lookalikes detected.
    pub pattern: String,
}

/// An unusual character found in the text.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UnusualChar {
    /// The character.
    pub character: String,
    /// Unicode codepoint (e.g., "U+200B").
    pub codepoint: String,
    /// Unicode name or category.
    pub category: String,
    /// Number of occurrences.
    pub count: usize,
}

/// Statistical text analysis.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TextStatistics {
    /// Shannon entropy (bits per character).
    pub shannon_entropy: f64,
    /// Noise density (invisible chars / total).
    pub noise_density: f64,
    /// Homoglyph density (Cyrillic lookalikes / total).
    pub homoglyph_density: f64,
    /// Entropy classification.
    pub entropy_assessment: String,
}

// ─── Analysis Engine ────────────────────────────────────────

/// Run a full forensic analysis on the given text.
pub fn analyze(text: &str) -> ForensicReport {
    let unicode_analysis = analyze_unicode(text);
    let statistics = analyze_statistics(text);
    let stego_signatures = detect_stego_methods(text);

    let suspicion_score = compute_suspicion_score(&unicode_analysis, &statistics, &stego_signatures);
    let verdict = score_to_verdict(suspicion_score, &stego_signatures);
    let summary = build_summary(&verdict, &unicode_analysis, &statistics, &stego_signatures);

    ForensicReport {
        verdict,
        suspicion_score,
        stego_signatures,
        unicode_analysis,
        statistics,
        summary,
    }
}

// ─── Method Detection ───────────────────────────────────────

/// A carrier's honest report on a text.
///
/// Backlog F16. Every one of these four blocks used to read
/// `carrier.decode(text).is_ok()` as proof of a payload, and a carrier's
/// decode returned Ok on any text that merely held its codepoints. On
/// monolingual Russian that made the detector claim a decodable 22-byte
/// homoglyph payload at full confidence, in a document every other command in
/// the tool called unmarked.
///
/// Nothing here decides that any more. The carriers now attribute their own
/// alphabet before they read it (`stego/recognition.rs`), so `decode` refuses
/// on a text it did not mark and `detect` scores only what it can attribute.
/// This function reports what they say, and adds the one piece of evidence
/// that outranks both: whether the document states its own structure.
fn signature_for<C>(carrier: &C, text: &str, detail_prefix: &str) -> Option<StegoSignature>
where
    C: StegoMethod + PositionChannel,
{
    let confidence = carrier.detect(text);
    if confidence <= 0.0 {
        return None;
    }

    let payload_size = carrier.decode(text).ok().map(|d| d.len());
    let decodable = payload_size.is_some();

    // A valid preamble is the strongest evidence available: a document
    // carrying one states its own format, mission and payload length. Its
    // absence is not proof of innocence, since documents written before the
    // format existed carry none, so it is reported as what it is.
    let framed = format::locate_preamble(&carrier.read_positions(text)).is_ok();

    let evidence = match (framed, decodable) {
        (true, _) => ", the document states its own structure and the payload reads back",
        (false, true) => ", payload is decodable",
        (false, false) => "",
    };

    Some(StegoSignature {
        method: carrier.id().to_string(),
        name: carrier.name().to_string(),
        confidence,
        decodable,
        estimated_payload_bytes: payload_size,
        detail: format!(
            "{detail_prefix} detected with {:.0}% confidence{evidence}",
            confidence * 100.0
        ),
    })
}

fn detect_stego_methods(text: &str) -> Vec<StegoSignature> {
    let mut signatures = Vec::new();

    if let Some(sig) = signature_for(
        &ZeroWidth::new(),
        text,
        "Zero-width characters (ZWSP/ZWNJ)",
    ) {
        signatures.push(sig);
    }

    // Says what was found, not what the carrier is usually used for. The old
    // wording asserted "in Latin text" on a document holding no Latin.
    if let Some(sig) = signature_for(
        &Homoglyph::new(),
        text,
        "Cyrillic homoglyph substitutions inside Latin-script words",
    ) {
        signatures.push(sig);
    }

    if let Some(sig) = signature_for(
        &Bidi::new(),
        text,
        "Bidirectional control characters (LRM/RLM)",
    ) {
        signatures.push(sig);
    }

    if let Some(sig) = signature_for(
        &WhitespaceVar::new(),
        text,
        "Whitespace variation characters (WJ/ZWNBSP)",
    ) {
        signatures.push(sig);
    }

    signatures
}

fn count_bidi_controls(text: &str) -> usize {
    text.chars()
        .filter(|c| matches!(c,
            '\u{202A}' | '\u{202B}' | '\u{202C}' | '\u{202D}' | '\u{202E}'
            | '\u{200E}' | '\u{200F}'
            | '\u{2066}' | '\u{2067}' | '\u{2068}' | '\u{2069}'
        ))
        .count()
}

fn count_word_joiners(text: &str) -> usize {
    text.chars()
        .filter(|c| matches!(c,
            '\u{2060}' | '\u{FEFF}' | '\u{2061}' | '\u{2062}' | '\u{2063}' | '\u{2064}'
        ))
        .count()
}

// ─── Unicode Analysis ───────────────────────────────────────

fn analyze_unicode(text: &str) -> UnicodeAnalysis {
    let mut total_chars = 0usize;
    let mut visible_chars = 0usize;
    let mut invisible_chars = 0usize;
    let mut invisible_breakdown: HashMap<String, usize> = HashMap::new();
    let mut unusual_chars: HashMap<char, usize> = HashMap::new();

    // Script counting
    let mut latin_count = 0usize;
    let mut cyrillic_count = 0usize;

    for c in text.chars() {
        total_chars += 1;

        if is_invisible(c) {
            invisible_chars += 1;
            let name = invisible_char_name(c);
            *invisible_breakdown.entry(name).or_default() += 1;
        } else {
            visible_chars += 1;
        }

        if is_unusual(c) {
            *unusual_chars.entry(c).or_default() += 1;
        }

        // Script detection
        if is_latin(c) {
            latin_count += 1;
        } else if is_cyrillic(c) {
            cyrillic_count += 1;
        }
    }

    // Mixed script analysis
    let mut mixed_scripts = Vec::new();
    if latin_count > 0 && cyrillic_count > 0 {
        let (primary, secondary, sec_count) = if latin_count >= cyrillic_count {
            ("Latin", "Cyrillic", cyrillic_count)
        } else {
            ("Cyrillic", "Latin", latin_count)
        };

        let pattern = if metrics::homoglyph_density(text) > 0.0 {
            "homoglyph_substitution"
        } else {
            "mixed_content"
        };

        mixed_scripts.push(ScriptMix {
            primary: primary.to_string(),
            secondary: secondary.to_string(),
            secondary_count: sec_count,
            pattern: pattern.to_string(),
        });
    }

    // Unusual characters list
    let unusual_categories: Vec<UnusualChar> = unusual_chars
        .into_iter()
        .map(|(c, count)| UnusualChar {
            character: if is_invisible(c) {
                format!("(invisible)")
            } else {
                c.to_string()
            },
            codepoint: format!("U+{:04X}", c as u32),
            category: unicode_category_name(c),
            count,
        })
        .collect();

    // Bidi controls and word joiners are counted by their own named helpers, so
    // the two functions are the single source of truth for those signals.
    let bidi_controls = count_bidi_controls(text);
    let word_joiners = count_word_joiners(text);

    UnicodeAnalysis {
        total_chars,
        visible_chars,
        invisible_chars,
        invisible_breakdown,
        mixed_scripts,
        bidi_controls,
        word_joiners,
        unusual_categories,
    }
}

// ─── Statistics ──────────────────────────────────────────────

fn analyze_statistics(text: &str) -> TextStatistics {
    let entropy = metrics::shannon_entropy(text);
    let noise = metrics::noise_density(text);
    let homoglyph = metrics::homoglyph_density(text);

    let entropy_assessment = if text.is_empty() {
        "empty text".to_string()
    } else if entropy < 2.0 {
        "very low entropy, repetitive or simple text".to_string()
    } else if entropy < 4.0 {
        "normal for natural language text".to_string()
    } else if entropy < 5.0 {
        "slightly elevated, may contain embedded data".to_string()
    } else if entropy < 6.5 {
        "elevated, likely contains non-text data or steganographic payload".to_string()
    } else {
        "very high, strongly suggests embedded binary or encrypted data".to_string()
    };

    TextStatistics {
        shannon_entropy: entropy,
        noise_density: noise,
        homoglyph_density: homoglyph,
        entropy_assessment,
    }
}

// ─── Scoring ────────────────────────────────────────────────

fn compute_suspicion_score(
    unicode: &UnicodeAnalysis,
    stats: &TextStatistics,
    signatures: &[StegoSignature],
) -> f64 {
    let mut score = 0.0;

    // Method detections are the strongest signal
    for sig in signatures {
        score += sig.confidence * 0.6;
    }

    // Invisible characters
    if unicode.invisible_chars > 0 {
        let invisible_ratio = unicode.invisible_chars as f64 / unicode.total_chars.max(1) as f64;
        score += invisible_ratio.min(0.3) * 0.5;
    }

    // Mixed scripts (especially homoglyph patterns)
    for mix in &unicode.mixed_scripts {
        if mix.pattern == "homoglyph_substitution" {
            score += 0.3;
        } else {
            score += 0.1;
        }
    }

    // Statistical anomalies
    if stats.noise_density > 0.01 {
        score += 0.1;
    }
    if stats.homoglyph_density > 0.01 {
        score += 0.1;
    }

    // Bidi controls in normal text
    if unicode.bidi_controls > 0 {
        score += 0.15;
    }

    score.min(1.0)
}

fn score_to_verdict(score: f64, signatures: &[StegoSignature]) -> Verdict {
    // If any method is decodable, it's confirmed
    if signatures.iter().any(|s| s.decodable) {
        return Verdict::Confirmed;
    }

    if score >= 0.7 {
        Verdict::Modified
    } else if score >= 0.3 {
        Verdict::Suspicious
    } else {
        Verdict::Clean
    }
}

// ─── Summary Builder ────────────────────────────────────────

fn build_summary(
    verdict: &Verdict,
    unicode: &UnicodeAnalysis,
    stats: &TextStatistics,
    signatures: &[StegoSignature],
) -> Vec<String> {
    let mut lines = Vec::new();

    lines.push(format!("Verdict: {verdict}"));
    lines.push(format!(
        "Text: {} total chars ({} visible, {} invisible)",
        unicode.total_chars, unicode.visible_chars, unicode.invisible_chars
    ));

    if !signatures.is_empty() {
        lines.push("Detected methods:".to_string());
        for sig in signatures {
            let decode_status = if sig.decodable {
                match sig.estimated_payload_bytes {
                    Some(n) => format!(", decodable ({n} bytes)"),
                    None => ", decodable".to_string(),
                }
            } else {
                String::new()
            };
            lines.push(format!(
                "  - {} ({:.0}% confidence{})",
                sig.name,
                sig.confidence * 100.0,
                decode_status,
            ));
        }
    }

    if !unicode.mixed_scripts.is_empty() {
        for mix in &unicode.mixed_scripts {
            lines.push(format!(
                "Script mixing: {} + {} ({} chars, pattern: {})",
                mix.primary, mix.secondary, mix.secondary_count, mix.pattern
            ));
        }
    }

    if unicode.bidi_controls > 0 {
        lines.push(format!(
            "Bidirectional controls: {} found",
            unicode.bidi_controls
        ));
    }

    lines.push(format!(
        "Entropy: {:.3} bits/char, {}",
        stats.shannon_entropy, stats.entropy_assessment
    ));

    lines
}

// ─── Unicode Helpers ────────────────────────────────────────

fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}' | '\u{200C}' | '\u{200D}'
        | '\u{200E}' | '\u{200F}'
        | '\u{202A}' | '\u{202B}' | '\u{202C}' | '\u{202D}' | '\u{202E}'
        | '\u{2060}' | '\u{2061}' | '\u{2062}' | '\u{2063}' | '\u{2064}'
        | '\u{2066}' | '\u{2067}' | '\u{2068}' | '\u{2069}'
        | '\u{FEFF}'
        | '\u{00AD}'
        | '\u{034F}' // combining grapheme joiner
        | '\u{061C}' // arabic letter mark
        | '\u{180E}' // mongolian vowel separator
    )
}

/// Remove every invisible / format-control character this module flags (the
/// exact set [`is_invisible`] recognises), returning the cleaned text and the
/// count removed. This is the pristine strip: it takes out even the invisibles
/// no cleanable mark class owns (soft hyphen, a lone ZWJ, and the like), which
/// the conservative clean deliberately leaves because they can be
/// meaning-bearing. Used by the declared, opt-in pristine clean.
pub fn strip_invisibles(text: &str) -> (String, usize) {
    let mut removed = 0usize;
    let cleaned: String = text
        .chars()
        .filter(|&c| {
            let keep = !is_invisible(c);
            if !keep {
                removed += 1;
            }
            keep
        })
        .collect();
    (cleaned, removed)
}

fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{200E}' | '\u{200F}'
        | '\u{202A}' | '\u{202B}' | '\u{202C}' | '\u{202D}' | '\u{202E}'
        | '\u{2066}' | '\u{2067}' | '\u{2068}' | '\u{2069}'
    )
}

fn is_unusual(c: char) -> bool {
    is_invisible(c) || is_bidi_control(c)
}

fn is_latin(c: char) -> bool {
    matches!(c, 'A'..='Z' | 'a'..='z')
}

fn is_cyrillic(c: char) -> bool {
    matches!(c as u32, 0x0400..=0x04FF | 0x0500..=0x052F)
}

fn invisible_char_name(c: char) -> String {
    match c {
        '\u{200B}' => "ZWSP (Zero Width Space)".into(),
        '\u{200C}' => "ZWNJ (Zero Width Non-Joiner)".into(),
        '\u{200D}' => "ZWJ (Zero Width Joiner)".into(),
        '\u{200E}' => "LRM (Left-to-Right Mark)".into(),
        '\u{200F}' => "RLM (Right-to-Left Mark)".into(),
        '\u{202A}' => "LRE (Left-to-Right Embedding)".into(),
        '\u{202B}' => "RLE (Right-to-Left Embedding)".into(),
        '\u{202C}' => "PDF (Pop Directional Formatting)".into(),
        '\u{202D}' => "LRO (Left-to-Right Override)".into(),
        '\u{202E}' => "RLO (Right-to-Left Override)".into(),
        '\u{2060}' => "WJ (Word Joiner)".into(),
        '\u{2061}' => "Function Application".into(),
        '\u{2062}' => "Invisible Times".into(),
        '\u{2063}' => "Invisible Separator".into(),
        '\u{2064}' => "Invisible Plus".into(),
        '\u{2066}' => "LRI (Left-to-Right Isolate)".into(),
        '\u{2067}' => "RLI (Right-to-Left Isolate)".into(),
        '\u{2068}' => "FSI (First Strong Isolate)".into(),
        '\u{2069}' => "PDI (Pop Directional Isolate)".into(),
        '\u{FEFF}' => "BOM/ZWNBSP (Zero Width No-Break Space)".into(),
        '\u{00AD}' => "SHY (Soft Hyphen)".into(),
        '\u{034F}' => "CGJ (Combining Grapheme Joiner)".into(),
        '\u{061C}' => "ALM (Arabic Letter Mark)".into(),
        '\u{180E}' => "MVS (Mongolian Vowel Separator)".into(),
        _ => format!("U+{:04X}", c as u32),
    }
}

fn unicode_category_name(c: char) -> String {
    if is_invisible(c) {
        "invisible/formatting".to_string()
    } else if is_bidi_control(c) {
        "bidirectional control".to_string()
    } else if is_cyrillic(c) {
        "Cyrillic".to_string()
    } else {
        "other".to_string()
    }
}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stego::ZeroWidth;

    const CYRILLIC_RUSSIAN: &str = include_str!("../../../tests/corpus/cyrillic_russian.txt");
    const EN_LONG_ARTICLE: &str = include_str!("../../../tests/corpus/en_long_article.txt");
    const ALREADY_CARRYING: &str = include_str!("../../../tests/corpus/already_carrying.txt");

    // ─── Attribution: an alphabet is not a payload ───

    /// Backlog F16, the headline. Monolingual Russian that has never been
    /// touched was reported as Confirmed, with a decodable 22-byte homoglyph
    /// signature at full confidence and a detail line about Latin text in a
    /// document holding no Latin, while every other command in the tool said
    /// the carrier could not operate on it at all.
    #[test]
    fn an_unmarked_cyrillic_document_is_clean() {
        let report = analyze(CYRILLIC_RUSSIAN);

        assert_eq!(
            report.verdict,
            Verdict::Clean,
            "summary was: {:?}",
            report.summary
        );
        assert!(
            report.stego_signatures.is_empty(),
            "signatures were: {:?}",
            report
                .stego_signatures
                .iter()
                .map(|s| (&s.method, s.confidence, s.decodable))
                .collect::<Vec<_>>()
        );
        assert_eq!(report.statistics.homoglyph_density, 0.0);
    }

    /// The other direction of F16, and the one that matters commercially: a
    /// document this tool actually marked is still confirmed, with the payload
    /// it holds.
    #[test]
    fn a_marked_latin_document_is_still_confirmed() {
        let hg = Homoglyph::new();
        let marked = hg.encode(EN_LONG_ARTICLE, b"provenance").unwrap();

        let report = analyze(&marked);
        assert_eq!(report.verdict, Verdict::Confirmed);

        let signature = report
            .stego_signatures
            .iter()
            .find(|s| s.method == "homoglyph")
            .expect("the marked document must show a homoglyph signature");
        assert!(signature.decodable, "detail was: {}", signature.detail);
        assert!(signature.confidence > 0.0);
    }

    /// Backlog F13b. `already_carrying.txt` holds one character of each
    /// carrier's alphabet and nothing else. Stray characters are an anomaly
    /// worth reporting, and they are not a payload.
    #[test]
    fn a_document_holding_stray_channel_characters_reports_no_payload() {
        let report = analyze(ALREADY_CARRYING);

        for signature in &report.stego_signatures {
            assert!(
                !signature.decodable,
                "{} claimed a decodable payload: {}",
                signature.method, signature.detail
            );
            assert_eq!(
                signature.estimated_payload_bytes, None,
                "{} sized a payload that is not there",
                signature.method
            );
        }
        assert_ne!(report.verdict, Verdict::Confirmed);
        // The characters are still an anomaly, and the report still says so.
        assert_ne!(report.verdict, Verdict::Clean);
    }

    /// The detail line described a script mix that the document does not have.
    /// It states what was found, not what the carrier is usually used for.
    #[test]
    fn a_signature_detail_does_not_describe_a_script_the_document_lacks() {
        let hg = Homoglyph::new();
        let marked = hg.encode(EN_LONG_ARTICLE, b"provenance").unwrap();
        let report = analyze(&marked);

        let signature = report
            .stego_signatures
            .iter()
            .find(|s| s.method == "homoglyph")
            .expect("signature");
        assert!(
            !signature.detail.contains('\u{2014}'),
            "no em dash reaches user-facing output: {}",
            signature.detail
        );
    }

    #[test]
    fn clean_text_is_clean() {
        let report = analyze("The quick brown fox jumps over the lazy dog.");
        assert_eq!(report.verdict, Verdict::Clean);
        assert!(report.suspicion_score < 0.1);
        assert!(report.stego_signatures.is_empty());
        assert_eq!(report.unicode_analysis.invisible_chars, 0);
    }

    #[test]
    fn detects_zero_width_stego() {
        let zw = ZeroWidth::new();
        let cover = "A sufficiently long cover text with enough room for hidden data inside";
        let stego = zw.encode(cover, b"secret").unwrap();

        let report = analyze(&stego);
        assert!(report.suspicion_score > 0.3);
        assert!(matches!(report.verdict, Verdict::Confirmed | Verdict::Modified));

        let zw_sig = report.stego_signatures.iter().find(|s| s.method == "zero_width");
        assert!(zw_sig.is_some(), "should detect zero_width method");
        assert!(zw_sig.unwrap().decodable, "should be decodable");
        assert!(report.unicode_analysis.invisible_chars > 0);
    }

    #[test]
    fn detects_homoglyph_stego() {
        let hg = Homoglyph::new();
        let cover = "The secret operation code was activated yesterday evening at base";
        let stego = hg.encode(cover, b"\x0F").unwrap();

        let report = analyze(&stego);
        assert!(report.suspicion_score > 0.2);

        let hg_sig = report.stego_signatures.iter().find(|s| s.method == "homoglyph");
        assert!(hg_sig.is_some(), "should detect homoglyph method");
        assert!(!report.unicode_analysis.mixed_scripts.is_empty());
    }

    #[test]
    fn detects_bidi_controls() {
        let text = "Hello \u{200E}world\u{200F} test \u{200E}text\u{200F}here\u{202C}now";
        let report = analyze(text);

        assert!(report.unicode_analysis.bidi_controls > 0);
        let bidi_sig = report.stego_signatures.iter().find(|s| s.method == "bidi");
        assert!(bidi_sig.is_some(), "should detect bidi method, got: {:?}",
            report.stego_signatures.iter().map(|s| &s.method).collect::<Vec<_>>());
    }

    #[test]
    fn counts_word_joiners() {
        // The word joiners and invisible math operators are surfaced as their
        // own count by the wired-in helper.
        let report = analyze("a\u{2060}b\u{FEFF}c\u{2063}d");
        assert!(report.unicode_analysis.word_joiners >= 3);
    }

    #[test]
    fn detects_whitespace_variation() {
        let text = "Hello\u{2060}world\u{FEFF}test\u{2063}here\u{2060}now";
        let report = analyze(text);

        let ws_sig = report.stego_signatures.iter().find(|s| s.method == "whitespace_var");
        assert!(ws_sig.is_some(), "should detect whitespace_var method, got: {:?}",
            report.stego_signatures.iter().map(|s| &s.method).collect::<Vec<_>>());
    }

    #[test]
    fn mixed_scripts_detected() {
        // Mix Latin 'a' with Cyrillic 'а' (U+0430)
        let text = "Hello w\u{043E}rld";
        let report = analyze(text);

        assert!(!report.unicode_analysis.mixed_scripts.is_empty());
        assert_eq!(report.unicode_analysis.mixed_scripts[0].pattern, "homoglyph_substitution");
    }

    #[test]
    fn statistics_are_reasonable() {
        let text = "The quick brown fox jumps over the lazy dog. This is a normal English sentence.";
        let report = analyze(text);

        assert!(report.statistics.shannon_entropy > 3.0);
        assert!(report.statistics.shannon_entropy < 5.0);
        assert_eq!(report.statistics.noise_density, 0.0);
        assert_eq!(report.statistics.homoglyph_density, 0.0);
    }

    #[test]
    fn empty_text_handled() {
        let report = analyze("");
        assert_eq!(report.verdict, Verdict::Clean);
        assert_eq!(report.suspicion_score, 0.0);
    }

    #[test]
    fn summary_contains_verdict() {
        let report = analyze("Normal text here.");
        assert!(report.summary[0].contains("CLEAN"));
    }

    #[test]
    fn confirmed_when_decodable() {
        let zw = ZeroWidth::new();
        let cover = "This text is long enough to hide some secret data inside of it easily";
        let stego = zw.encode(cover, b"test").unwrap();

        let report = analyze(&stego);
        assert_eq!(report.verdict, Verdict::Confirmed);
    }
}
