//! A minimal, self-contained native PDF writer for the export path.
//!
//! This is NOT the browser-backed PDF tier (`pdf.rs`): it needs no external
//! process and no bundled font. It writes a valid PDF by hand using the standard
//! base-14 Helvetica font, which every conformant reader already carries, so the
//! output is fully self-contained and offline (the embed-everything invariant).
//!
//! ## Honest contract
//!
//! A PDF is a RENDERING, not a byte-faithful container. Two limits follow and are
//! stated rather than hidden (invariant 2):
//!
//! - The hidden layer of a marked text does NOT survive. Zero-width characters and
//!   whitespace-variation carriers are not rendered glyphs, so a PDF made from a
//!   marked cover is no longer decodable. PDF is therefore an export target for
//!   readable content and reports, never a way to carry a mark. Plain text and
//!   Markdown remain the byte-faithful, mark-preserving export choices.
//! - The base-14 Helvetica font covers Latin-1. A character outside it is replaced
//!   by `?` rather than dropped silently, so a reader can see that a substitution
//!   happened.
//!
//! The layout is deliberately plain: left-aligned Helvetica, soft-wrapped to the
//! page width and paginated, which is all a text result or a report needs.

/// A4 page width in PostScript points.
const PAGE_W: i32 = 595;
/// A4 page height in PostScript points.
const PAGE_H: i32 = 842;
/// Margin on every side, in points.
const MARGIN: i32 = 54;
/// Font size in points.
const FONT_SIZE: i32 = 11;
/// Baseline-to-baseline distance in points.
const LINE_HEIGHT: i32 = 15;
/// Soft-wrap width in characters. An approximation of the page width at this font
/// size (Helvetica 11pt averages ~5.5pt per character over the ~487pt text
/// column), good enough for a left-aligned text block.
const WRAP_COLS: usize = 88;

/// Render a text result to a self-contained PDF. See the module doc for the
/// contract: readable content only, Latin-1, never a carrier for a hidden layer.
pub fn text_to_pdf(text: &str) -> Vec<u8> {
    let lines = wrap_lines(text);
    let usable_height = PAGE_H - 2 * MARGIN;
    let lines_per_page = (usable_height / LINE_HEIGHT).max(1) as usize;
    let pages: Vec<&[String]> = if lines.is_empty() {
        // Always emit at least one (empty) page, so the file is a valid document
        // rather than a header with no pages.
        vec![&[][..]]
    } else {
        lines.chunks(lines_per_page).collect()
    };

    // Object ids: 1 = Catalog, 2 = Pages, 3 = Font, then per page a Page object and
    // a Contents object.
    let font_id = 3;
    let first_page_id = 4;
    let page_ids: Vec<usize> = (0..pages.len()).map(|i| first_page_id + i * 2).collect();
    let content_ids: Vec<usize> = (0..pages.len()).map(|i| first_page_id + i * 2 + 1).collect();
    let total_objects = 3 + pages.len() * 2;

    let mut out: Vec<u8> = Vec::new();
    // Byte offset of each object, indexed by object id (1-based; index 0 unused).
    let mut offsets: Vec<usize> = vec![0; total_objects + 1];

    out.extend_from_slice(b"%PDF-1.4\n");
    // A binary-marker comment, so tools treat the file as binary.
    out.extend_from_slice(b"%\xE2\xE3\xCF\xD3\n");

    // 1: Catalog.
    offsets[1] = out.len();
    out.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    // 2: Pages.
    offsets[2] = out.len();
    let kids = page_ids
        .iter()
        .map(|id| format!("{id} 0 R"))
        .collect::<Vec<_>>()
        .join(" ");
    out.extend_from_slice(
        format!(
            "2 0 obj\n<< /Type /Pages /Kids [{kids}] /Count {} >>\nendobj\n",
            pages.len()
        )
        .as_bytes(),
    );

    // 3: Font (base-14 Helvetica, WinAnsi).
    offsets[font_id] = out.len();
    out.extend_from_slice(
        b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n",
    );

    // Per-page Page and Contents objects.
    for (index, page_lines) in pages.iter().enumerate() {
        let page_id = page_ids[index];
        let content_id = content_ids[index];

        let stream = page_content_stream(page_lines);

        offsets[page_id] = out.len();
        out.extend_from_slice(
            format!(
                "{page_id} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>\nendobj\n"
            )
            .as_bytes(),
        );

        offsets[content_id] = out.len();
        out.extend_from_slice(
            format!("{content_id} 0 obj\n<< /Length {} >>\nstream\n", stream.len()).as_bytes(),
        );
        out.extend_from_slice(stream.as_bytes());
        out.extend_from_slice(b"\nendstream\nendobj\n");
    }

    // Cross-reference table.
    let xref_offset = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", total_objects + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for id in 1..=total_objects {
        out.extend_from_slice(format!("{:010} 00000 n \n", offsets[id]).as_bytes());
    }

    // Trailer.
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n",
            total_objects + 1
        )
        .as_bytes(),
    );

    out
}

/// Build the content stream for one page: place each wrapped line with Helvetica.
fn page_content_stream(lines: &[String]) -> String {
    let mut stream = String::new();
    stream.push_str("BT\n");
    stream.push_str(&format!("/F1 {FONT_SIZE} Tf\n"));
    stream.push_str(&format!("{LINE_HEIGHT} TL\n"));
    // First baseline: one line-height below the top margin.
    let start_y = PAGE_H - MARGIN - FONT_SIZE;
    stream.push_str(&format!("{MARGIN} {start_y} Td\n"));
    for line in lines {
        stream.push('(');
        stream.push_str(&escape_pdf_text(line));
        stream.push_str(") Tj\nT*\n");
    }
    stream.push_str("ET");
    stream
}

/// Soft-wrap the text: split on existing newlines, then wrap each paragraph to the
/// column width without breaking words where a word fits on its own line.
fn wrap_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.split('\n') {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() {
            out.push(String::new());
            continue;
        }
        let mut current = String::new();
        for word in line.split(' ') {
            if current.is_empty() {
                current.push_str(word);
            } else if current.chars().count() + 1 + word.chars().count() <= WRAP_COLS {
                current.push(' ');
                current.push_str(word);
            } else {
                out.push(std::mem::take(&mut current));
                current.push_str(word);
            }
            // A single word longer than the column is hard-split so it cannot run
            // off the page.
            while current.chars().count() > WRAP_COLS {
                let split: String = current.chars().take(WRAP_COLS).collect();
                out.push(split);
                current = current.chars().skip(WRAP_COLS).collect();
            }
        }
        if !current.is_empty() {
            out.push(current);
        }
    }
    out
}

/// Escape a line for a PDF literal string and reduce it to the font's WinAnsi
/// range. A character outside Latin-1 becomes `?` so the substitution is visible;
/// the PDF string delimiters and the escape character are escaped.
fn escape_pdf_text(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    for c in line.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            c if (' '..='~').contains(&c) => out.push(c),
            // Latin-1 upper range renders under WinAnsi; keep it as its byte.
            c if ('\u{A0}'..='\u{FF}').contains(&c) => out.push(c),
            // Everything else (control, zero-width, non-Latin-1) is not a base-14
            // glyph: substitute visibly rather than emit an invalid byte.
            _ => out.push('?'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_a_parseable_pdf() {
        let pdf = text_to_pdf("A short report.\n\nWith a second paragraph.");
        assert!(pdf.starts_with(b"%PDF-1.4"), "carries the PDF header");
        assert!(pdf.windows(5).any(|w| w == b"%%EOF"), "carries the EOF marker");
        // The pure-Rust PDF reader the crate already ships must accept it.
        let doc = lopdf::Document::load_mem(&pdf).expect("the PDF re-parses");
        assert!(doc.get_pages().len() >= 1, "the PDF has at least one page");
    }

    #[test]
    fn long_text_paginates() {
        // Enough lines to force more than one page.
        let text = (0..400).map(|i| format!("line number {i}")).collect::<Vec<_>>().join("\n");
        let pdf = text_to_pdf(&text);
        let doc = lopdf::Document::load_mem(&pdf).expect("the PDF re-parses");
        assert!(doc.get_pages().len() >= 2, "long text spans several pages");
    }

    #[test]
    fn a_non_latin1_character_is_substituted_not_dropped() {
        // A CJK character is outside Helvetica; it must become a visible marker.
        let out = escape_pdf_text("hi \u{4e2d} there");
        assert!(out.contains('?'), "the out-of-range character is substituted: {out}");
    }

    #[test]
    fn pdf_string_delimiters_are_escaped() {
        let out = escape_pdf_text("a (parenthesis) and a \\ backslash");
        assert!(out.contains("\\(") && out.contains("\\)"), "parentheses escaped");
        assert!(out.contains("\\\\"), "backslash escaped");
    }

    #[test]
    fn an_empty_text_still_makes_a_valid_pdf() {
        let pdf = text_to_pdf("");
        let doc = lopdf::Document::load_mem(&pdf).expect("an empty document is still valid");
        assert_eq!(doc.get_pages().len(), 1, "one empty page");
    }
}
