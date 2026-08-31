//! Pure-Rust document exporters for the conversion capability (Phase C).
//!
//! CONVERSION IS SEPARATE FROM MARKING. This module regenerates a target
//! document from a Markdown waypoint. It is best-effort and DECLARED LOSSY: it
//! round-trips through Markdown, so target-specific formatting the source Markdown
//! cannot express is lost. It MUST NOT be used to place a mark: marking is the
//! surgical in-place / additive-metadata path built elsewhere ([`crate::transform`]
//! and [`crate::metadata`]), which never converts. See [`crate::convert`].
//!
//! ## Provenance
//!
//! Each writer is copied, not depended upon, from an upstream Markdown converter
//! (`crates/core/src/export_formats.rs`, and the HTML shape from `export.rs`),
//! then adapted in three ways, all documented at their site:
//!
//! 1. No file I/O. The originals wrote to a path and returned `Result<(), String>`;
//!    these build the document in memory and return `Result<Vec<u8>, String>`.
//! 2. No document metadata. Conversion flows through a Markdown waypoint that
//!    carries no title/author, so a minimal [`ConvertMeta`] is passed empty and the
//!    title/author/date preambles are skipped; the body is faithful.
//! 3. Math is carried as its LaTeX SOURCE, not rasterised or transliterated.
//!    Reproducing the upstream converter's `render::latex_to_unicode` / `export_typst::
//!    latex_to_typst_math` would drag the `render` and `latex_macros` modules
//!    (thread-local macro state, large substitution tables) into this dependency-
//!    light crate, which the copy-not-depend principle rules out. Emitting the
//!    LaTeX source unchanged is a declared-lossy best-effort rendering, not a
//!    silent failure (invariant 2): the conversion still succeeds and names its
//!    target on any real error.
//!
//! The binary-container writers (DOCX, ODT, EPUB) are deliberately NOT here: their
//! the upstream converter exporters link the Typst equation-image renderer (`equation_renderer`
//! -> `typst`, `typst-render`, `typst-svg`, `typst-assets`) and the `image` crate
//! for figure embedding, which this build excludes. They are refused by name at the
//! conversion boundary (see [`crate::convert`]); a stripped, text-only container
//! writer is a later slice. HTML uses `pulldown-cmark`'s own pure-Rust renderer
//! rather than the upstream converter's `render::markdown_to_html`, which renders math through a
//! compiled-in JS engine (`katex`/duktape, a C build dependency) this build avoids.

// Each exporter is a pulldown-cmark event-loop state machine. Several formats
// intentionally do not read some tracked state (plain TXT drops bold/italic,
// headings reset at block end), which produces benign "assigned but never read"
// lints for that state; silence them at the module level, as the source does.
#![allow(unused_assignments, unused_variables)]

use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};

/// The minimal document metadata the copied writers read. Conversion flows through
/// a Markdown waypoint that carries none of it, so it is always passed empty and
/// the title/author/date preambles are skipped. Kept as a struct (rather than
/// dropped) so the copied writers stay structurally faithful to their source.
#[derive(Debug, Clone, Default)]
pub(crate) struct ConvertMeta {
    pub title: String,
    pub author: String,
    pub timestamp: String,
    pub lang: String,
}

/// Carry a math fragment as its LaTeX source, trimmed. See the module doc, point
/// 3: a declared-lossy passthrough that keeps the source visible rather than
/// dragging the LaTeX-to-unicode / LaTeX-to-Typst engines into this crate.
fn math_source(latex: &str) -> String {
    latex.trim().to_string()
}

// ── Markdown block splitter (copied from export_formats.rs) ───────────────────
// Separates `$$ ... $$` equation blocks from prose.

enum Block<'a> {
    Text(&'a str),
    Equation(&'a str), // raw LaTeX, display delimiter ($$...$$, \[...\])
}

/// Split out ONLY display equations ($$...$$, \[...\]) from prose.
/// Inline math stays inside the Text so it renders in line within a paragraph.
fn split_display_blocks(src: &str) -> Vec<Block<'_>> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    let mut in_code = false;

    if !src.contains("$$") && !src.contains("\\[") {
        out.push(Block::Text(src));
        return out;
    }

    while cursor < src.len() {
        let rest = &src[cursor..];
        let disp: Option<(usize, &str, &str)> = {
            let dd = rest.find("$$").map(|p| (p, "$$", "$$"));
            let br = rest.find("\\[").map(|p| (p, "\\[", "\\]"));
            [dd, br].into_iter().flatten().min_by_key(|(p, _, _)| *p)
        };

        let scan_end = disp.map(|(p, _, _)| p).unwrap_or(rest.len());
        if rest[..scan_end].contains("```") {
            for line in rest[..scan_end].split_inclusive('\n') {
                if line.trim_start().starts_with("```") {
                    in_code = !in_code;
                }
            }
            if in_code {
                let end = disp
                    .map(|(p, o, _)| cursor + p + o.len())
                    .unwrap_or(src.len())
                    .min(src.len());
                out.push(Block::Text(&src[cursor..end]));
                cursor = end;
                continue;
            }
        }

        match disp {
            None => {
                out.push(Block::Text(&src[cursor..]));
                break;
            }
            Some((rel, open_pat, close_pat)) => {
                let open = cursor + rel;
                if open > cursor {
                    out.push(Block::Text(&src[cursor..open]));
                }
                let after = open + open_pat.len();
                if let Some(c) = src[after..].find(close_pat) {
                    let latex = src[after..after + c].trim();
                    if !latex.is_empty() {
                        out.push(Block::Equation(latex));
                    }
                    cursor = after + c + close_pat.len();
                } else {
                    out.push(Block::Text(&src[cursor..]));
                    break;
                }
            }
        }
    }
    out
}

// ── Escaping helpers (copied from export_formats.rs) ──────────────────────────

fn esc_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn esc_tex(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\textbackslash{}"),
            '{' => o.push_str("\\{"),
            '}' => o.push_str("\\}"),
            '$' => o.push_str("\\$"),
            '#' => o.push_str("\\#"),
            '%' => o.push_str("\\%"),
            '^' => o.push_str("\\^{}"),
            '&' => o.push_str("\\&"),
            '_' => o.push_str("\\_"),
            '~' => o.push_str("\\textasciitilde{}"),
            c => o.push(c),
        }
    }
    o
}

fn esc_rtf(s: &str) -> String {
    let mut o = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '{' => o.push_str("\\{"),
            '}' => o.push_str("\\}"),
            '\n' => o.push_str("\\line "),
            c if (c as u32) > 127 => o.push_str(&format!("\\u{}?", c as u32)),
            c => o.push(c),
        }
    }
    o
}

fn esc_typst(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('#', "\\#")
        .replace('*', "\\*")
        .replace('_', "\\_")
        .replace('`', "\\`")
        .replace('$', "\\$")
        .replace('@', "\\@")
}

/// Escape the RST inline-markup triggers in prose text.
fn esc_rst_text(s: &str) -> String {
    s.replace('*', "\\*").replace('`', "\\`").replace('|', "\\|")
}

// ── Shared table rendering for the source-text exporters ──────────────────────

enum TableStyle {
    Latex,
    Typst,
    Rst,
    Org,
    Adoc,
    Rtf,
}

fn tcell(row: &[String], i: usize) -> &str {
    row.get(i).map(|s| s.trim()).unwrap_or("")
}

fn render_table(rows: &[Vec<String>], style: TableStyle) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let ncol = rows.iter().map(|r| r.len()).max().unwrap_or(1).max(1);
    let cell = tcell;
    let mut s = String::new();
    match style {
        TableStyle::Latex => {
            s.push_str("\n\\begin{table}[h]\\centering\n\\begin{tabular}{|");
            for _ in 0..ncol {
                s.push('l');
                s.push('|');
            }
            s.push_str("}\n\\hline\n");
            for r in rows {
                let cells: Vec<&str> = (0..ncol).map(|i| cell(r, i)).collect();
                s.push_str(&cells.join(" & "));
                s.push_str(" \\\\ \\hline\n");
            }
            s.push_str("\\end{tabular}\n\\end{table}\n\n");
        }
        TableStyle::Typst => {
            s.push_str(&format!("\n#table(\n  columns: {},\n", ncol));
            for r in rows {
                let cells: Vec<String> = (0..ncol).map(|i| format!("[{}]", cell(r, i))).collect();
                s.push_str("  ");
                s.push_str(&cells.join(", "));
                s.push_str(",\n");
            }
            s.push_str(")\n\n");
        }
        TableStyle::Rst => {
            s.push_str("\n.. list-table::\n   :header-rows: 1\n\n");
            for r in rows {
                for i in 0..ncol {
                    let c = cell(r, i);
                    let c = if c.is_empty() { " " } else { c };
                    s.push_str(if i == 0 { "   * - " } else { "     - " });
                    s.push_str(c);
                    s.push('\n');
                }
            }
            s.push('\n');
        }
        TableStyle::Org => {
            for (ri, r) in rows.iter().enumerate() {
                let cells: Vec<&str> = (0..ncol).map(|i| cell(r, i)).collect();
                s.push_str(&format!("| {} |\n", cells.join(" | ")));
                if ri == 0 {
                    s.push('|');
                    for _ in 0..ncol {
                        s.push_str("---+");
                    }
                    s.pop();
                    s.push_str("|\n");
                }
            }
            s.push('\n');
        }
        TableStyle::Adoc => {
            s.push_str("\n[options=\"header\"]\n|===\n");
            for r in rows {
                for i in 0..ncol {
                    s.push_str(&format!("| {} ", cell(r, i)));
                }
                s.push('\n');
            }
            s.push_str("|===\n\n");
        }
        TableStyle::Rtf => {
            let colw = (9000 / ncol as u32).max(800);
            for (ri, r) in rows.iter().enumerate() {
                s.push_str("\\trowd\\trgaph108");
                for c in 1..=ncol {
                    s.push_str(&format!("\\cellx{}", colw * c as u32));
                }
                for i in 0..ncol {
                    let bold = if ri == 0 { "\\b " } else { "" };
                    let unbold = if ri == 0 { "\\b0" } else { "" };
                    s.push_str(&format!("\\intbl {}{}{}\\cell ", bold, cell(r, i), unbold));
                }
                s.push_str("\\row\n");
            }
            s.push_str("\\pard\n");
        }
    }
    s
}

// ═════════════════════════════════════════════════════════════════════════════
// Markdown target - the waypoint itself, re-emitted unchanged
// ═════════════════════════════════════════════════════════════════════════════

/// Markdown target: the extracted Markdown waypoint IS the output. Re-emitting it
/// unchanged is the honest identity export (no round-trip loss for this target).
pub(crate) fn export_md(markdown: &str) -> Result<Vec<u8>, String> {
    Ok(markdown.as_bytes().to_vec())
}

// ═════════════════════════════════════════════════════════════════════════════
// HTML target - pulldown-cmark's own pure-Rust renderer (no katex/duktape)
// ═════════════════════════════════════════════════════════════════════════════

/// HTML target. Uses `pulldown_cmark::html::push_html` (pure Rust) wrapped in a
/// minimal, valid HTML5 skeleton. Unlike the upstream converter's `export_html`, no math is
/// rendered (that path compiled in a JS engine); `$...$` stays literal text.
pub(crate) fn export_html(markdown: &str, meta: &ConvertMeta) -> Result<Vec<u8>, String> {
    let opts = Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TABLES | Options::ENABLE_TASKLISTS;
    let mut body = String::new();
    pulldown_cmark::html::push_html(&mut body, Parser::new_ext(markdown, opts));

    let lang = if meta.lang.is_empty() { "en" } else { &meta.lang };
    let title = if meta.title.is_empty() {
        "Document"
    } else {
        &meta.title
    };
    let doc = format!(
        "<!DOCTYPE html>\n<html lang=\"{}\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{}</title>\n</head>\n<body>\n{}</body>\n</html>\n",
        esc_xml(lang),
        esc_xml(title),
        body
    );
    Ok(doc.into_bytes())
}

// ═════════════════════════════════════════════════════════════════════════════
// TXT target - plain text, math delimiters stripped to their LaTeX source
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn export_txt(markdown: &str, _meta: &ConvertMeta) -> Result<Vec<u8>, String> {
    let opts = Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TABLES | Options::ENABLE_TASKLISTS;
    let mut out = String::new();
    let mut h_level: u32 = 0;
    let mut in_code = false;
    let mut is_ordered = false;
    let mut ord_n = 0u64;
    let mut in_image = false;
    let mut img_alt = String::new();

    for event in Parser::new_ext(markdown, opts) {
        match event {
            Event::Start(Tag::Image { .. }) => {
                in_image = true;
                img_alt.clear();
            }
            Event::End(TagEnd::Image) => {
                in_image = false;
                let label = if img_alt.is_empty() {
                    "image".to_string()
                } else {
                    std::mem::take(&mut img_alt)
                };
                out.push_str(&format!("[Image: {}]", label));
                img_alt.clear();
            }
            Event::Start(Tag::Heading { level, .. }) => {
                h_level = match level {
                    HeadingLevel::H1 => 1,
                    HeadingLevel::H2 => 2,
                    HeadingLevel::H3 => 3,
                    _ => 4,
                };
            }
            Event::End(TagEnd::Heading(_)) => {
                out.push_str("\n\n");
                h_level = 0;
            }
            Event::End(TagEnd::Paragraph) => out.push_str("\n\n"),
            Event::Start(Tag::List(start)) => {
                is_ordered = start.is_some();
                ord_n = start.unwrap_or(1).saturating_sub(1);
            }
            Event::End(TagEnd::List(_)) => out.push('\n'),
            Event::Start(Tag::Item) => {
                if is_ordered {
                    ord_n += 1;
                    out.push_str(&format!("  {}. ", ord_n));
                } else {
                    out.push_str("  \u{2022} ");
                }
            }
            Event::End(TagEnd::Item) => out.push('\n'),
            Event::Start(Tag::CodeBlock(_)) => {
                in_code = true;
                out.push('\n');
            }
            Event::End(TagEnd::CodeBlock) => {
                in_code = false;
                out.push('\n');
            }
            Event::Start(Tag::BlockQuote(_)) => out.push_str("  \u{2502} "),
            Event::End(TagEnd::BlockQuote(_)) => out.push('\n'),
            Event::Rule => {
                out.push_str(&"\u{2500}".repeat(60));
                out.push_str("\n\n");
            }
            Event::Text(t) => {
                if in_image {
                    img_alt.push_str(&t);
                } else {
                    if h_level > 0 {
                        out.push_str(&"#".repeat(h_level as usize));
                        out.push(' ');
                    }
                    if in_code {
                        for l in t.lines() {
                            out.push_str("    ");
                            out.push_str(l);
                            out.push('\n');
                        }
                    } else {
                        out.push_str(&t);
                    }
                }
            }
            Event::Code(c) => {
                out.push('`');
                out.push_str(&c);
                out.push('`');
            }
            Event::SoftBreak => out.push(' '),
            Event::HardBreak => out.push('\n'),
            _ => {}
        }
    }

    // Strip any remaining $$...$$ delimiters, keeping the LaTeX source (see the
    // module doc, point 3: math is carried as source, not approximated).
    let final_text = strip_display_delimiters(&out);
    Ok(final_text.trim_end().as_bytes().to_vec())
}

/// Replace `$$ ... $$` display blocks with their inner LaTeX source, delimiters
/// removed. The dependency-light stand-in for the upstream converter's `sub_eq_unicode`.
fn strip_display_delimiters(text: &str) -> String {
    let mut o = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        if let Some(p) = rest.find("$$") {
            o.push_str(&rest[..p]);
            let after = &rest[p + 2..];
            if let Some(e) = after.find("$$") {
                o.push_str(&math_source(&after[..e]));
                rest = &after[e + 2..];
            } else {
                o.push_str(rest);
                break;
            }
        } else {
            o.push_str(rest);
            break;
        }
    }
    o
}

// ═════════════════════════════════════════════════════════════════════════════
// TeX/LaTeX target - native \begin{equation} blocks, LaTeX kept verbatim
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn export_tex(markdown: &str, meta: &ConvertMeta) -> Result<Vec<u8>, String> {
    let mut doc = String::with_capacity(markdown.len() * 2);

    doc.push_str("\\documentclass[12pt,a4paper]{article}\n");
    doc.push_str("\\usepackage[utf8]{inputenc}\n\\usepackage[T1]{fontenc}\n");
    doc.push_str("\\usepackage{amsmath,amssymb,amsfonts}\n");
    doc.push_str("\\usepackage{graphicx,xcolor}\n");
    doc.push_str("\\usepackage[colorlinks,linkcolor=blue,urlcolor=blue]{hyperref}\n");
    doc.push_str("\\usepackage{listings,geometry}\n");
    doc.push_str("\\geometry{a4paper,margin=2.5cm}\n");
    doc.push_str("\\setlength{\\parskip}{0.5em}\\setlength{\\parindent}{0pt}\n");
    doc.push_str("\\lstset{basicstyle=\\ttfamily\\small,breaklines=true,frame=single,backgroundcolor=\\color{gray!10}}\n\n");

    if !meta.title.is_empty() {
        doc.push_str(&format!("\\title{{{}}}\n", esc_tex(&meta.title)));
    }
    if !meta.author.is_empty() {
        doc.push_str(&format!("\\author{{{}}}\n", esc_tex(&meta.author)));
    }
    let date_line = if meta.timestamp.is_empty() {
        "\\date{}\n".to_string()
    } else {
        format!("\\date{{{}}}\n", esc_tex(&meta.timestamp))
    };
    doc.push_str(&date_line);

    doc.push_str("\n\\begin{document}\n");
    if !meta.title.is_empty() || !meta.author.is_empty() {
        doc.push_str("\\maketitle\n");
    }
    doc.push('\n');

    for block in split_display_blocks(markdown) {
        match block {
            Block::Text(t) => doc.push_str(&md_fragment_to_tex(t)),
            Block::Equation(latex) => {
                doc.push_str("\\begin{equation}\n");
                doc.push_str(latex);
                doc.push_str("\n\\end{equation}\n\n");
            }
        }
    }

    doc.push_str("\\end{document}\n");
    Ok(doc.into_bytes())
}

fn md_fragment_to_tex(md: &str) -> String {
    let opts = Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TABLES
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_MATH;
    let mut out = String::new();
    let mut buf = String::new();
    let mut h_level: u32 = 0;
    let mut in_code = false;
    let mut is_ordered = false;
    let mut in_image = false;
    let mut img_url = String::new();
    let mut trow: Vec<String> = Vec::new();
    let mut trows: Vec<Vec<String>> = Vec::new();

    macro_rules! flush {
        () => {
            let t = std::mem::take(&mut buf);
            if !t.trim().is_empty() {
                out.push_str(t.trim());
                out.push('\n');
            }
        };
    }

    for event in Parser::new_ext(md, opts) {
        match event {
            Event::Start(Tag::Image { dest_url, .. }) => {
                in_image = true;
                img_url = dest_url.to_string();
            }
            Event::End(TagEnd::Image) => {
                in_image = false;
                buf.push_str(&format!(
                    "\\includegraphics[width=0.8\\linewidth]{{{}}}",
                    img_url
                ));
                img_url.clear();
            }
            Event::Start(Tag::Heading { level, .. }) => {
                flush!();
                h_level = match level {
                    HeadingLevel::H1 => 1,
                    HeadingLevel::H2 => 2,
                    HeadingLevel::H3 => 3,
                    HeadingLevel::H4 => 4,
                    _ => 5,
                };
                let cmd = [
                    "",
                    "section",
                    "subsection",
                    "subsubsection",
                    "paragraph",
                    "subparagraph",
                ][h_level as usize];
                out.push_str(&format!("\n\\{}{{\n", cmd));
            }
            Event::End(TagEnd::Heading(_)) => {
                flush!();
                out.push_str("}\n\n");
                h_level = 0;
            }
            Event::End(TagEnd::Paragraph) => {
                let t = std::mem::take(&mut buf);
                if !t.trim().is_empty() {
                    out.push_str(t.trim());
                    out.push_str("\n\n");
                }
            }
            Event::Start(Tag::Strong) => buf.push_str("\\textbf{"),
            Event::End(TagEnd::Strong) => buf.push('}'),
            Event::Start(Tag::Emphasis) => buf.push_str("\\textit{"),
            Event::End(TagEnd::Emphasis) => buf.push('}'),
            Event::Start(Tag::Strikethrough) => buf.push_str("\\sout{"),
            Event::End(TagEnd::Strikethrough) => buf.push('}'),
            Event::Start(Tag::List(s)) => {
                flush!();
                is_ordered = s.is_some();
                out.push_str(if is_ordered {
                    "\\begin{enumerate}\n"
                } else {
                    "\\begin{itemize}\n"
                });
            }
            Event::End(TagEnd::List(_)) => out.push_str(if is_ordered {
                "\\end{enumerate}\n\n"
            } else {
                "\\end{itemize}\n\n"
            }),
            Event::Start(Tag::Item) => out.push_str("  \\item "),
            Event::End(TagEnd::Item) => {
                let t = std::mem::take(&mut buf);
                out.push_str(t.trim());
                out.push('\n');
            }
            Event::Start(Tag::CodeBlock(kind)) => {
                flush!();
                in_code = true;
                let lang = match &kind {
                    CodeBlockKind::Fenced(l) if !l.is_empty() => format!("[language={}]", l),
                    _ => String::new(),
                };
                out.push_str(&format!("\\begin{{lstlisting}}{}\n", lang));
            }
            Event::End(TagEnd::CodeBlock) => {
                out.push_str(&buf);
                buf.clear();
                out.push_str("\\end{lstlisting}\n\n");
                in_code = false;
            }
            Event::Start(Tag::BlockQuote(_)) => {
                flush!();
                out.push_str("\\begin{quote}\n\\itshape ");
            }
            Event::End(TagEnd::BlockQuote(_)) => {
                let t = std::mem::take(&mut buf);
                out.push_str(t.trim());
                out.push_str("\n\\end{quote}\n\n");
            }
            Event::Start(Tag::Link { dest_url, .. }) => {
                buf.push_str(&format!("\\href{{{}}}{{\n", esc_tex(&dest_url)))
            }
            Event::End(TagEnd::Link) => buf.push('}'),
            Event::Rule => out.push_str("\n\\noindent\\rule{\\textwidth}{0.4pt}\n\n"),
            Event::Start(Tag::Table(_)) => {
                flush!();
                trows.clear();
                trow.clear();
            }
            Event::End(TagEnd::TableCell) => trow.push(std::mem::take(&mut buf)),
            Event::End(TagEnd::TableHead) | Event::End(TagEnd::TableRow) => {
                trows.push(std::mem::take(&mut trow))
            }
            Event::End(TagEnd::Table) => out.push_str(&render_table(&trows, TableStyle::Latex)),
            Event::InlineMath(m) => buf.push_str(&format!("${}$", math_source(&m))),
            Event::DisplayMath(m) => {
                flush!();
                out.push_str(&format!("\\[{}\\]\n\n", math_source(&m)));
            }
            Event::Text(t) => {
                if in_image {
                } else if in_code {
                    buf.push_str(&t);
                } else {
                    buf.push_str(&esc_tex(&t));
                }
            }
            Event::Code(c) => buf.push_str(&format!("\\texttt{{{}}}", esc_tex(&c))),
            Event::SoftBreak => buf.push(' '),
            Event::HardBreak => buf.push_str("\\\\\n"),
            _ => {}
        }
    }
    flush!();
    out
}

// ═════════════════════════════════════════════════════════════════════════════
// Typst source target (.typ) - math carried as LaTeX source (see module doc)
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn export_typst_src(markdown: &str, meta: &ConvertMeta) -> Result<Vec<u8>, String> {
    let mut doc = String::new();
    doc.push_str("#set page(paper: \"a4\", margin: (x: 2.5cm, y: 2.5cm))\n");
    doc.push_str("#set text(font: \"New Computer Modern\", size: 11pt, lang: \"");
    doc.push_str(if meta.lang.is_empty() { "en" } else { &meta.lang });
    doc.push_str("\")\n#set heading(numbering: \"1.\")\n#set par(justify: true)\n\n");

    if !meta.title.is_empty() {
        doc.push_str(&format!(
            "#align(center)[#text(size: 18pt, weight: \"bold\")[{}]]\n",
            &meta.title
        ));
        if !meta.author.is_empty() {
            doc.push_str(&format!(
                "#align(center)[#text(size: 12pt, style: \"italic\")[{}]]\n",
                &meta.author
            ));
        }
        doc.push_str("#v(1em)\n\n");
    }

    for block in split_display_blocks(markdown) {
        match block {
            Block::Text(t) => doc.push_str(&md_fragment_to_typst(t)),
            Block::Equation(lat) => {
                doc.push_str(&format!("$ {} $\n\n", math_source(lat)));
            }
        }
    }

    Ok(doc.into_bytes())
}

fn md_fragment_to_typst(md: &str) -> String {
    let opts =
        Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TABLES | Options::ENABLE_MATH;
    let mut out = String::new();
    let mut buf = String::new();
    let mut h_level: u32 = 0;
    let mut in_code = false;
    let mut is_ordered = false;
    let mut list_depth: u32 = 0;
    let mut in_image = false;
    let mut img_url = String::new();
    let mut img_alt = String::new();
    let mut trow: Vec<String> = Vec::new();
    let mut trows: Vec<Vec<String>> = Vec::new();

    macro_rules! flush {
        () => {
            let t = std::mem::take(&mut buf);
            if !t.is_empty() {
                out.push_str(&t);
            }
        };
    }

    for event in Parser::new_ext(md, opts) {
        match event {
            Event::Start(Tag::Image { dest_url, .. }) => {
                in_image = true;
                img_url = dest_url.to_string();
                img_alt.clear();
            }
            Event::End(TagEnd::Image) => {
                in_image = false;
                if img_alt.is_empty() {
                    buf.push_str(&format!("#image(\"{}\", width: 80%)", img_url));
                } else {
                    buf.push_str(&format!(
                        "#figure(image(\"{}\", width: 80%), caption: [{}])",
                        img_url,
                        esc_typst(&img_alt)
                    ));
                }
                img_url.clear();
                img_alt.clear();
            }
            Event::Start(Tag::Heading { level, .. }) => {
                flush!();
                h_level = match level {
                    HeadingLevel::H1 => 1,
                    HeadingLevel::H2 => 2,
                    HeadingLevel::H3 => 3,
                    _ => 4,
                };
                out.push_str(&"=".repeat(h_level as usize));
                out.push(' ');
            }
            Event::End(TagEnd::Heading(_)) => {
                flush!();
                out.push_str("\n\n");
                h_level = 0;
            }
            Event::End(TagEnd::Paragraph) => {
                flush!();
                out.push_str("\n\n");
            }
            Event::Start(Tag::Strong) => buf.push_str("*"),
            Event::End(TagEnd::Strong) => buf.push('*'),
            Event::Start(Tag::Emphasis) => buf.push('_'),
            Event::End(TagEnd::Emphasis) => buf.push('_'),
            Event::Start(Tag::Strikethrough) => buf.push_str("#strike["),
            Event::End(TagEnd::Strikethrough) => buf.push(']'),
            Event::Start(Tag::List(s)) => {
                flush!();
                list_depth += 1;
                is_ordered = s.is_some();
            }
            Event::End(TagEnd::List(_)) => {
                list_depth = list_depth.saturating_sub(1);
                out.push('\n');
            }
            Event::Start(Tag::Item) => {
                let ind = "  ".repeat(list_depth.saturating_sub(1) as usize);
                out.push_str(&format!("{}{} ", ind, if is_ordered { "+" } else { "-" }));
            }
            Event::End(TagEnd::Item) => {
                flush!();
                out.push('\n');
            }
            Event::Start(Tag::CodeBlock(kind)) => {
                flush!();
                in_code = true;
                let lang = match &kind {
                    CodeBlockKind::Fenced(l) if !l.is_empty() => l.as_ref(),
                    _ => "",
                };
                out.push_str(&format!("```{}\n", lang));
            }
            Event::End(TagEnd::CodeBlock) => {
                flush!();
                out.push_str("```\n\n");
                in_code = false;
            }
            Event::Start(Tag::BlockQuote(_)) => {
                flush!();
                out.push_str("#quote[\n");
            }
            Event::End(TagEnd::BlockQuote(_)) => {
                flush!();
                out.push_str("]\n\n");
            }
            Event::Start(Tag::Link { dest_url, .. }) => {
                buf.push_str(&format!("#link(\"{}\")[", dest_url))
            }
            Event::End(TagEnd::Link) => buf.push(']'),
            Event::Rule => {
                flush!();
                out.push_str("#line(length: 100%)\n\n");
            }
            Event::Start(Tag::Table(_)) => {
                flush!();
                trows.clear();
                trow.clear();
            }
            Event::End(TagEnd::TableCell) => trow.push(std::mem::take(&mut buf)),
            Event::End(TagEnd::TableHead) | Event::End(TagEnd::TableRow) => {
                trows.push(std::mem::take(&mut trow))
            }
            Event::End(TagEnd::Table) => out.push_str(&render_table(&trows, TableStyle::Typst)),
            Event::InlineMath(m) => buf.push_str(&format!("${}$", math_source(&m))),
            Event::DisplayMath(m) => {
                flush!();
                out.push_str(&format!("$ {} $\n\n", math_source(&m)));
            }
            Event::Text(t) => {
                if in_image {
                    img_alt.push_str(&t);
                } else if in_code {
                    buf.push_str(&t);
                } else {
                    buf.push_str(&esc_typst(&t));
                }
            }
            Event::Code(c) => buf.push_str(&format!("`{}`", c)),
            Event::SoftBreak => buf.push(' '),
            Event::HardBreak => {
                flush!();
                out.push_str("\\\n");
            }
            _ => {}
        }
    }
    flush!();
    out
}

// ═════════════════════════════════════════════════════════════════════════════
// RTF target - manual RTF generation, math as LaTeX source, no figure embedding
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn export_rtf(markdown: &str, meta: &ConvertMeta) -> Result<Vec<u8>, String> {
    let mut rtf = String::new();
    rtf.push_str("{\\rtf1\\ansi\\ansicpg1252\\cocoartf2639\n");
    rtf.push_str(
        "{\\fonttbl\\f0\\froman\\fcharset0 Times New Roman;\\f1\\fmodern\\fcharset0 Courier New;}\n",
    );
    rtf.push_str("{\\colortbl;\\red0\\green0\\blue0;\\red70\\green130\\blue200;\\red85\\green85\\blue85;}\n");
    rtf.push_str("\\widowctrl\\hyphauto\\widctlpar\\f0\\fs24\\cf1\n");

    if !meta.title.is_empty() {
        rtf.push_str(&format!(
            "\\pard\\qc\\sb240\\b\\fs36 {}\\b0\\fs24\\par\n",
            esc_rtf(&meta.title)
        ));
        if !meta.author.is_empty() {
            rtf.push_str(&format!(
                "\\pard\\qc\\fs22\\cf3 {}\\cf1\\fs24\\par\n",
                esc_rtf(&meta.author)
            ));
        }
        rtf.push_str("\\pard\\sb200\\par\n");
    }

    for block in split_display_blocks(markdown) {
        match block {
            Block::Text(t) => rtf.push_str(&md_fragment_to_rtf(t)),
            Block::Equation(lat) => {
                rtf.push_str(&format!(
                    "\\pard\\qc\\sb100\\sa100\\i {}\\i0\\par\n",
                    esc_rtf(&math_source(lat))
                ));
            }
        }
    }

    rtf.push('}');
    Ok(rtf.into_bytes())
}

fn md_fragment_to_rtf(md: &str) -> String {
    let opts = Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TABLES
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_MATH;
    let mut out = String::new();
    let mut buf = String::new();
    let mut h_level: u32 = 0;
    let mut in_code = false;
    let mut is_ordered = false;
    let mut ord_n = 0u64;
    let mut bold = false;
    let mut italic = false;
    let mut in_image = false;
    let mut img_alt = String::new();
    let mut trow: Vec<String> = Vec::new();
    let mut trows: Vec<Vec<String>> = Vec::new();

    macro_rules! flush {
        () => {
            let t = std::mem::take(&mut buf);
            if !t.is_empty() {
                out.push_str(&t);
            }
        };
    }

    for event in Parser::new_ext(md, opts) {
        match event {
            Event::Start(Tag::Heading { level, .. }) => {
                flush!();
                h_level = match level {
                    HeadingLevel::H1 => 1,
                    HeadingLevel::H2 => 2,
                    _ => 3,
                };
                let (sz, sb) = match h_level {
                    1 => (40u32, 280u32),
                    2 => (32, 220),
                    _ => (28, 180),
                };
                out.push_str(&format!("\\pard\\sb{}\\b\\fs{} ", sb, sz));
            }
            Event::End(TagEnd::Heading(_)) => {
                flush!();
                out.push_str("\\b0\\fs24\\par\n");
                h_level = 0;
            }
            Event::End(TagEnd::Paragraph) => {
                flush!();
                out.push_str("\\par\n");
            }
            Event::Start(Tag::Strong) => {
                flush!();
                bold = true;
                out.push_str("\\b ");
            }
            Event::End(TagEnd::Strong) => {
                flush!();
                bold = false;
                out.push_str("\\b0 ");
            }
            Event::Start(Tag::Emphasis) => {
                flush!();
                italic = true;
                out.push_str("\\i ");
            }
            Event::End(TagEnd::Emphasis) => {
                flush!();
                italic = false;
                out.push_str("\\i0 ");
            }
            Event::Start(Tag::Strikethrough) => {
                flush!();
                out.push_str("\\strike ");
            }
            Event::End(TagEnd::Strikethrough) => {
                flush!();
                out.push_str("\\strike0 ");
            }
            Event::Start(Tag::List(s)) => {
                flush!();
                is_ordered = s.is_some();
                ord_n = s.unwrap_or(1).saturating_sub(1);
            }
            Event::End(TagEnd::List(_)) => {
                out.push_str("\\par\n");
            }
            Event::Start(Tag::Item) => {
                if is_ordered {
                    ord_n += 1;
                    out.push_str(&format!("\\pard\\li720\\fi-360 {}.\\ ", ord_n));
                } else {
                    out.push_str("\\pard\\li720\\fi-360 \\bullet\\ ");
                }
            }
            Event::End(TagEnd::Item) => {
                flush!();
                out.push_str("\\par\n");
            }
            Event::Start(Tag::CodeBlock(_)) => {
                flush!();
                in_code = true;
                out.push_str("\\pard\\f1\\fs20\\cf3 ");
            }
            Event::End(TagEnd::CodeBlock) => {
                flush!();
                out.push_str("\\f0\\fs24\\cf1\\par\n");
                in_code = false;
            }
            Event::Start(Tag::BlockQuote(_)) => {
                flush!();
                out.push_str("\\pard\\li720\\i\\cf3 ");
            }
            Event::End(TagEnd::BlockQuote(_)) => {
                flush!();
                out.push_str("\\i0\\cf1\\par\n");
            }
            Event::Rule => {
                flush!();
                out.push_str("\\pard\\brdrb\\brdrs\\brdrw10\\brsp20 \\par\n");
            }
            Event::Start(Tag::Image { .. }) => {
                flush!();
                in_image = true;
                img_alt.clear();
            }
            Event::End(TagEnd::Image) => {
                in_image = false;
                // No figure embedding in the converter (that path pulls the image
                // crate); emit the alt text as a caption fallback.
                if !img_alt.is_empty() {
                    out.push_str(&esc_rtf(&img_alt));
                }
                img_alt.clear();
            }
            Event::Start(Tag::Table(_)) => {
                flush!();
                trows.clear();
                trow.clear();
            }
            Event::End(TagEnd::TableCell) => trow.push(std::mem::take(&mut buf)),
            Event::End(TagEnd::TableHead) | Event::End(TagEnd::TableRow) => {
                trows.push(std::mem::take(&mut trow))
            }
            Event::End(TagEnd::Table) => out.push_str(&render_table(&trows, TableStyle::Rtf)),
            Event::InlineMath(m) => buf.push_str(&esc_rtf(&math_source(&m))),
            Event::DisplayMath(m) => {
                flush!();
                out.push_str(&format!(
                    "\\pard\\qc\\i {}\\i0\\par\n",
                    esc_rtf(&math_source(&m))
                ));
            }
            Event::Text(t) => {
                if in_image {
                    img_alt.push_str(&t);
                } else {
                    buf.push_str(&esc_rtf(&t));
                }
            }
            Event::Code(c) => {
                flush!();
                out.push_str(&format!("\\f1\\fs20 {}\\f0\\fs24 ", esc_rtf(&c)));
            }
            Event::SoftBreak => buf.push(' '),
            Event::HardBreak => {
                flush!();
                out.push_str("\\line ");
            }
            _ => {}
        }
    }
    flush!();
    out
}

// ═════════════════════════════════════════════════════════════════════════════
// Org-mode target (.org) - LaTeX math kept verbatim
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn export_org(markdown: &str, meta: &ConvertMeta) -> Result<Vec<u8>, String> {
    let opts = Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TABLES
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_MATH;
    let mut doc = String::new();

    if !meta.title.is_empty() {
        doc.push_str(&format!("#+TITLE: {}\n", meta.title));
    }
    if !meta.author.is_empty() {
        doc.push_str(&format!("#+AUTHOR: {}\n", meta.author));
    }
    doc.push_str("#+OPTIONS: toc:t num:t\n\n");

    let mut buf = String::new();
    let mut in_code = false;
    let mut is_ordered = false;
    let mut in_bquote = false;
    let mut in_image = false;
    let mut img_url = String::new();
    let mut trow: Vec<String> = Vec::new();
    let mut trows: Vec<Vec<String>> = Vec::new();

    macro_rules! flush {
        () => {
            let t = std::mem::take(&mut buf);
            if !t.is_empty() {
                doc.push_str(t.trim());
            }
        };
    }

    for event in Parser::new_ext(markdown, opts) {
        match event {
            Event::Start(Tag::Table(_)) => {
                flush!();
                trows.clear();
                trow.clear();
            }
            Event::End(TagEnd::TableCell) => trow.push(std::mem::take(&mut buf)),
            Event::End(TagEnd::TableHead) | Event::End(TagEnd::TableRow) => {
                trows.push(std::mem::take(&mut trow))
            }
            Event::End(TagEnd::Table) => {
                doc.push('\n');
                doc.push_str(&render_table(&trows, TableStyle::Org));
            }
            Event::Start(Tag::Image { dest_url, .. }) => {
                in_image = true;
                img_url = dest_url.to_string();
            }
            Event::End(TagEnd::Image) => {
                in_image = false;
                buf.push_str(&format!("[[file:{}]]", img_url));
                img_url.clear();
            }
            Event::Start(Tag::Heading { level, .. }) => {
                flush!();
                let n = match level {
                    HeadingLevel::H1 => 1,
                    HeadingLevel::H2 => 2,
                    HeadingLevel::H3 => 3,
                    HeadingLevel::H4 => 4,
                    _ => 5,
                };
                doc.push_str(&"*".repeat(n));
                doc.push(' ');
            }
            Event::End(TagEnd::Heading(_)) => {
                flush!();
                doc.push_str("\n\n");
            }
            Event::End(TagEnd::Paragraph) => {
                flush!();
                doc.push_str("\n\n");
            }
            Event::Start(Tag::Strong) => buf.push('*'),
            Event::End(TagEnd::Strong) => buf.push('*'),
            Event::Start(Tag::Emphasis) => buf.push('/'),
            Event::End(TagEnd::Emphasis) => buf.push('/'),
            Event::Start(Tag::Strikethrough) => buf.push('+'),
            Event::End(TagEnd::Strikethrough) => buf.push('+'),
            Event::Start(Tag::List(s)) => {
                is_ordered = s.is_some();
            }
            Event::End(TagEnd::List(_)) => {
                doc.push('\n');
            }
            Event::Start(Tag::Item) => {
                if is_ordered {
                    doc.push_str("1. ");
                } else {
                    doc.push_str("- ");
                }
            }
            Event::End(TagEnd::Item) => {
                flush!();
                doc.push('\n');
            }
            Event::Start(Tag::CodeBlock(kind)) => {
                flush!();
                in_code = true;
                let lang = match &kind {
                    CodeBlockKind::Fenced(l) if !l.is_empty() => l.to_string(),
                    _ => String::new(),
                };
                doc.push_str(&format!("#+begin_src {}\n", lang));
            }
            Event::End(TagEnd::CodeBlock) => {
                doc.push_str(buf.trim_end());
                buf.clear();
                doc.push_str("\n#+end_src\n\n");
                in_code = false;
            }
            Event::Start(Tag::BlockQuote(_)) => {
                flush!();
                in_bquote = true;
                doc.push_str("#+begin_quote\n");
            }
            Event::End(TagEnd::BlockQuote(_)) => {
                flush!();
                doc.push_str("\n#+end_quote\n\n");
                in_bquote = false;
            }
            Event::Start(Tag::Link { dest_url, .. }) => {
                buf.push_str(&format!("[[{}][", dest_url))
            }
            Event::End(TagEnd::Link) => buf.push_str("]]"),
            Event::Rule => {
                flush!();
                doc.push_str("-----\n\n");
            }
            Event::DisplayMath(m) => {
                flush!();
                doc.push_str(&format!(
                    "\n\\begin{{equation}}\n{}\n\\end{{equation}}\n\n",
                    math_source(&m)
                ));
            }
            Event::InlineMath(m) => buf.push_str(&format!("${}$", math_source(&m))),
            Event::Text(t) => {
                if in_image {
                } else {
                    buf.push_str(&t);
                }
            }
            Event::Code(c) => buf.push_str(&format!("={}=", c)),
            Event::SoftBreak => buf.push(' '),
            Event::HardBreak => {
                flush!();
                doc.push('\n');
            }
            _ => {}
        }
    }

    Ok(doc.into_bytes())
}

// ═════════════════════════════════════════════════════════════════════════════
// reStructuredText target (.rst) - LaTeX math kept verbatim
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn export_rst(markdown: &str, meta: &ConvertMeta) -> Result<Vec<u8>, String> {
    let opts = Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TABLES | Options::ENABLE_MATH;
    let underlines = ['=', '-', '~', '^', '"'];
    let mut doc = String::new();

    if !meta.title.is_empty() {
        let u = "=".repeat(meta.title.len());
        doc.push_str(&format!("{}\n{}\n{}\n\n", u, meta.title, u));
    }
    if !meta.author.is_empty() {
        doc.push_str(&format!(":Author: {}\n\n", meta.author));
    }

    let mut buf = String::new();
    let mut in_code = false;
    let mut code_lang = String::new();
    let mut is_ordered = false;
    let mut in_image = false;
    let mut img_url = String::new();
    let mut img_alt = String::new();
    let mut trow: Vec<String> = Vec::new();
    let mut trows: Vec<Vec<String>> = Vec::new();

    macro_rules! flush {
        () => {
            let t = std::mem::take(&mut buf);
            if !t.trim().is_empty() {
                doc.push_str(t.trim());
            }
        };
    }

    for event in Parser::new_ext(markdown, opts) {
        match event {
            Event::Start(Tag::Table(_)) => {
                flush!();
                trows.clear();
                trow.clear();
            }
            Event::End(TagEnd::TableCell) => trow.push(std::mem::take(&mut buf)),
            Event::End(TagEnd::TableHead) | Event::End(TagEnd::TableRow) => {
                trows.push(std::mem::take(&mut trow))
            }
            Event::End(TagEnd::Table) => doc.push_str(&render_table(&trows, TableStyle::Rst)),
            Event::Start(Tag::Image { dest_url, .. }) => {
                flush!();
                in_image = true;
                img_url = dest_url.to_string();
                img_alt.clear();
            }
            Event::End(TagEnd::Image) => {
                in_image = false;
                doc.push_str(&format!("\n\n.. image:: {}\n", img_url));
                if !img_alt.is_empty() {
                    doc.push_str(&format!("   :alt: {}\n", img_alt));
                }
                doc.push('\n');
                img_url.clear();
                img_alt.clear();
            }
            Event::Start(Tag::Heading { level: _, .. }) => {
                flush!();
                doc.push('\n');
            }
            Event::End(TagEnd::Heading(level)) => {
                let lvl = match level {
                    HeadingLevel::H1 => 0,
                    HeadingLevel::H2 => 1,
                    HeadingLevel::H3 => 2,
                    HeadingLevel::H4 => 3,
                    _ => 4,
                };
                let uc = underlines.get(lvl).copied().unwrap_or('"');
                let t = buf.trim().to_string();
                buf.clear();
                let u = uc.to_string().repeat(t.len().max(4));
                doc.push_str(&format!("{}\n{}\n\n", t, u));
            }
            Event::End(TagEnd::Paragraph) => {
                flush!();
                doc.push_str("\n\n");
            }
            Event::Start(Tag::Strong) => buf.push_str("**"),
            Event::End(TagEnd::Strong) => buf.push_str("**"),
            Event::Start(Tag::Emphasis) => buf.push('*'),
            Event::End(TagEnd::Emphasis) => buf.push('*'),
            Event::Start(Tag::List(s)) => {
                is_ordered = s.is_some();
            }
            Event::End(TagEnd::List(_)) => doc.push('\n'),
            Event::Start(Tag::Item) => {
                if is_ordered {
                    doc.push_str("#. ");
                } else {
                    doc.push_str("- ");
                }
            }
            Event::End(TagEnd::Item) => {
                flush!();
                doc.push('\n');
            }
            Event::Start(Tag::CodeBlock(kind)) => {
                flush!();
                in_code = true;
                code_lang = match &kind {
                    CodeBlockKind::Fenced(l) if !l.is_empty() => l.to_string(),
                    _ => String::new(),
                };
                doc.push_str(&format!(".. code-block:: {}\n\n", code_lang));
            }
            Event::End(TagEnd::CodeBlock) => {
                for line in buf.lines() {
                    doc.push_str(&format!("   {}\n", line));
                }
                buf.clear();
                doc.push('\n');
                in_code = false;
            }
            Event::Start(Tag::BlockQuote(_)) => {}
            Event::End(TagEnd::BlockQuote(_)) => {
                let t = std::mem::take(&mut buf);
                for line in t.lines() {
                    doc.push_str(&format!("   {}\n", line.trim()));
                }
                doc.push('\n');
            }
            Event::DisplayMath(m) => {
                flush!();
                doc.push_str(&format!(
                    ".. math::\n\n   {}\n\n",
                    math_source(&m).replace('\n', "\n   ")
                ));
            }
            Event::InlineMath(m) => {
                buf.push_str(&format!("\\ :math:`{}`\\ ", math_source(&m)))
            }
            Event::Rule => {
                flush!();
                doc.push_str("\n----\n\n");
            }
            Event::Text(t) => {
                if in_image {
                    img_alt.push_str(&t);
                } else {
                    buf.push_str(&esc_rst_text(&t));
                }
            }
            Event::Code(c) => buf.push_str(&format!("\\ ``{}``\\ ", c)),
            Event::SoftBreak => buf.push(' '),
            Event::HardBreak => {
                flush!();
                doc.push_str("\n\n");
            }
            _ => {}
        }
    }

    Ok(doc.into_bytes())
}

// ═════════════════════════════════════════════════════════════════════════════
// AsciiDoc target (.adoc) - LaTeX math kept verbatim
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn export_adoc(markdown: &str, meta: &ConvertMeta) -> Result<Vec<u8>, String> {
    let opts = Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TABLES | Options::ENABLE_MATH;
    let mut doc = String::new();

    if !meta.title.is_empty() {
        doc.push_str(&format!("= {}\n", meta.title));
    }
    if !meta.author.is_empty() {
        doc.push_str(&format!("{}\n", meta.author));
    }
    doc.push_str(":toc:\n:stem: latexmath\n\n");

    let mut buf = String::new();
    let mut in_code = false;
    let mut code_lang = String::new();
    let mut is_ordered = false;
    let mut in_image = false;
    let mut img_url = String::new();
    let mut img_alt = String::new();
    let mut trow: Vec<String> = Vec::new();
    let mut trows: Vec<Vec<String>> = Vec::new();

    macro_rules! flush {
        () => {
            let t = std::mem::take(&mut buf);
            if !t.trim().is_empty() {
                doc.push_str(t.trim());
            }
        };
    }

    for event in Parser::new_ext(markdown, opts) {
        match event {
            Event::Start(Tag::Table(_)) => {
                flush!();
                trows.clear();
                trow.clear();
            }
            Event::End(TagEnd::TableCell) => trow.push(std::mem::take(&mut buf)),
            Event::End(TagEnd::TableHead) | Event::End(TagEnd::TableRow) => {
                trows.push(std::mem::take(&mut trow))
            }
            Event::End(TagEnd::Table) => doc.push_str(&render_table(&trows, TableStyle::Adoc)),
            Event::Start(Tag::Image { dest_url, .. }) => {
                flush!();
                in_image = true;
                img_url = dest_url.to_string();
                img_alt.clear();
            }
            Event::End(TagEnd::Image) => {
                in_image = false;
                doc.push_str(&format!("\n\nimage::{}[{}]\n\n", img_url, img_alt));
                img_url.clear();
                img_alt.clear();
            }
            Event::Start(Tag::Heading { level, .. }) => {
                flush!();
                let lvl = match level {
                    HeadingLevel::H1 => 2,
                    HeadingLevel::H2 => 3,
                    HeadingLevel::H3 => 4,
                    HeadingLevel::H4 => 5,
                    _ => 6,
                };
                doc.push_str(&"=".repeat(lvl));
                doc.push(' ');
            }
            Event::End(TagEnd::Heading(_)) => {
                flush!();
                doc.push_str("\n\n");
            }
            Event::End(TagEnd::Paragraph) => {
                flush!();
                doc.push_str("\n\n");
            }
            Event::Start(Tag::Strong) => buf.push('*'),
            Event::End(TagEnd::Strong) => buf.push('*'),
            Event::Start(Tag::Emphasis) => buf.push('_'),
            Event::End(TagEnd::Emphasis) => buf.push('_'),
            Event::Start(Tag::Strikethrough) => buf.push_str("[.line-through]#"),
            Event::End(TagEnd::Strikethrough) => buf.push('#'),
            Event::Start(Tag::List(s)) => {
                is_ordered = s.is_some();
            }
            Event::End(TagEnd::List(_)) => doc.push('\n'),
            Event::Start(Tag::Item) => {
                if is_ordered {
                    doc.push_str(". ");
                } else {
                    doc.push_str("* ");
                }
            }
            Event::End(TagEnd::Item) => {
                flush!();
                doc.push('\n');
            }
            Event::Start(Tag::CodeBlock(kind)) => {
                flush!();
                in_code = true;
                code_lang = match &kind {
                    CodeBlockKind::Fenced(l) if !l.is_empty() => l.to_string(),
                    _ => String::new(),
                };
                if !code_lang.is_empty() {
                    doc.push_str(&format!("[source,{}]\n", code_lang));
                }
                doc.push_str("----\n");
            }
            Event::End(TagEnd::CodeBlock) => {
                doc.push_str(buf.trim_end());
                buf.clear();
                doc.push_str("\n----\n\n");
                in_code = false;
            }
            Event::Start(Tag::BlockQuote(_)) => {
                flush!();
                doc.push_str("____\n");
            }
            Event::End(TagEnd::BlockQuote(_)) => {
                flush!();
                doc.push_str("\n____\n\n");
            }
            Event::DisplayMath(m) => {
                flush!();
                doc.push_str(&format!("[stem]\n++++\n{}\n++++\n\n", math_source(&m)));
            }
            Event::InlineMath(m) => buf.push_str(&format!("stem:[{}]", math_source(&m))),
            Event::Rule => {
                flush!();
                doc.push_str("'''\n\n");
            }
            Event::Text(t) => {
                if in_image {
                    img_alt.push_str(&t);
                } else {
                    buf.push_str(&t);
                }
            }
            Event::Code(c) => buf.push_str(&format!("`{}`", c)),
            Event::SoftBreak => buf.push(' '),
            Event::HardBreak => {
                flush!();
                doc.push_str(" +\n");
            }
            _ => {}
        }
    }

    Ok(doc.into_bytes())
}

// ═════════════════════════════════════════════════════════════════════════════
// Jupyter Notebook target (.ipynb) - JSON via serde_json (already a dep)
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn export_ipynb(markdown: &str, _meta: &ConvertMeta) -> Result<Vec<u8>, String> {
    let opts = Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TABLES | Options::ENABLE_MATH;
    let mut cells: Vec<serde_json::Value> = Vec::new();
    let mut md_buf = String::new();
    let mut code_buf = String::new();
    let mut in_code = false;
    let mut code_lang = String::new();
    let mut in_image = false;
    let mut img_url = String::new();
    let mut img_alt = String::new();

    let flush_md = |md_buf: &mut String, cells: &mut Vec<serde_json::Value>| {
        let t = std::mem::take(md_buf);
        if !t.trim().is_empty() {
            let source: Vec<serde_json::Value> = t
                .trim_end()
                .split('\n')
                .map(|l| serde_json::Value::String(format!("{}\n", l)))
                .collect();
            cells.push(serde_json::json!({
                "cell_type": "markdown", "metadata": {}, "source": source
            }));
        }
    };
    let flush_code = |code_buf: &mut String, cells: &mut Vec<serde_json::Value>| {
        let c = std::mem::take(code_buf);
        if !c.trim().is_empty() {
            let source: Vec<serde_json::Value> = c
                .trim_end()
                .split('\n')
                .map(|l| serde_json::Value::String(format!("{}\n", l)))
                .collect();
            cells.push(serde_json::json!({
                "cell_type": "code", "metadata": {},
                "source": source, "outputs": [], "execution_count": null
            }));
        }
    };

    for event in Parser::new_ext(markdown, opts) {
        match event {
            Event::Start(Tag::CodeBlock(kind)) => {
                flush_md(&mut md_buf, &mut cells);
                in_code = true;
                code_lang = match &kind {
                    CodeBlockKind::Fenced(l) if !l.is_empty() => l.to_string(),
                    _ => "python".into(),
                };
            }
            Event::End(TagEnd::CodeBlock) => {
                flush_code(&mut code_buf, &mut cells);
                in_code = false;
            }
            Event::Start(Tag::Image { dest_url, .. }) => {
                in_image = true;
                img_url = dest_url.to_string();
                img_alt.clear();
            }
            Event::End(TagEnd::Image) => {
                in_image = false;
                md_buf.push_str(&format!("![{}]({})", img_alt, img_url));
                img_url.clear();
                img_alt.clear();
            }
            Event::Text(t) => {
                if in_image {
                    img_alt.push_str(&t);
                } else if in_code {
                    code_buf.push_str(&t);
                } else {
                    md_buf.push_str(&t);
                }
            }
            Event::Start(Tag::Heading { level, .. }) => {
                let n = match level {
                    HeadingLevel::H1 => 1,
                    HeadingLevel::H2 => 2,
                    HeadingLevel::H3 => 3,
                    _ => 4,
                };
                md_buf.push_str(&"#".repeat(n));
                md_buf.push(' ');
            }
            Event::End(TagEnd::Heading(_)) => md_buf.push_str("\n\n"),
            Event::End(TagEnd::Paragraph) => md_buf.push_str("\n\n"),
            Event::Start(Tag::Strong) => md_buf.push_str("**"),
            Event::End(TagEnd::Strong) => md_buf.push_str("**"),
            Event::Start(Tag::Emphasis) => md_buf.push('*'),
            Event::End(TagEnd::Emphasis) => md_buf.push('*'),
            Event::Start(Tag::Item) => md_buf.push_str("- "),
            Event::End(TagEnd::Item) => md_buf.push('\n'),
            Event::DisplayMath(m) => md_buf.push_str(&format!("\n$$\n{}\n$$\n\n", math_source(&m))),
            Event::InlineMath(m) => md_buf.push_str(&format!("${}$", math_source(&m))),
            Event::Code(c) => md_buf.push_str(&format!("`{}`", c)),
            Event::Rule => md_buf.push_str("\n---\n\n"),
            Event::SoftBreak => md_buf.push(' '),
            Event::HardBreak => md_buf.push('\n'),
            _ => {}
        }
    }
    flush_md(&mut md_buf, &mut cells);

    let notebook = serde_json::json!({
        "nbformat": 4, "nbformat_minor": 5,
        "metadata": {
            "kernelspec": { "name": "python3", "display_name": "Python 3", "language": "python" },
            "language_info": { "name": "python" }
        },
        "cells": cells
    });

    let json = serde_json::to_string_pretty(&notebook)
        .map_err(|e| format!("Jupyter JSON: {}", e))?;
    Ok(json.into_bytes())
}
