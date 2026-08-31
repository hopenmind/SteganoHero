//! Pure-Rust importers for the wider document set: EPUB, RTF, LaTeX, Org,
//! reStructuredText, MediaWiki, AsciiDoc, Typst source, Jupyter, BibTeX,
//! FictionBook, PowerPoint, email, CSV/TSV, and plain source code.
//!
//! Each function lowers one source format to a Markdown string, which is the
//! readable text the SteganoHero text tools (inspect, clean, conceal, provenance
//! mark, C2PA read) operate on.
//!
//! ## Provenance
//!
//! Copied, not depended upon, from an upstream Markdown converter,
//! `crates/core/src/import.rs` (the pure-Rust importer functions and their
//! private helpers). `mdall-core` is monolithic and drags in Typst and a headless
//! Chromium, so a crate dependency would blow the self-contained, small-binary
//! posture. The the upstream converter source function is named in a comment above each
//! importer. Re-sync from the upstream converter if that tree's copies move.
//!
//! ## Differences from the upstream converter (honest-failure contract, invariant 2)
//!
//! the upstream converter's importers take a file path; these take in-memory bytes/strings so
//! the file layer can operate on bytes the surfaces already hold. The container
//! importers (EPUB, PPTX) read the archive from a `Cursor` instead of a `File`.
//! Where the upstream converter would return an empty or header-only string for input that
//! carries no readable content, this layer raises by name instead: no path
//! returns empty text silently (invariant 2). The uniform empty-result guard
//! lives in [`crate::extract_text`]; the format-specific "nothing found" guards
//! (no EPUB chapters, no PPTX slides, no BibTeX entries, no CSV rows) live here.

use std::io::{Cursor, Read};

use crate::html::html_to_md;
use crate::md_common::{
    collapse_blank_lines, decode_entities, ensure_double_newline, extract_xml_attr, normalize_path,
    regex_replace_inline, replace_delim_pair, xml_tag_to_inline, MAX_ZIP_ENTRY_BYTES,
};

// ═════════════════════════════════════════════════════════════════════════════
// EPUB -> Markdown        (the upstream converter import.rs: epub_to_md)
// ═════════════════════════════════════════════════════════════════════════════

/// Convert EPUB bytes to Markdown.
///
/// Unpacks the ZIP, reads the OPF manifest + spine, converts each XHTML chapter
/// via [`html_to_md`], and joins them with horizontal rules. Raises by name if
/// the archive, its container descriptor, or its OPF is unreadable, or if no
/// readable chapter is found.
pub(crate) fn epub_to_md(bytes: &[u8]) -> Result<String, String> {
    let mut zip =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| format!("EPUB ZIP error: {}", e))?;

    // 1. Read META-INF/container.xml -> find OPF path
    let opf_path = {
        let mut s = String::new();
        zip.by_name("META-INF/container.xml")
            .map_err(|_| "EPUB: META-INF/container.xml missing".to_string())?
            .take(MAX_ZIP_ENTRY_BYTES)
            .read_to_string(&mut s)
            .map_err(|e| e.to_string())?;
        extract_xml_attr(&s, "full-path")
            .ok_or_else(|| "EPUB: could not find OPF path in container.xml".to_string())?
    };

    // Base directory of the OPF file (for resolving relative hrefs)
    let opf_dir = std::path::Path::new(&opf_path)
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or("")
        .to_string();

    // 2. Read OPF -> manifest + spine
    let opf = {
        let mut s = String::new();
        zip.by_name(&opf_path)
            .map_err(|e| format!("EPUB OPF not found: {}", e))?
            .take(MAX_ZIP_ENTRY_BYTES)
            .read_to_string(&mut s)
            .map_err(|e| e.to_string())?;
        s
    };

    let manifest = epub_manifest(&opf); // id -> href
    let spine = epub_spine(&opf); // ordered idrefs

    // 3. Convert chapters in spine order
    let mut parts: Vec<String> = Vec::new();
    for idref in &spine {
        let href = match manifest.get(idref.as_str()) {
            Some(h) => h,
            None => continue,
        };
        let chapter_path = if opf_dir.is_empty() {
            href.clone()
        } else {
            normalize_path(&format!("{}/{}", opf_dir, href))
        };
        let html = match zip.by_name(&chapter_path) {
            Ok(e) => {
                let mut s = String::new();
                e.take(MAX_ZIP_ENTRY_BYTES)
                    .read_to_string(&mut s)
                    .map_err(|e| e.to_string())?;
                s
            }
            Err(_) => continue,
        };
        if let Ok(md) = html_to_md(&html) {
            let trimmed = md.trim().to_string();
            if !trimmed.is_empty() {
                parts.push(trimmed);
            }
        }
    }

    if parts.is_empty() {
        return Err("EPUB: no readable HTML chapters found".into());
    }
    Ok(parts.join("\n\n---\n\n") + "\n")
}

fn epub_manifest(opf: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let mut pos = 0;
    while let Some(p) = opf[pos..].find("<item ") {
        let abs = pos + p;
        let end = opf[abs..].find('>').map(|e| abs + e + 1).unwrap_or(opf.len());
        let item = &opf[abs..end];
        if let (Some(id), Some(href)) = (extract_xml_attr(item, "id"), extract_xml_attr(item, "href"))
        {
            // Only add HTML/XHTML items
            let mt = extract_xml_attr(item, "media-type").unwrap_or_default();
            if mt.contains("html")
                || href.ends_with(".xhtml")
                || href.ends_with(".html")
                || href.ends_with(".htm")
            {
                map.insert(id, href);
            }
        }
        pos = end;
    }
    map
}

fn epub_spine(opf: &str) -> Vec<String> {
    let mut spine = Vec::new();
    let start = match opf.find("<spine") {
        Some(p) => p,
        None => return spine,
    };
    let end = opf[start..].find("</spine>").map(|e| start + e).unwrap_or(opf.len());
    let body = &opf[start..end];
    let mut pos = 0;
    while let Some(p) = body[pos..].find("<itemref ") {
        let abs = pos + p;
        let e = body[abs..].find('>').map(|x| abs + x + 1).unwrap_or(body.len());
        if let Some(idref) = extract_xml_attr(&body[abs..e], "idref") {
            spine.push(idref);
        }
        pos = e;
    }
    spine
}

// ═════════════════════════════════════════════════════════════════════════════
// RTF -> Markdown         (the upstream converter import.rs: rtf_to_md / rtf_strip)
// ═════════════════════════════════════════════════════════════════════════════

/// Convert RTF text to Markdown.
///
/// Best-effort: strips control words, maps `\b`/`\i` to `**`/`*`, maps `\pard` /
/// `\par` to paragraph breaks, decodes `\'xx` hex escapes. Complex RTF features
/// (tables, fields, embedded objects) are ignored.
pub(crate) fn rtf_to_md(rtf: &str) -> Result<String, String> {
    Ok(rtf_strip(rtf))
}

fn rtf_strip(rtf: &str) -> String {
    let mut out = String::new();
    let bytes = rtf.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut depth = 0i32; // { nesting depth
    let mut bold = false;
    let mut italic = false;
    let mut skip_group = 0i32; // depth at which we entered a skip group (\*)

    while i < len {
        match bytes[i] {
            b'{' => {
                depth += 1;
                i += 1;
            }
            b'}' => {
                if skip_group > 0 && depth <= skip_group {
                    skip_group = 0;
                }
                depth -= 1;
                i += 1;
            }
            b'\\' if i + 1 < len => {
                i += 1;
                if bytes[i].is_ascii_alphabetic() {
                    // Read control word
                    let start = i;
                    while i < len && bytes[i].is_ascii_alphabetic() {
                        i += 1;
                    }
                    // Optional numeric parameter (may be negative)
                    let param_start = i;
                    if i < len && bytes[i] == b'-' {
                        i += 1;
                    }
                    while i < len && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                    let param_end = i;
                    // Skip optional trailing space delimiter
                    if i < len && bytes[i] == b' ' {
                        i += 1;
                    }

                    let word = &rtf[start..param_start];
                    let param = &rtf[param_start..param_end];

                    if skip_group > 0 {
                        continue;
                    }

                    match word {
                        "b" => {
                            let on = param != "0";
                            if on && !bold {
                                bold = true;
                                if depth <= 1 {
                                    out.push_str("**");
                                }
                            }
                            if !on && bold {
                                bold = false;
                                if depth <= 1 {
                                    out.push_str("**");
                                }
                            }
                        }
                        "i" => {
                            let on = param != "0";
                            if on && !italic {
                                italic = true;
                                if depth <= 1 {
                                    out.push('*');
                                }
                            }
                            if !on && italic {
                                italic = false;
                                if depth <= 1 {
                                    out.push('*');
                                }
                            }
                        }
                        "par" | "pard" => {
                            if depth <= 1 {
                                out.push_str("\n\n");
                            }
                        }
                        "line" => {
                            if depth <= 1 {
                                out.push('\n');
                            }
                        }
                        "tab" => {
                            if depth <= 1 {
                                out.push('\t');
                            }
                        }
                        "bullet" => {
                            if depth <= 1 {
                                out.push_str("- ");
                            }
                        }
                        "sect" | "page" => {
                            if depth <= 1 {
                                out.push_str("\n---\n\n");
                            }
                        }
                        _ => {}
                    }
                } else if bytes[i] == b'\'' && i + 2 < len {
                    // \'xx hex-encoded character
                    let val = hex_nibble(bytes[i + 1]) * 16 + hex_nibble(bytes[i + 2]);
                    i += 3;
                    if skip_group > 0 {
                        continue;
                    }
                    // Windows-1252 -> approximate mapping for common chars
                    match val {
                        0x20..=0x7E => {
                            if depth <= 1 {
                                out.push(val as char);
                            }
                        }
                        0x85 => {
                            if depth <= 1 {
                                out.push('\u{2026}');
                            }
                        }
                        0x91 => {
                            if depth <= 1 {
                                out.push('\u{2018}');
                            }
                        }
                        0x92 => {
                            if depth <= 1 {
                                out.push('\u{2019}');
                            }
                        }
                        0x93 => {
                            if depth <= 1 {
                                out.push('"');
                            }
                        }
                        0x94 => {
                            if depth <= 1 {
                                out.push('"');
                            }
                        }
                        0x96 => {
                            if depth <= 1 {
                                out.push('-');
                            }
                        }
                        0x97 => {
                            if depth <= 1 {
                                out.push('-');
                            }
                        }
                        _ => {}
                    }
                } else if bytes[i] == b'*' {
                    // \* destination - skip everything until matching }
                    skip_group = depth;
                    i += 1;
                } else {
                    // Special characters: \\ \{ \} \- \_ \~ etc.
                    if skip_group == 0 && depth <= 1 {
                        match bytes[i] {
                            b'\\' => out.push('\\'),
                            b'{' => out.push('{'),
                            b'}' => out.push('}'),
                            b'-' => {} // optional hyphen
                            b'_' => out.push('\u{00A0}'), // non-breaking hyphen
                            b'~' => out.push('\u{00A0}'), // non-breaking space
                            b'\n' | b'\r' => out.push('\n'),
                            _ => {}
                        }
                    }
                    i += 1;
                }
            }
            b'\n' | b'\r' => {
                // Bare newlines in RTF have no semantic meaning
                i += 1;
            }
            b => {
                if skip_group == 0 && depth <= 1 {
                    out.push(b as char);
                }
                i += 1;
            }
        }
    }
    collapse_blank_lines(&out)
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// CSV / TSV -> Markdown table       (the upstream converter import.rs: csv_to_md)
// ═════════════════════════════════════════════════════════════════════════════

/// Convert CSV or TSV content to a GFM pipe table. First row is the header.
/// Delimiter auto-detected (tab vs comma). Raises by name on empty input.
pub(crate) fn csv_to_md(content: &str) -> Result<String, String> {
    let delimiter = if content.contains('\t') { '\t' } else { ',' };
    let rows: Vec<Vec<String>> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| parse_csv_row(line, delimiter))
        .collect();

    // the upstream converter returns Ok("") here; this layer raises by name (invariant 2).
    if rows.is_empty() {
        return Err("CSV: no rows found".into());
    }

    let col_count = rows.iter().map(|r| r.len()).max().unwrap_or(1);
    let mut md = String::new();

    // Header row
    md.push('|');
    for i in 0..col_count {
        md.push(' ');
        md.push_str(rows[0].get(i).map(|s| s.as_str()).unwrap_or(""));
        md.push_str(" |");
    }
    md.push('\n');

    // Separator row
    md.push('|');
    for _ in 0..col_count {
        md.push_str(" --- |");
    }
    md.push('\n');

    // Data rows
    for row in rows.iter().skip(1) {
        md.push('|');
        for i in 0..col_count {
            md.push(' ');
            md.push_str(row.get(i).map(|s| s.as_str()).unwrap_or(""));
            md.push_str(" |");
        }
        md.push('\n');
    }
    Ok(md)
}

fn parse_csv_row(line: &str, delim: char) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut in_q = false;
    for ch in line.chars() {
        if ch == '"' {
            in_q = !in_q;
        } else if ch == delim && !in_q {
            fields.push(std::mem::take(&mut field));
        } else {
            field.push(ch);
        }
    }
    fields.push(field);
    fields
}

// ═════════════════════════════════════════════════════════════════════════════
// Source code -> fenced Markdown block      (the upstream converter import.rs: code_to_md)
// ═════════════════════════════════════════════════════════════════════════════

/// Wrap source code in a fenced code block with the given language identifier.
pub(crate) fn code_to_md(content: &str, lang: &str) -> Result<String, String> {
    Ok(format!("```{}\n{}\n```\n", lang, content.trim_end()))
}

// ═════════════════════════════════════════════════════════════════════════════
// LaTeX (.tex) -> Markdown          (the upstream converter import.rs: tex_to_md)
// ═════════════════════════════════════════════════════════════════════════════

/// Collect the raw `\newcommand` / `\renewcommand` / `\providecommand` / `\def`
/// definition lines from a LaTeX source so they can be preserved verbatim.
fn extract_preamble_macros(content: &str) -> String {
    let mut out = String::new();
    for line in content.lines() {
        let t = line.trim_start();
        if t.starts_with("\\newcommand")
            || t.starts_with("\\renewcommand")
            || t.starts_with("\\providecommand")
            || t.starts_with("\\def")
        {
            out.push_str(line.trim_end());
            out.push('\n');
        }
    }
    out.trim_end().to_string()
}

/// Collapse newlines inside inline math to a single space so `$...$` never breaks
/// at a Markdown block boundary.
fn collapse_math_newlines(s: &str) -> String {
    if !s.contains('\n') && !s.contains('\r') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\n' || c == '\r' {
            while matches!(chars.peek(), Some(' ' | '\t' | '\n' | '\r')) {
                chars.next();
            }
            while out.ends_with(' ') || out.ends_with('\t') {
                out.pop();
            }
            if !out.is_empty() {
                out.push(' ');
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub(crate) fn tex_to_md(content: &str) -> Result<String, String> {
    let mut src = content;

    let preamble_macros = extract_preamble_macros(content);

    // Strip preamble (\documentclass ... \begin{document})
    if let Some(p) = src.find("\\begin{document}") {
        src = &src[p + 16..];
    }
    if let Some(p) = src.find("\\end{document}") {
        src = &src[..p];
    }

    let mut md = String::new();
    if !preamble_macros.is_empty() {
        md.push_str("<!-- mdall:latex-macros\n");
        md.push_str(&preamble_macros);
        md.push_str("\n-->\n\n");
    }
    let bytes = src.as_bytes();
    let len = src.len();
    let mut i = 0usize;

    while i < len {
        // LaTeX line comment
        if bytes[i] == b'%' {
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Inline math $...$  (not $$)
        if bytes[i] == b'$' {
            if i + 1 < len && bytes[i + 1] == b'$' {
                // Display $$ ... $$
                i += 2;
                let start = i;
                while i + 1 < len && !(bytes[i] == b'$' && bytes[i + 1] == b'$') {
                    i += 1;
                }
                let latex = src[start..i].trim();
                md.push_str(&format!("\n$$\n{}\n$$\n\n", latex));
                if i + 1 < len {
                    i += 2;
                }
                continue;
            } else {
                // Inline $...$
                i += 1;
                let start = i;
                while i < len && bytes[i] != b'$' {
                    i += 1;
                }
                let latex = collapse_math_newlines(&src[start..i]);
                md.push_str(&format!("${}$", latex));
                if i < len {
                    i += 1;
                }
                continue;
            }
        }
        if bytes[i] != b'\\' {
            match bytes[i] {
                // LaTeX grouping braces in prose - skip, don't emit
                b'{' | b'}' => {
                    i += 1;
                }
                // ASCII passes through directly.
                b if b < 0x80 => {
                    md.push(b as char);
                    i += 1;
                }
                // Non-ASCII: copy the WHOLE UTF-8 character (never byte-split).
                _ => {
                    let ch = src[i..].chars().next().unwrap_or('\u{FFFD}');
                    md.push(ch);
                    i += ch.len_utf8();
                }
            }
            continue;
        }
        // Control sequence
        i += 1;
        if i >= len {
            break;
        }

        if bytes[i].is_ascii_alphabetic() {
            let start = i;
            while i < len && bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            let word = &src[start..i];
            // Skip optional whitespace / *
            while i < len && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'*') {
                i += 1;
            }

            match word {
                "title" => {
                    let a = tex_braced(src, &mut i);
                    ensure_double_newline(&mut md);
                    md.push_str(&format!("# {}\n\n", a));
                }
                "author" => {
                    let a = tex_braced(src, &mut i);
                    md.push_str(&format!("*{}*\n\n", a));
                }
                "date" => {
                    let a = tex_braced(src, &mut i);
                    md.push_str(&format!("*{}*\n\n", a));
                }
                "section" => {
                    let a = tex_braced(src, &mut i);
                    md.push_str(&format!("\n## {}\n\n", a));
                }
                "subsection" => {
                    let a = tex_braced(src, &mut i);
                    md.push_str(&format!("\n### {}\n\n", a));
                }
                "subsubsection" => {
                    let a = tex_braced(src, &mut i);
                    md.push_str(&format!("\n#### {}\n\n", a));
                }
                "paragraph" => {
                    let a = tex_braced(src, &mut i);
                    md.push_str(&format!("\n##### {}\n\n", a));
                }
                "chapter" => {
                    let a = tex_braced(src, &mut i);
                    md.push_str(&format!("\n# {}\n\n", a));
                }
                "includegraphics" => {
                    // Skip optional [width=...]
                    if i < len && bytes[i] == b'[' {
                        while i < len && bytes[i] != b']' {
                            i += 1;
                        }
                        if i < len {
                            i += 1;
                        }
                    }
                    let path = tex_braced(src, &mut i);
                    md.push_str(&format!("\n![]({})\n\n", path));
                }
                "begin" => {
                    let env = tex_braced(src, &mut i);
                    // Skip optional argument [...]
                    if i < len && bytes[i] == b'[' {
                        while i < len && bytes[i] != b']' {
                            i += 1;
                        }
                        if i < len {
                            i += 1;
                        }
                    }
                    let env = env.trim().to_string();
                    match env.as_str() {
                        "equation" | "equation*" | "align" | "align*" | "gather" | "gather*"
                        | "multline" | "multline*" => {
                            let body = tex_until_end(src, &mut i, &env);
                            md.push_str(&format!("\n$$\n{}\n$$\n\n", body.trim()));
                        }
                        "itemize" => {
                            let body = tex_until_end(src, &mut i, "itemize");
                            md.push_str(&tex_list_to_md(&body, false));
                        }
                        "enumerate" => {
                            let body = tex_until_end(src, &mut i, "enumerate");
                            md.push_str(&tex_list_to_md(&body, true));
                        }
                        "verbatim" | "lstlisting" | "minted" | "alltt" => {
                            let body = tex_until_end(src, &mut i, &env);
                            md.push_str(&format!("\n```\n{}\n```\n\n", body.trim()));
                        }
                        "abstract" => {
                            let body = tex_until_end(src, &mut i, "abstract");
                            md.push_str("\n> **Abstract**\n>\n");
                            for para in body.split("\n\n") {
                                if para.trim().is_empty() {
                                    continue;
                                }
                                let converted = tex_fragment_to_md(para);
                                let flat = converted.split_whitespace().collect::<Vec<_>>().join(" ");
                                if !flat.is_empty() {
                                    md.push_str(&format!("> {}\n>\n", flat));
                                }
                            }
                            md.push('\n');
                        }
                        "figure" | "figure*" | "wrapfigure" => {
                            let body = tex_until_end(src, &mut i, &env);
                            let img = tex_extract_cmd(&body, "includegraphics");
                            let cap = tex_fragment_to_md(&tex_extract_cmd(&body, "caption"));
                            if !img.is_empty() {
                                md.push_str(&format!("\n![{}]({})\n\n", cap.trim(), img));
                            }
                        }
                        "table" | "table*" => {
                            let body = tex_until_end(src, &mut i, &env);
                            let cap = tex_fragment_to_md(&tex_extract_cmd(&body, "caption"));
                            if !cap.trim().is_empty() {
                                md.push_str(&format!("\n*Table: {}*\n\n", cap.trim()));
                            }
                        }
                        "tabular" | "tabular*" => {
                            tex_until_end(src, &mut i, &env);
                        }
                        "quote" | "quotation" | "displayquote" => {
                            let body = tex_until_end(src, &mut i, &env);
                            for para in body.split("\n\n") {
                                if para.trim().is_empty() {
                                    continue;
                                }
                                let converted = tex_fragment_to_md(para);
                                let flat = converted.split_whitespace().collect::<Vec<_>>().join(" ");
                                if !flat.is_empty() {
                                    md.push_str(&format!("> {}\n>\n", flat));
                                }
                            }
                            md.push('\n');
                        }
                        "document" => {}
                        "center" | "flushleft" | "flushright" | "minipage" | "multicols"
                        | "column" | "columns" | "frame" | "block" | "alertblock"
                        | "exampleblock" | "theorem" | "lemma" | "proof" | "corollary"
                        | "definition" | "remark" | "example" | "exercise" | "solution" => {
                            // Layout environments: process content in the main loop.
                            if i < len && bytes[i] == b'[' {
                                while i < len && bytes[i] != b']' {
                                    i += 1;
                                }
                                if i < len {
                                    i += 1;
                                }
                            }
                            if i < len && bytes[i] == b'{' {
                                while i < len && bytes[i] != b'}' {
                                    i += 1;
                                }
                                if i < len {
                                    i += 1;
                                }
                            }
                        }
                        _ => {
                            // Truly unknown env - skip it to avoid dumping raw LaTeX
                            let _body = tex_until_end(src, &mut i, &env);
                        }
                    }
                }
                "end" => {
                    tex_braced(src, &mut i);
                }
                "newline" | "linebreak" => md.push_str("  \n"),
                "newpage" | "clearpage" | "cleardoublepage" => md.push_str("\n---\n\n"),
                "maketitle" | "tableofcontents" | "listoffigures" | "listoftables" => {}
                "index" => {
                    tex_braced(src, &mut i);
                }
                "vspace" | "hspace" | "vskip" | "hskip" | "setlength" | "addtolength" => {
                    tex_braced(src, &mut i);
                }
                "noindent" | "indent" | "par" => {}
                "item" => {}
                _ => {
                    if let Some(piece) = tex_inline_word_to_md(word, src, &mut i) {
                        md.push_str(&piece);
                    }
                }
            }
        } else if bytes[i] == b'[' {
            // \[ display math
            i += 1;
            if let Some(end) = src[i..].find("\\]") {
                let latex = src[i..i + end].trim();
                md.push_str(&format!("\n$$\n{}\n$$\n\n", latex));
                i += end + 2;
            }
        } else if bytes[i] == b'(' {
            // \( inline math
            i += 1;
            if let Some(end) = src[i..].find("\\)") {
                let latex = collapse_math_newlines(src[i..i + end].trim());
                md.push_str(&format!("${}$", latex));
                i += end + 2;
            }
        } else {
            // Escaped specials, accent symbols (\'e, \"u, ...), spacing.
            md.push_str(&tex_inline_symbol_to_md(src, &mut i));
        }
    }

    Ok(collapse_blank_lines(&md))
}

/// Map a single-token LaTeX letter command (no braces) to its Unicode letter.
fn tex_simple_letter(word: &str) -> Option<&'static str> {
    Some(match word {
        "l" => "\u{0142}",
        "L" => "\u{0141}",
        "o" => "\u{00F8}",
        "O" => "\u{00D8}",
        "ss" => "\u{00DF}",
        "ae" => "\u{00E6}",
        "AE" => "\u{00C6}",
        "oe" => "\u{0153}",
        "OE" => "\u{0152}",
        "aa" => "\u{00E5}",
        "AA" => "\u{00C5}",
        "i" => "\u{0131}",
        "j" => "\u{0237}",
        _ => return None,
    })
}

/// Compose a LaTeX accent given the accent symbol and the base letter.
fn tex_accent_compose(accent: char, base: char) -> Option<char> {
    let mapped = match (accent, base) {
        ('\'', 'a') => '\u{00E1}',
        ('\'', 'e') => '\u{00E9}',
        ('\'', 'i') => '\u{00ED}',
        ('\'', 'o') => '\u{00F3}',
        ('\'', 'u') => '\u{00FA}',
        ('\'', 'y') => '\u{00FD}',
        ('\'', 'c') => '\u{0107}',
        ('\'', 'n') => '\u{0144}',
        ('\'', 's') => '\u{015B}',
        ('\'', 'z') => '\u{017A}',
        ('\'', 'A') => '\u{00C1}',
        ('\'', 'E') => '\u{00C9}',
        ('\'', 'I') => '\u{00CD}',
        ('\'', 'O') => '\u{00D3}',
        ('\'', 'U') => '\u{00DA}',
        ('`', 'a') => '\u{00E0}',
        ('`', 'e') => '\u{00E8}',
        ('`', 'i') => '\u{00EC}',
        ('`', 'o') => '\u{00F2}',
        ('`', 'u') => '\u{00F9}',
        ('`', 'A') => '\u{00C0}',
        ('`', 'E') => '\u{00C8}',
        ('`', 'O') => '\u{00D2}',
        ('^', 'a') => '\u{00E2}',
        ('^', 'e') => '\u{00EA}',
        ('^', 'i') => '\u{00EE}',
        ('^', 'o') => '\u{00F4}',
        ('^', 'u') => '\u{00FB}',
        ('^', 'A') => '\u{00C2}',
        ('^', 'E') => '\u{00CA}',
        ('^', 'O') => '\u{00D4}',
        ('"', 'a') => '\u{00E4}',
        ('"', 'e') => '\u{00EB}',
        ('"', 'i') => '\u{00EF}',
        ('"', 'o') => '\u{00F6}',
        ('"', 'u') => '\u{00FC}',
        ('"', 'y') => '\u{00FF}',
        ('"', 'A') => '\u{00C4}',
        ('"', 'O') => '\u{00D6}',
        ('"', 'U') => '\u{00DC}',
        ('~', 'a') => '\u{00E3}',
        ('~', 'n') => '\u{00F1}',
        ('~', 'o') => '\u{00F5}',
        ('~', 'A') => '\u{00C3}',
        ('~', 'N') => '\u{00D1}',
        ('~', 'O') => '\u{00D5}',
        ('c', 'c') => '\u{00E7}',
        ('c', 'C') => '\u{00C7}',
        _ => return None,
    };
    Some(mapped)
}

/// Read the base letter for an accent command.
fn tex_accent_base(src: &str, i: &mut usize) -> Option<char> {
    let bytes = src.as_bytes();
    let len = src.len();
    while *i < len && (bytes[*i] == b' ' || bytes[*i] == b'\t' || bytes[*i] == b'\n') {
        *i += 1;
    }
    if *i >= len {
        return None;
    }
    if bytes[*i] == b'{' {
        let inner = tex_braced(src, i);
        return inner.chars().next();
    }
    let ch = src[*i..].chars().next()?;
    *i += ch.len_utf8();
    Some(ch)
}

/// Handle a backslash-letter command that is inline (prose-level).
fn tex_inline_word_to_md(word: &str, src: &str, i: &mut usize) -> Option<String> {
    let s = match word {
        "textbf" | "mathbf" | "textsc" => format!("**{}**", tex_fragment_to_md(&tex_braced(src, i))),
        "textit" | "emph" | "textsl" => format!("*{}*", tex_fragment_to_md(&tex_braced(src, i))),
        "texttt" => format!("`{}`", tex_braced(src, i)),
        "underline" => format!("<u>{}</u>", tex_fragment_to_md(&tex_braced(src, i))),
        "textsuperscript" => format!("<sup>{}</sup>", tex_fragment_to_md(&tex_braced(src, i))),
        "textsubscript" => format!("<sub>{}</sub>", tex_fragment_to_md(&tex_braced(src, i))),
        "href" => {
            let url = tex_braced(src, i);
            let text = tex_fragment_to_md(&tex_braced(src, i));
            format!("[{}]({})", text, url)
        }
        "url" => format!("<{}>", tex_braced(src, i)),
        "footnote" => {
            let a = tex_braced(src, i);
            format!(" [^{}]", a.chars().take(20).collect::<String>())
        }
        "cite" | "citep" | "citet" | "citeauthor" | "citeyear" | "citealt" | "citealp"
        | "citenum" | "Citep" | "Citet" => {
            let bytes = src.as_bytes();
            let len = src.len();
            while *i < len && bytes[*i] == b'[' {
                while *i < len && bytes[*i] != b']' {
                    *i += 1;
                }
                if *i < len {
                    *i += 1;
                }
            }
            tex_braced(src, i);
            String::new()
        }
        "ref" | "eqref" | "autoref" | "cref" | "Cref" | "pageref" | "label" | "vref"
        | "nameref" => {
            tex_braced(src, i);
            String::new()
        }
        "LaTeX" => "LaTeX".to_string(),
        "TeX" => "TeX".to_string(),
        "dots" | "ldots" | "cdots" => "\u{2026}".to_string(),
        "textbackslash" => "\\".to_string(),
        "textquotedblleft" => "\u{201C}".to_string(),
        "textquotedblright" => "\u{201D}".to_string(),
        _ => {
            if let Some(letter) = tex_simple_letter(word) {
                return Some(letter.to_string());
            }
            if word == "c"
                || word == "v"
                || word == "u"
                || word == "H"
                || word == "r"
                || word == "d"
                || word == "b"
                || word == "k"
            {
                let bytes = src.as_bytes();
                if *i < src.len() && bytes[*i] == b'{' {
                    let base = tex_braced(src, i);
                    if let Some(bc) = base.chars().next() {
                        if let Some(c) = tex_accent_compose(word.chars().next().unwrap(), bc) {
                            return Some(c.to_string());
                        }
                        return Some(base);
                    }
                    return Some(String::new());
                }
                return None;
            }
            let bytes = src.as_bytes();
            if *i < src.len() && bytes[*i] == b'{' {
                return Some(tex_fragment_to_md(&tex_braced(src, i)));
            }
            return Some(String::new());
        }
    };
    Some(s)
}

/// Handle a backslash followed by a non-letter (escaped special, accent, break).
fn tex_inline_symbol_to_md(src: &str, i: &mut usize) -> String {
    let bytes = src.as_bytes();
    let b = bytes[*i];
    match b {
        b'\\' => {
            *i += 1;
            "  \n".to_string()
        }
        b'{' => {
            *i += 1;
            "{".to_string()
        }
        b'}' => {
            *i += 1;
            "}".to_string()
        }
        b'&' => {
            *i += 1;
            "&".to_string()
        }
        b'%' => {
            *i += 1;
            "%".to_string()
        }
        b'$' => {
            *i += 1;
            "$".to_string()
        }
        b'#' => {
            *i += 1;
            "#".to_string()
        }
        b'_' => {
            *i += 1;
            "_".to_string()
        }
        b'~' => {
            *i += 1;
            " ".to_string()
        }
        b' ' => {
            *i += 1;
            " ".to_string()
        }
        b'\'' | b'`' | b'^' | b'"' => {
            let accent = b as char;
            *i += 1;
            if let Some(base) = tex_accent_base(src, i) {
                if let Some(c) = tex_accent_compose(accent, base) {
                    c.to_string()
                } else {
                    base.to_string()
                }
            } else {
                String::new()
            }
        }
        b',' | b';' | b'!' | b'.' | b':' => {
            *i += 1;
            " ".to_string()
        }
        _ => {
            let ch = src[*i..].chars().next().unwrap_or('\u{FFFD}');
            *i += ch.len_utf8();
            ch.to_string()
        }
    }
}

/// Convert plain-text punctuation ligatures used by LaTeX in prose.
fn tex_apply_ligatures(s: &str) -> String {
    let s = s.replace("---", "\u{2014}");
    let s = s.replace("--", "\u{2013}");
    let s = s.replace("``", "\u{201C}");
    s.replace("''", "\u{201D}")
}

/// Convert a LaTeX prose fragment to Markdown (no preamble stripping).
pub(crate) fn tex_fragment_to_md(fragment: &str) -> String {
    let bytes = fragment.as_bytes();
    let len = fragment.len();
    let mut i = 0usize;
    let mut out = String::new();

    while i < len {
        // Inline math $...$ (not $$)
        if bytes[i] == b'$' {
            if i + 1 < len && bytes[i + 1] == b'$' {
                i += 2;
                let start = i;
                while i + 1 < len && !(bytes[i] == b'$' && bytes[i + 1] == b'$') {
                    i += 1;
                }
                let latex = fragment[start..i].trim();
                out.push_str(&format!("\n$$\n{}\n$$\n\n", latex));
                if i + 1 < len {
                    i += 2;
                }
                continue;
            }
            i += 1;
            let start = i;
            while i < len && bytes[i] != b'$' {
                i += 1;
            }
            out.push_str(&format!("${}$", collapse_math_newlines(&fragment[start..i])));
            if i < len {
                i += 1;
            }
            continue;
        }
        if bytes[i] != b'\\' {
            match bytes[i] {
                b'{' | b'}' => {
                    i += 1;
                }
                b if b < 0x80 => {
                    out.push(b as char);
                    i += 1;
                }
                _ => {
                    let ch = fragment[i..].chars().next().unwrap_or('\u{FFFD}');
                    out.push(ch);
                    i += ch.len_utf8();
                }
            }
            continue;
        }
        // Backslash command
        i += 1;
        if i >= len {
            break;
        }
        if bytes[i].is_ascii_alphabetic() {
            let start = i;
            while i < len && bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            let word = &fragment[start..i];
            while i < len && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'*') {
                i += 1;
            }
            if let Some(piece) = tex_inline_word_to_md(word, fragment, &mut i) {
                out.push_str(&piece);
            }
        } else {
            out.push_str(&tex_inline_symbol_to_md(fragment, &mut i));
        }
    }

    tex_apply_ligatures(&out)
}

fn tex_braced(src: &str, i: &mut usize) -> String {
    let bytes = src.as_bytes();
    let len = src.len();
    while *i < len && (bytes[*i] == b' ' || bytes[*i] == b'\n' || bytes[*i] == b'\t') {
        *i += 1;
    }
    if *i >= len || bytes[*i] != b'{' {
        return String::new();
    }
    *i += 1;
    let start = *i;
    let mut depth = 1i32;
    while *i < len {
        match bytes[*i] {
            b'{' => {
                depth += 1;
                *i += 1;
            }
            b'}' => {
                depth -= 1;
                *i += 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {
                *i += 1;
            }
        }
    }
    src[start..*i - 1].to_string()
}

fn tex_until_end(src: &str, i: &mut usize, env: &str) -> String {
    let end_marker = format!("\\end{{{}}}", env);
    let rest = &src[*i..];
    if let Some(p) = rest.find(&end_marker) {
        let body = rest[..p].to_string();
        *i += p + end_marker.len();
        body
    } else {
        *i = src.len();
        rest.to_string()
    }
}

fn tex_list_to_md(body: &str, ordered: bool) -> String {
    let mut md = String::new();
    let mut n = 0u32;
    for part in body.split("\\item") {
        let raw = part.trim();
        if raw.is_empty() {
            continue;
        }
        let t = if raw.starts_with('[') {
            if let Some(end) = raw.find(']') {
                raw[end + 1..].trim()
            } else {
                raw
            }
        } else {
            raw
        };
        if t.is_empty() {
            continue;
        }
        let converted = tex_fragment_to_md(t);
        let line: String = converted.split_whitespace().collect::<Vec<_>>().join(" ");
        if line.is_empty() {
            continue;
        }
        if ordered {
            n += 1;
            md.push_str(&format!("{}. {}\n", n, line));
        } else {
            md.push_str(&format!("- {}\n", line));
        }
    }
    md.push('\n');
    md
}

fn tex_extract_cmd(body: &str, cmd: &str) -> String {
    let search = format!("\\{}", cmd);
    if let Some(p) = body.find(&search) {
        let mut i = p + search.len();
        let bytes = body.as_bytes();
        if i < body.len() && bytes[i] == b'[' {
            while i < body.len() && bytes[i] != b']' {
                i += 1;
            }
            if i < body.len() {
                i += 1;
            }
        }
        return tex_braced(body, &mut i);
    }
    String::new()
}

// ═════════════════════════════════════════════════════════════════════════════
// Emacs Org-mode (.org) -> Markdown         (the upstream converter import.rs: org_to_md)
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn org_to_md(content: &str) -> Result<String, String> {
    let mut md = String::new();
    let mut in_src = false;
    let mut in_quote = false;
    let mut in_example = false;

    for line in content.lines() {
        let t = line.trim();
        let tl = t.to_lowercase();

        if tl.starts_with("#+title:") {
            md.push_str(&format!("# {}\n\n", t.splitn(2, ':').nth(1).unwrap_or("").trim()));
            continue;
        }
        if tl.starts_with("#+author:") {
            md.push_str(&format!("*{}*\n\n", t.splitn(2, ':').nth(1).unwrap_or("").trim()));
            continue;
        }
        if tl.starts_with("#+date:") {
            md.push_str(&format!("*{}*\n\n", t.splitn(2, ':').nth(1).unwrap_or("").trim()));
            continue;
        }
        if t.starts_with("#+") && !tl.starts_with("#+begin") && !tl.starts_with("#+end") {
            continue;
        }

        if tl.starts_with("#+begin_src") {
            let lang = t.split_whitespace().nth(1).unwrap_or("").to_lowercase();
            in_src = true;
            md.push_str(&format!("```{}\n", lang));
            continue;
        }
        if tl.starts_with("#+end_src") {
            in_src = false;
            md.push_str("```\n\n");
            continue;
        }
        if tl.starts_with("#+begin_example") || tl.starts_with("#+begin_verbatim") {
            in_example = true;
            md.push_str("```\n");
            continue;
        }
        if tl.starts_with("#+end_example") || tl.starts_with("#+end_verbatim") {
            in_example = false;
            md.push_str("```\n\n");
            continue;
        }
        if tl.starts_with("#+begin_quote") || tl.starts_with("#+begin_abstract") {
            in_quote = true;
            continue;
        }
        if tl.starts_with("#+end_quote") || tl.starts_with("#+end_abstract") {
            in_quote = false;
            md.push('\n');
            continue;
        }

        if in_src || in_example {
            md.push_str(line);
            md.push('\n');
            continue;
        }
        if in_quote {
            md.push_str(&format!("> {}\n", org_inline(t)));
            continue;
        }

        let stars = t.bytes().take_while(|&b| b == b'*').count();
        if stars > 0 && stars < t.len() && t.as_bytes()[stars] == b' ' {
            let title = t[stars + 1..]
                .trim()
                .split_whitespace()
                .take_while(|w| !w.starts_with(':'))
                .collect::<Vec<_>>()
                .join(" ");
            md.push_str(&format!("{} {}\n\n", "#".repeat(stars.min(6)), title));
            continue;
        }

        if t == "-----" || t == "---" {
            md.push_str("---\n\n");
            continue;
        }

        if t.starts_with("- ") || t.starts_with("+ ") {
            md.push_str(&format!("- {}\n", org_inline(&t[2..])));
            continue;
        }
        let digits = t.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digits > 0
            && t.len() > digits + 1
            && (t.as_bytes()[digits] == b'.' || t.as_bytes()[digits] == b')')
        {
            md.push_str(&format!("1. {}\n", org_inline(t[digits + 2..].trim())));
            continue;
        }

        if t.is_empty() {
            md.push('\n');
            continue;
        }
        md.push_str(&org_inline(t));
        md.push('\n');
    }

    Ok(collapse_blank_lines(&md))
}

fn org_inline(s: &str) -> String {
    let s = org_replace_span(s, '*', "**");
    let s = org_replace_span(&s, '/', "*");
    let s = org_replace_span(&s, '=', "`");
    let s = org_replace_span(&s, '~', "`");
    org_replace_links(&s)
}

fn org_replace_span(s: &str, delim: char, md: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == delim {
            let preceded_ok =
                i == 0 || chars[i - 1].is_whitespace() || "([{\"'".contains(chars[i - 1]);
            let followed_ok = i + 1 < chars.len() && !chars[i + 1].is_whitespace();

            if preceded_ok && followed_ok {
                if let Some(j) = chars[i + 1..].iter().position(|&c| c == delim) {
                    let content: String = chars[i + 1..i + 1 + j].iter().collect();
                    if !content.is_empty()
                        && !content.starts_with(' ')
                        && !content.ends_with(' ')
                        && !content.contains('\n')
                        && !content.contains("://")
                    {
                        out.push_str(md);
                        out.push_str(&content);
                        out.push_str(md);
                        i += j + 2;
                        continue;
                    }
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn org_replace_links(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(p) = rest.find("[[") {
        out.push_str(&rest[..p]);
        rest = &rest[p + 2..];
        if let Some(e) = rest.find("]]") {
            let inner = &rest[..e];
            rest = &rest[e + 2..];
            if let Some(sep) = inner.find("][") {
                out.push_str(&format!("[{}]({})", &inner[sep + 2..], &inner[..sep]));
            } else {
                out.push_str(&format!("[{}]({})", inner, inner));
            }
        }
    }
    out.push_str(rest);
    out
}

// ═════════════════════════════════════════════════════════════════════════════
// reStructuredText (.rst) -> Markdown       (the upstream converter import.rs: rst_to_md)
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn rst_to_md(content: &str) -> Result<String, String> {
    let lines: Vec<&str> = content.lines().collect();
    let n = lines.len();
    let mut md = String::new();
    let mut i = 0;
    let mut heading_levels: Vec<char> = Vec::new();
    let heading_chars = ['=', '-', '~', '^', '"', '\'', '#', '+'];

    while i < n {
        let line = lines[i];
        let t = line.trim();

        if i + 1 < n && !t.is_empty() {
            let next = lines[i + 1].trim();
            if !next.is_empty() {
                let uc = next.chars().next().unwrap_or(' ');
                if heading_chars.contains(&uc)
                    && next.len() >= t.len()
                    && next.chars().all(|c| c == uc)
                {
                    let level = if let Some(p) = heading_levels.iter().position(|&c| c == uc) {
                        p + 1
                    } else {
                        heading_levels.push(uc);
                        heading_levels.len()
                    };
                    md.push_str(&format!("{} {}\n\n", "#".repeat(level.min(6)), t));
                    i += 2;
                    continue;
                }
            }
        }

        if t.starts_with(".. ") {
            let dir = &t[3..];
            if dir.starts_with("math::") {
                let body = rst_collect_indented(&lines, &mut i);
                md.push_str(&format!("\n$$\n{}\n$$\n\n", body.trim()));
                continue;
            }
            if dir.starts_with("code-block::")
                || dir.starts_with("code::")
                || dir.starts_with("sourcecode::")
            {
                let lang = dir.splitn(2, "::").nth(1).unwrap_or("").trim();
                let body = rst_collect_indented(&lines, &mut i);
                md.push_str(&format!("```{}\n{}\n```\n\n", lang, body.trim_end()));
                continue;
            }
            if dir.starts_with("figure::") || dir.starts_with("image::") {
                let path = dir.splitn(2, "::").nth(1).unwrap_or("").trim();
                let body = rst_collect_indented(&lines, &mut i);
                let alt = body
                    .lines()
                    .find(|l| l.trim_start().starts_with(":alt:"))
                    .and_then(|l| l.splitn(3, ':').nth(2))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                md.push_str(&format!("![{}]({})\n\n", alt, path));
                continue;
            }
            if dir.starts_with("note::")
                || dir.starts_with("warning::")
                || dir.starts_with("tip::")
                || dir.starts_with("important::")
            {
                let kind = dir.splitn(2, "::").next().unwrap_or("note");
                let body = rst_collect_indented(&lines, &mut i);
                md.push_str(&format!("> **{}:** {}\n\n", kind, body.trim()));
                continue;
            }
            rst_collect_indented(&lines, &mut i);
            continue;
        }

        if t.ends_with("::") && t.len() > 2 {
            md.push_str(&format!("{}\n\n", rst_inline(&t[..t.len() - 2])));
            let body = rst_collect_indented(&lines, &mut i);
            md.push_str(&format!("```\n{}\n```\n\n", body.trim_end()));
            continue;
        }
        if t == "::" {
            let body = rst_collect_indented(&lines, &mut i);
            md.push_str(&format!("```\n{}\n```\n\n", body.trim_end()));
            continue;
        }

        if t.len() >= 4 && t.chars().all(|c| c == '-') {
            md.push_str("---\n\n");
            i += 1;
            continue;
        }

        if t.starts_with("- ") || t.starts_with("* ") {
            md.push_str(&format!("- {}\n", rst_inline(&t[2..])));
            i += 1;
            continue;
        }
        let dig = t.bytes().take_while(|b| b.is_ascii_digit()).count();
        if dig > 0 && t.len() > dig + 1 && t.as_bytes()[dig] == b'.' {
            md.push_str(&format!("1. {}\n", rst_inline(t[dig + 1..].trim())));
            i += 1;
            continue;
        }
        if t.starts_with("#. ") {
            md.push_str(&format!("1. {}\n", rst_inline(&t[3..])));
            i += 1;
            continue;
        }

        if t.is_empty() {
            md.push('\n');
        } else {
            md.push_str(&rst_inline(t));
            md.push('\n');
        }
        i += 1;
    }

    Ok(collapse_blank_lines(&md))
}

fn rst_collect_indented(lines: &[&str], i: &mut usize) -> String {
    *i += 1;
    while *i < lines.len() && lines[*i].trim().is_empty() {
        *i += 1;
    }
    let mut body = String::new();
    while *i < lines.len() {
        let l = lines[*i];
        if l.trim().is_empty() {
            body.push('\n');
            *i += 1;
        } else if l.starts_with("   ") || l.starts_with('\t') {
            let stripped = if l.starts_with("   ") { &l[3..] } else { &l[1..] };
            body.push_str(stripped);
            body.push('\n');
            *i += 1;
        } else {
            break;
        }
    }
    body
}

fn rst_inline(s: &str) -> String {
    let s = regex_replace_inline(s, "``", "``", "`", "`");
    let s = regex_replace_inline(&s, ":math:`", "`", "$", "$");
    let s = regex_replace_inline(&s, ":code:`", "`", "`", "`");
    rst_strip_role(&s)
}

fn rst_strip_role(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(p) = rest.find(":`") {
        let before = &rest[..p];
        if let Some(colon) = before.rfind(':') {
            let role = &before[colon + 1..];
            if role.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
                out.push_str(&before[..colon]);
                rest = &rest[p + 2..];
                if let Some(e) = rest.find('`') {
                    out.push_str(&rest[..e]);
                    rest = &rest[e + 1..];
                }
                continue;
            }
        }
        out.push_str(&rest[..p + 2]);
        rest = &rest[p + 2..];
    }
    out.push_str(rest);
    out
}

// ═════════════════════════════════════════════════════════════════════════════
// MediaWiki (.wiki) -> Markdown             (the upstream converter import.rs: wiki_to_md)
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn wiki_to_md(content: &str) -> Result<String, String> {
    let mut md = String::new();
    let mut in_pre = false;

    for line in content.lines() {
        let t = line.trim();

        if t.starts_with('=') && t.ends_with('=') {
            let level = t.bytes().take_while(|&b| b == b'=').count().min(6);
            let end = t.len().saturating_sub(level);
            if end > level {
                let title = t[level..end].trim();
                if !title.is_empty() {
                    md.push_str(&format!("{} {}\n\n", "#".repeat(level), title));
                    continue;
                }
            }
        }

        if t.starts_with("<pre") || t.starts_with("<syntaxhighlight") || t.starts_with("<source") {
            in_pre = true;
            md.push_str("```\n");
            continue;
        }
        if t.starts_with("</pre>")
            || t.starts_with("</syntaxhighlight>")
            || t.starts_with("</source>")
        {
            in_pre = false;
            md.push_str("```\n\n");
            continue;
        }
        if in_pre {
            md.push_str(line);
            md.push('\n');
            continue;
        }

        if t == "----" {
            md.push_str("---\n\n");
            continue;
        }
        if t.starts_with("* ") {
            md.push_str(&format!("- {}\n", wiki_inline(&t[2..])));
            continue;
        }
        if t.starts_with("** ") {
            md.push_str(&format!("  - {}\n", wiki_inline(&t[3..])));
            continue;
        }
        if t.starts_with("# ") {
            md.push_str(&format!("1. {}\n", wiki_inline(&t[2..])));
            continue;
        }
        if t.starts_with(": ") {
            md.push_str(&format!("> {}\n", wiki_inline(&t[2..])));
            continue;
        }

        if t.is_empty() {
            md.push('\n');
        } else {
            md.push_str(&wiki_inline(t));
            md.push('\n');
        }
    }

    Ok(collapse_blank_lines(&md))
}

fn wiki_inline(s: &str) -> String {
    let s = replace_delim_pair(s, "'''", "**");
    let s = replace_delim_pair(&s, "''", "*");
    let s = xml_tag_to_inline(&s, "math", "$", "$");
    let s = xml_tag_to_inline(&s, "code", "`", "`");
    let s = xml_tag_to_inline(&s, "ref", "", ""); // strip ref tags
    let s = replace_wiki_links(&s);
    strip_templates(&s)
}

fn replace_wiki_links(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(p) = rest.find("[[") {
        out.push_str(&rest[..p]);
        rest = &rest[p + 2..];
        if let Some(e) = rest.find("]]") {
            let inner = &rest[..e];
            rest = &rest[e + 2..];
            if let Some(sep) = inner.find('|') {
                out.push_str(&format!("[{}]({})", &inner[sep + 1..], &inner[..sep]));
            } else {
                out.push_str(&format!("[{}]({})", inner, inner));
            }
        }
    }
    out.push_str(rest);
    out
}

fn strip_templates(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(p) = rest.find("{{") {
        out.push_str(&rest[..p]);
        rest = &rest[p + 2..];
        if let Some(e) = rest.find("}}") {
            rest = &rest[e + 2..];
        }
    }
    out.push_str(rest);
    out
}

// ═════════════════════════════════════════════════════════════════════════════
// AsciiDoc (.adoc) -> Markdown              (the upstream converter import.rs: adoc_to_md)
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn adoc_to_md(content: &str) -> Result<String, String> {
    let mut md = String::new();
    let mut in_src = false;
    let mut in_quote = false;
    let mut in_list = false;
    let mut in_stem = false;
    let mut stem_buf = String::new();
    let mut next_lang = String::new();

    for line in content.lines() {
        let t = line.trim();

        if t.starts_with("[source") {
            let lang = t
                .split(',')
                .nth(1)
                .or_else(|| t.split('.').nth(1))
                .unwrap_or("")
                .trim_end_matches(']')
                .trim();
            next_lang = lang.to_string();
            continue;
        }
        if t == "[stem]" || t == "[latexmath]" || t == "[asciimath]" {
            in_stem = true;
            continue;
        }

        if t == "----" {
            if in_src {
                md.push_str("```\n\n");
                in_src = false;
            } else {
                md.push_str(&format!("```{}\n", std::mem::take(&mut next_lang)));
                in_src = true;
            }
            continue;
        }
        if t == "====" {
            if in_quote {
                md.push('\n');
                in_quote = false;
            } else {
                in_quote = true;
            }
            continue;
        }
        if t == "++++" {
            if in_stem {
                in_stem = false;
                md.push_str(&format!("\n$$\n{}\n$$\n\n", stem_buf.trim()));
                stem_buf.clear();
            }
            continue;
        }
        if t == "...." {
            if in_src {
                md.push_str("```\n\n");
                in_src = false;
            } else {
                md.push_str("```\n");
                in_src = true;
            }
            continue;
        }

        if in_src {
            md.push_str(line);
            md.push('\n');
            continue;
        }
        if in_stem {
            stem_buf.push_str(line);
            stem_buf.push('\n');
            continue;
        }
        if in_quote {
            md.push_str(&format!("> {}\n", adoc_inline(t)));
            continue;
        }

        if t.starts_with(':') && t.len() > 1 {
            let rest = &t[1..];
            if let Some(end) = rest.find(':') {
                let attr_name = &rest[..end];
                let name_clean = attr_name.trim_start_matches('!');
                if !name_clean.is_empty()
                    && name_clean.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                {
                    continue;
                }
            }
        }

        let eq_count = t.bytes().take_while(|&b| b == b'=').count();
        if eq_count > 0 && eq_count < t.len() && t.as_bytes()[eq_count] == b' ' {
            let title = t[eq_count + 1..].trim();
            md.push_str(&format!("{} {}\n\n", "#".repeat(eq_count.min(6)), title));
            in_list = false;
            continue;
        }

        if t == "'''" || (t.len() >= 3 && t.chars().all(|c| c == '-')) {
            md.push_str("---\n\n");
            continue;
        }

        let star_count = t.bytes().take_while(|&b| b == b'*').count();
        if star_count > 0 && star_count < t.len() && t.as_bytes()[star_count] == b' ' {
            let indent = "  ".repeat(star_count.saturating_sub(1));
            md.push_str(&format!("{}- {}\n", indent, adoc_inline(t[star_count + 1..].trim())));
            in_list = true;
            continue;
        }
        let dot_count = t.bytes().take_while(|&b| b == b'.').count();
        if dot_count > 0 && dot_count < t.len() && t.as_bytes()[dot_count] == b' ' {
            let indent = "  ".repeat(dot_count.saturating_sub(1));
            md.push_str(&format!("{}1. {}\n", indent, adoc_inline(t[dot_count + 1..].trim())));
            in_list = true;
            continue;
        }

        let mut handled = false;
        for admon in &["NOTE", "TIP", "WARNING", "IMPORTANT", "CAUTION"] {
            let tag = format!("{}:", admon);
            if t.starts_with(&tag) {
                md.push_str(&format!("> **{}:** {}\n\n", admon, adoc_inline(t[tag.len()..].trim())));
                handled = true;
                break;
            }
        }
        if handled {
            continue;
        }

        if t.starts_with("image::") {
            let rest = &t[7..];
            let path = rest.split('[').next().unwrap_or("").trim();
            let alt = rest
                .find('[')
                .and_then(|p| rest[p + 1..].find(']').map(|e| &rest[p + 1..p + 1 + e]))
                .unwrap_or("");
            md.push_str(&format!("![{}]({})\n\n", alt, path));
            in_list = false;
            continue;
        }

        if t.is_empty() {
            if in_list {
                md.push('\n');
                in_list = false;
            } else {
                md.push('\n');
            }
        } else {
            md.push_str(&adoc_inline(t));
            md.push('\n');
        }
    }

    Ok(collapse_blank_lines(&md))
}

fn adoc_inline(s: &str) -> String {
    let s = if s.contains("**") {
        regex_replace_inline(s, "**", "**", "**", "**")
    } else {
        replace_delim_pair(s, "*", "**")
    };
    let s = replace_delim_pair(&s, "_", "*");
    let s = regex_replace_inline(&s, "stem:[", "]", "$", "$");
    let s = regex_replace_inline(&s, "latexmath:[", "]", "$", "$");
    replace_adoc_links(&s)
}

fn replace_adoc_links(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(p) = rest.find("link:") {
        out.push_str(&rest[..p]);
        rest = &rest[p + 5..];
        let url_end = rest.find('[').unwrap_or(rest.len());
        let url = rest[..url_end].to_string();
        if url_end < rest.len() {
            rest = &rest[url_end + 1..];
            if let Some(rb) = rest.find(']') {
                out.push_str(&format!("[{}]({})", &rest[..rb], url));
                rest = &rest[rb + 1..];
                continue;
            }
        }
        out.push_str("link:");
        out.push_str(&url);
    }
    out.push_str(rest);
    out
}

// ═════════════════════════════════════════════════════════════════════════════
// Typst source (.typ) -> Markdown           (the upstream converter import.rs: typ_to_md)
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn typ_to_md(content: &str) -> Result<String, String> {
    let mut md = String::new();
    let mut in_raw = false;

    for line in content.lines() {
        let t = line.trim();

        if t.starts_with("```") && !in_raw {
            in_raw = true;
            md.push_str(line);
            md.push('\n');
            continue;
        }
        if t == "```" && in_raw {
            in_raw = false;
            md.push_str("```\n\n");
            continue;
        }
        if in_raw {
            md.push_str(line);
            md.push('\n');
            continue;
        }

        if t.starts_with("#set ")
            || t.starts_with("#show ")
            || t.starts_with("#let ")
            || t.starts_with("#import")
            || t.starts_with("#include")
            || t.starts_with("#align(")
            || t.starts_with("#v(")
            || t.starts_with("#pagebreak")
        {
            continue;
        }

        let eq_count = t.bytes().take_while(|&b| b == b'=').count();
        if eq_count > 0 && eq_count < t.len() && t.as_bytes()[eq_count] == b' ' {
            let title = t[eq_count + 1..].trim();
            if !title.is_empty() {
                md.push_str(&format!("{} {}\n\n", "#".repeat(eq_count.min(6)), title));
                continue;
            }
        }

        if t.starts_with("#line(") {
            md.push_str("---\n\n");
            continue;
        }

        if t.starts_with("- ") {
            md.push_str(&format!("- {}\n", typ_inline(&t[2..])));
            continue;
        }
        if t.starts_with("+ ") {
            md.push_str(&format!("1. {}\n", typ_inline(&t[2..])));
            continue;
        }

        if t.is_empty() {
            md.push('\n');
        } else {
            md.push_str(&typ_inline(t));
            md.push('\n');
        }
    }

    Ok(collapse_blank_lines(&md))
}

fn typ_inline(s: &str) -> String {
    let s = replace_delim_pair(s, "*", "**");
    let s = replace_delim_pair(&s, "_", "*");
    let s = regex_replace_inline(&s, "#strike[", "]", "~~", "~~");
    typ_replace_link(&s)
}

fn typ_replace_link(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(p) = rest.find("#link(\"") {
        out.push_str(&rest[..p]);
        rest = &rest[p + 7..];
        if let Some(eu) = rest.find('"') {
            let url = rest[..eu].to_string();
            rest = &rest[eu + 1..];
            if rest.starts_with(")[") {
                rest = &rest[2..];
                if let Some(et) = rest.find(']') {
                    out.push_str(&format!("[{}]({})", &rest[..et], url));
                    rest = &rest[et + 1..];
                    continue;
                }
            }
            out.push_str(&format!("<{}>", url));
        }
    }
    out.push_str(rest);
    out
}

// ═════════════════════════════════════════════════════════════════════════════
// Jupyter Notebook (.ipynb) -> Markdown     (the upstream converter import.rs: ipynb_to_md)
// ═════════════════════════════════════════════════════════════════════════════

/// Convert a Jupyter Notebook JSON string to Markdown.
/// Markdown cells -> as-is. Code cells -> fenced code blocks with language.
/// Raises by name on invalid JSON or a missing `cells` array.
pub(crate) fn ipynb_to_md(content: &str) -> Result<String, String> {
    let v: serde_json::Value =
        serde_json::from_str(content).map_err(|e| format!("Jupyter JSON error: {}", e))?;

    let lang = v["metadata"]["kernelspec"]["language"]
        .as_str()
        .unwrap_or("python")
        .to_string();

    let cells = v["cells"]
        .as_array()
        .ok_or("Jupyter: 'cells' array not found")?;

    let mut md = String::new();

    for cell in cells {
        let cell_type = cell["cell_type"].as_str().unwrap_or("raw");
        let source = ipynb_join_source(&cell["source"]);

        match cell_type {
            "markdown" => {
                md.push_str(&source);
                if !source.ends_with('\n') {
                    md.push('\n');
                }
                md.push('\n');
            }
            "code" => {
                let src = source.trim_end();
                if !src.is_empty() {
                    md.push_str(&format!("```{}\n{}\n```\n\n", lang, src));
                }
                if let Some(outputs) = cell["outputs"].as_array() {
                    for out in outputs {
                        let ot = out["output_type"].as_str().unwrap_or("");
                        let text = match ot {
                            "stream" => ipynb_join_source(&out["text"]),
                            "execute_result" | "display_data" => {
                                ipynb_join_source(&out["data"]["text/plain"])
                            }
                            _ => String::new(),
                        };
                        if !text.trim().is_empty() {
                            md.push_str(&format!("```\n{}\n```\n\n", text.trim_end()));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok(md)
}

fn ipynb_join_source(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(a) => a.iter().filter_map(|x| x.as_str()).collect(),
        _ => String::new(),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// BibTeX (.bib) -> Markdown reference list   (the upstream converter import.rs: bib_to_md)
// ═════════════════════════════════════════════════════════════════════════════

/// Convert BibTeX source to a Markdown reference list. Raises by name if no
/// entry is parsed (the upstream converter returns a header-only string; invariant 2).
pub(crate) fn bib_to_md(content: &str) -> Result<String, String> {
    let mut md = String::new();
    let mut i = 0usize;
    let bytes = content.as_bytes();
    let len = content.len();
    let mut entries = 0usize;

    md.push_str("# References\n\n");

    while i < len {
        if bytes[i] != b'@' {
            i += 1;
            continue;
        }
        i += 1;
        let ts = i;
        while i < len && bytes[i] != b'{' && bytes[i] != b'(' {
            i += 1;
        }
        let entry_type = content[ts..i].trim().to_lowercase();
        if entry_type == "string" || entry_type == "preamble" || entry_type == "comment" {
            if i < len {
                i += 1;
            }
            let mut d = 1i32;
            while i < len && d > 0 {
                match bytes[i] {
                    b'{' => d += 1,
                    b'}' => d -= 1,
                    _ => {}
                }
                i += 1;
            }
            continue;
        }
        if i >= len {
            break;
        }
        i += 1; // skip {
        while i < len && bytes[i] != b',' {
            i += 1;
        }
        if i < len {
            i += 1;
        }

        let mut fields: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let depth = 1i32;
        loop {
            while i < len && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= len || depth <= 0 {
                break;
            }
            if bytes[i] == b'}' {
                i += 1;
                break;
            }

            let fs = i;
            while i < len && bytes[i] != b'=' && bytes[i] != b'}' {
                i += 1;
            }
            if i >= len || bytes[i] == b'}' {
                i += 1;
                break;
            }
            let fname = content[fs..i].trim().to_lowercase();
            i += 1; // skip =
            while i < len && bytes[i].is_ascii_whitespace() {
                i += 1;
            }

            let fval = if i < len && bytes[i] == b'{' {
                i += 1;
                let vs = i;
                let mut d = 1;
                while i < len {
                    match bytes[i] {
                        b'{' => d += 1,
                        b'}' => {
                            d -= 1;
                            if d == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                let v = content[vs..i].replace('\n', " ");
                if i < len {
                    i += 1;
                }
                v
            } else if i < len && bytes[i] == b'"' {
                i += 1;
                let vs = i;
                while i < len && bytes[i] != b'"' {
                    i += 1;
                }
                let v = content[vs..i].to_string();
                if i < len {
                    i += 1;
                }
                v
            } else {
                let vs = i;
                while i < len && bytes[i] != b',' && bytes[i] != b'}' {
                    i += 1;
                }
                content[vs..i].trim().to_string()
            };
            while i < len && (bytes[i] == b',' || bytes[i].is_ascii_whitespace()) {
                i += 1;
            }

            if !fname.trim().is_empty() {
                fields.insert(fname.trim().to_string(), fval.trim().to_string());
            }
        }

        let author = fields.get("author").cloned().unwrap_or_default();
        let title = fields.get("title").cloned().unwrap_or_default();
        let year = fields.get("year").cloned().unwrap_or_default();
        let venue = fields
            .get("journal")
            .or_else(|| fields.get("booktitle"))
            .cloned()
            .unwrap_or_default();
        let pages = fields.get("pages").cloned().unwrap_or_default();
        let volume = fields.get("volume").cloned().unwrap_or_default();
        let url = fields.get("url").cloned().unwrap_or_default();
        let doi = fields.get("doi").cloned().unwrap_or_default();

        let author_fmt = bib_format_authors(&author);
        let mut entry = format!("- **{}**", title);
        if !author_fmt.is_empty() {
            entry.push_str(&format!(" - {}", author_fmt));
        }
        if !year.is_empty() {
            entry.push_str(&format!(" ({})", year));
        }
        if !venue.is_empty() {
            entry.push_str(&format!(". *{}*", venue));
        }
        if !volume.is_empty() {
            entry.push_str(&format!(", **{}**", volume));
        }
        if !pages.is_empty() {
            entry.push_str(&format!(", pp. {}", pages.replace("--", "-")));
        }
        if !doi.is_empty() {
            entry.push_str(&format!(". [doi:{}](https://doi.org/{})", doi, doi));
        } else if !url.is_empty() {
            entry.push_str(&format!(". [Link]({})", url));
        }
        entry.push('\n');
        md.push_str(&entry);
        entries += 1;
    }

    if entries == 0 {
        return Err("BibTeX: no entries found".into());
    }
    Ok(md)
}

fn bib_format_authors(authors: &str) -> String {
    authors
        .split(" and ")
        .map(|a| {
            let a = a.trim();
            if let Some(comma) = a.find(',') {
                let last = a[..comma].trim();
                let first = a[comma + 1..].trim();
                let init = first.chars().next().map(|c| format!("{}.", c)).unwrap_or_default();
                format!("{} {}", last, init)
            } else {
                a.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

// ═════════════════════════════════════════════════════════════════════════════
// FictionBook (.fb2) -> Markdown            (the upstream converter import.rs: fb2_to_md)
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn fb2_to_md(xml: &str) -> Result<String, String> {
    let mut md = String::new();
    let bytes = xml.as_bytes();
    let len = xml.len();
    let mut pos = 0usize;
    let mut in_body = false;
    let mut bold = false;
    let mut italic = false;
    let mut section_depth = 0u32;

    while pos < len {
        if bytes[pos] != b'<' {
            if in_body {
                let start = pos;
                while pos < len && bytes[pos] != b'<' {
                    pos += 1;
                }
                md.push_str(&decode_entities(&xml[start..pos]));
            } else {
                while pos < len && bytes[pos] != b'<' {
                    pos += 1;
                }
            }
            continue;
        }
        pos += 1;
        let ts = pos;
        while pos < len && bytes[pos] != b'>' {
            pos += 1;
        }
        let tag = &xml[ts..pos];
        if pos < len {
            pos += 1;
        }

        let closing = tag.starts_with('/');
        let tag_body = if closing { tag[1..].trim() } else { tag.trim() };
        let tag_name = tag_body
            .split(|c: char| !c.is_alphanumeric() && c != ':')
            .next()
            .unwrap_or("")
            .to_lowercase();

        match tag_name.as_str() {
            "body" => {
                in_body = !closing;
            }
            "section" => {
                if !closing {
                    section_depth += 1;
                } else {
                    section_depth = section_depth.saturating_sub(1);
                    md.push('\n');
                }
            }
            "title" => {
                if !closing {
                    md.push_str(&"#".repeat(section_depth.max(1).min(6) as usize));
                    md.push(' ');
                } else {
                    md.push_str("\n\n");
                }
            }
            "p" => {
                if closing {
                    md.push_str("\n\n");
                }
            }
            "strong" | "b" => {
                if !closing {
                    bold = true;
                    md.push_str("**");
                } else if bold {
                    bold = false;
                    md.push_str("**");
                }
            }
            "emphasis" | "i" | "em" => {
                if !closing {
                    italic = true;
                    md.push('*');
                } else if italic {
                    italic = false;
                    md.push('*');
                }
            }
            "code" => {
                if !closing {
                    md.push('`');
                } else {
                    md.push('`');
                }
            }
            "poem" => {
                if !closing {
                    md.push_str("\n> ");
                } else {
                    md.push_str("\n\n");
                }
            }
            "epigraph" => {
                if !closing {
                    md.push_str("\n> ");
                } else {
                    md.push_str("\n\n");
                }
            }
            "cite" => {
                if !closing {
                    md.push_str("\n> ");
                } else {
                    md.push_str("\n\n");
                }
            }
            "v" => {
                md.push_str("  \n");
            }
            "subtitle" => {
                if !closing {
                    md.push('*');
                } else {
                    md.push_str("*\n\n");
                }
            }
            "empty-line" => {
                md.push_str("\n\n");
            }
            _ => {}
        }
    }

    let out = collapse_blank_lines(&md);
    // the upstream converter trusts the parse; a document with no <body> yields empty here.
    // Raise by name rather than hand back nothing (invariant 2).
    if out.trim().is_empty() {
        return Err("FictionBook: no readable body text found".into());
    }
    Ok(out)
}

// ═════════════════════════════════════════════════════════════════════════════
// PowerPoint (.pptx) -> Markdown            (the upstream converter import.rs: pptx_to_md)
// ═════════════════════════════════════════════════════════════════════════════

/// Convert PPTX bytes to Markdown, one section per slide. Raises by name if the
/// archive is unreadable or carries no slides.
pub(crate) fn pptx_to_md(bytes: &[u8]) -> Result<String, String> {
    let mut zip =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| format!("PPTX ZIP: {}", e))?;

    // Find all slide*.xml files (exclude _rels)
    let mut slide_names: Vec<String> = (0..zip.len())
        .filter_map(|i| {
            let name = zip.by_index(i).ok()?.name().to_string();
            if name.starts_with("ppt/slides/slide")
                && name.ends_with(".xml")
                && !name.contains("_rels")
            {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    slide_names.sort_by_key(|n| {
        n.trim_start_matches("ppt/slides/slide")
            .trim_end_matches(".xml")
            .parse::<u32>()
            .unwrap_or(0)
    });

    // the upstream converter returns Ok("") for a slide-less archive; raise by name here.
    if slide_names.is_empty() {
        return Err("PPTX: no slides found".into());
    }

    let mut md = String::new();

    for (idx, slide_name) in slide_names.iter().enumerate() {
        let xml = {
            let entry = zip
                .by_name(slide_name)
                .map_err(|e| format!("PPTX slide: {}", e))?;
            let mut s = String::new();
            entry
                .take(MAX_ZIP_ENTRY_BYTES)
                .read_to_string(&mut s)
                .map_err(|e| e.to_string())?;
            s
        };

        let (title, bullets) = pptx_extract_slide(&xml);
        let num = idx + 1;

        if !title.is_empty() {
            md.push_str(&format!("## Slide {}: {}\n\n", num, title));
        } else {
            md.push_str(&format!("## Slide {}\n\n", num));
        }

        for b in &bullets {
            let t = b.trim();
            if !t.is_empty() {
                if bullets.len() > 1 {
                    md.push_str(&format!("- {}\n", t));
                } else {
                    md.push_str(&format!("{}\n\n", t));
                }
            }
        }
        md.push('\n');
    }

    Ok(collapse_blank_lines(&md))
}

fn pptx_extract_slide(xml: &str) -> (String, Vec<String>) {
    let mut title = String::new();
    let mut bullets: Vec<String> = Vec::new();
    let mut ph_type = String::new();
    let mut in_ph = false;
    let mut para_text = String::new();
    let bytes = xml.as_bytes();
    let len = xml.len();
    let mut pos = 0;

    while pos < len {
        if bytes[pos] != b'<' {
            pos += 1;
            continue;
        }
        pos += 1;
        let ts = pos;
        while pos < len && bytes[pos] != b'>' {
            pos += 1;
        }
        let tag = &xml[ts..pos];
        if pos < len {
            pos += 1;
        }
        let closing = tag.starts_with('/');
        let tag_body = if closing { tag[1..].trim() } else { tag.trim() };
        let tag_name = tag_body
            .split(|c: char| !c.is_alphanumeric() && c != ':')
            .next()
            .unwrap_or("")
            .to_lowercase();

        match tag_name.as_str() {
            "p:ph" => {
                ph_type = extract_xml_attr(tag, "type").unwrap_or_default();
                in_ph = true;
            }
            "p:sp" => {
                if closing {
                    let t = para_text.trim().to_string();
                    if !t.is_empty() {
                        if ph_type == "title" || ph_type == "ctrTitle" {
                            title = t;
                        } else {
                            bullets.push(t);
                        }
                    }
                    para_text.clear();
                    in_ph = false;
                }
            }
            "a:t" => {
                if !closing && in_ph {
                    let end = xml[pos..].find("</a:t>").unwrap_or(0);
                    para_text.push_str(&decode_entities(&xml[pos..pos + end]));
                }
            }
            "a:p" => {
                if closing && !para_text.trim().is_empty() {
                    para_text.push('\n');
                }
            }
            _ => {}
        }
    }

    (title, bullets)
}

// ═════════════════════════════════════════════════════════════════════════════
// Email (.eml) -> Markdown                  (the upstream converter import.rs: eml_to_md)
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn eml_to_md(content: &str) -> Result<String, String> {
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut current_key = String::new();
    let mut current_val = String::new();
    let mut in_body = false;
    let mut body_lines: Vec<&str> = Vec::new();

    for line in content.lines() {
        if !in_body {
            if line.is_empty() {
                if !current_key.is_empty() {
                    headers.push((
                        std::mem::take(&mut current_key),
                        std::mem::take(&mut current_val),
                    ));
                }
                in_body = true;
                continue;
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                current_val.push(' ');
                current_val.push_str(line.trim());
            } else if let Some(colon) = line.find(':') {
                if !current_key.is_empty() {
                    headers.push((
                        std::mem::take(&mut current_key),
                        std::mem::take(&mut current_val),
                    ));
                }
                current_key = line[..colon].trim().to_string();
                current_val = line[colon + 1..].trim().to_string();
            }
        } else {
            body_lines.push(line);
        }
    }
    if !current_key.is_empty() {
        headers.push((current_key, current_val));
    }

    // the upstream converter trusts the input is an email; a file with no headers at all is
    // not an email, so raise by name rather than emit an empty shell (invariant 2).
    if headers.is_empty() {
        return Err("email: no headers found".into());
    }

    let subject = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("subject"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("(no subject)");
    let mut md = format!("# {}\n\n", subject);

    for (key, val) in &headers {
        let k = key.to_lowercase();
        if k == "from" || k == "to" || k == "cc" || k == "date" || k == "reply-to" {
            md.push_str(&format!("**{}:** {}  \n", key, val));
        }
    }
    md.push_str("\n---\n\n");

    let body = body_lines.join("\n");
    let ct = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.to_lowercase())
        .unwrap_or_default();

    if ct.contains("text/html") {
        if let Ok(body_md) = html_to_md(&body) {
            md.push_str(&body_md);
        } else {
            md.push_str(&body);
        }
    } else {
        md.push_str(&body);
    }

    Ok(md)
}
