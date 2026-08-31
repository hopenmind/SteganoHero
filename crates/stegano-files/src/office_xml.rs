//! Namespace-aware DOCX / ODT import via `quick-xml`.
//!
//! Provenance: lifted from an upstream Markdown converter,
//! `crates/core/src/import_xml.rs` (the audit records this file as coupling-free
//! apart from the three `DocxSeg` / `render_docx_segs` / `omml_to_latex` symbols,
//! now homed in `crate::docx_common`). Pure `quick-xml`, no heavy dependency.
//!
//! These parsers recover run-level bold/italic, hyperlinks, nested lists, tables
//! (rendered as GFM) and OMML equations. On an empty or malformed result they
//! return `Err` naming the format: the caller raises rather than degrading (no
//! silent fallback to a partial read).

use std::collections::HashMap;

use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

use crate::docx_common::{omml_to_latex, render_docx_segs, DocxSeg};

// ── Shared helpers ───────────────────────────────────────────────────────────

fn attr_val(e: &BytesStart, key: &[u8]) -> Option<String> {
    for a in e.attributes().flatten() {
        if a.key.as_ref() == key {
            return a.unescape_value().ok().map(|v| v.into_owned());
        }
    }
    None
}

/// True when a `<w:b>` / `<w:i>` toggle is explicitly turned OFF.
fn attr_off(e: &BytesStart) -> bool {
    match attr_val(e, b"w:val") {
        Some(v) => matches!(v.as_str(), "false" | "0" | "off"),
        None => false,
    }
}

fn heading_level(style: &str) -> Option<u8> {
    let s = style.to_lowercase();
    if s == "title" {
        return Some(1);
    }
    if s == "subtitle" {
        return None;
    }
    if s.starts_with("heading") {
        return s
            .chars()
            .last()
            .and_then(|c| c.to_digit(10))
            .map(|n| (n as u8).clamp(1, 6));
    }
    None
}

fn ensure_blank(md: &mut String) {
    if md.is_empty() {
        return;
    }
    if md.ends_with("\n\n") {
    } else if md.ends_with('\n') {
        md.push('\n');
    } else {
        md.push_str("\n\n");
    }
}

/// Collapse runs of 3+ newlines to 2 and normalize the trailing newline.
fn collapse_blanks(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut nl = 0;
    for ch in s.chars() {
        if ch == '\n' {
            nl += 1;
            if nl <= 2 {
                out.push('\n');
            }
        } else {
            nl = 0;
            out.push(ch);
        }
    }
    format!("{}\n", out.trim_end())
}

fn sanitize_cell(s: &str) -> String {
    s.replace(['\r', '\n'], " ").replace('|', "\\|").trim().to_string()
}

/// Render accumulated rows as a GFM table (first row = header).
fn gfm_table(rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let cols = rows.iter().map(|r| r.len()).max().unwrap_or(0);
    if cols == 0 {
        return String::new();
    }
    let pad = |r: &Vec<String>| -> Vec<String> {
        let mut cells: Vec<String> = r.iter().map(|c| sanitize_cell(c)).collect();
        while cells.len() < cols {
            cells.push(String::new());
        }
        cells
    };
    let mut out = String::new();
    out.push_str("| ");
    out.push_str(&pad(&rows[0]).join(" | "));
    out.push_str(" |\n|");
    for _ in 0..cols {
        out.push_str(" --- |");
    }
    out.push('\n');
    for r in &rows[1..] {
        out.push_str("| ");
        out.push_str(&pad(r).join(" | "));
        out.push_str(" |\n");
    }
    out
}

// ── DOCX (word/document.xml) ─────────────────────────────────────────────────

/// Parse `word/_rels/document.xml.rels` into an `Id -> Target` map (hyperlinks).
pub(crate) fn parse_docx_rels(xml: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut reader = Reader::from_str(xml);
    loop {
        match reader.read_event() {
            Ok(Event::Empty(e)) | Ok(Event::Start(e)) => {
                if e.name().as_ref() == b"Relationship" {
                    if let (Some(id), Some(target)) =
                        (attr_val(&e, b"Id"), attr_val(&e, b"Target"))
                    {
                        map.insert(id, target);
                    }
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    map
}

pub(crate) fn docx_document_to_md(
    xml: &str,
    rels: &HashMap<String, String>,
) -> Result<String, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().check_end_names = false; // lenient: tolerate slightly imperfect files
    let mut md = String::new();

    let mut cur: Vec<DocxSeg> = Vec::new();
    let mut stack: Vec<Vec<DocxSeg>> = Vec::new();
    let mut link_url: Vec<Option<String>> = Vec::new();

    let mut pstyle = String::new();
    let mut is_list = false;
    let mut list_ilvl: usize = 0;
    let mut in_ppr = false;

    let mut run_b = false;
    let mut run_i = false;
    let mut in_rpr = false;
    let mut in_wt = false;

    let mut table_rows: Vec<Vec<String>> = Vec::new();
    let mut cur_row: Vec<String> = Vec::new();
    let mut in_cell = 0usize;

    let mut math_depth = 0usize;
    let mut math_start = 0usize;
    let mut math_display = false;

    loop {
        let ev = reader.read_event().map_err(|e| format!("DOCX XML: {}", e))?;
        match ev {
            Event::Eof => break,
            Event::Start(e) => {
                let name = e.name();
                let n = name.as_ref();
                if math_depth > 0 {
                    if n == b"m:oMath" || n == b"m:oMathPara" {
                        math_depth += 1;
                    }
                    continue;
                }
                match n {
                    b"w:p" => {
                        pstyle.clear();
                        is_list = false;
                        list_ilvl = 0;
                    }
                    b"w:pPr" => in_ppr = true,
                    b"w:pStyle" if in_ppr => {
                        if let Some(v) = attr_val(&e, b"w:val") {
                            pstyle = v;
                        }
                    }
                    b"w:numPr" if in_ppr => is_list = true,
                    b"w:ilvl" if in_ppr => {
                        if let Some(v) = attr_val(&e, b"w:val") {
                            list_ilvl = v.parse().unwrap_or(0);
                        }
                    }
                    b"w:r" => {
                        run_b = false;
                        run_i = false;
                    }
                    b"w:rPr" => in_rpr = true,
                    b"w:b" if in_rpr => run_b = !attr_off(&e),
                    b"w:i" if in_rpr => run_i = !attr_off(&e),
                    b"w:t" => in_wt = true,
                    b"w:hyperlink" => {
                        let url = attr_val(&e, b"r:id").and_then(|id| rels.get(&id).cloned());
                        stack.push(std::mem::take(&mut cur));
                        link_url.push(url);
                    }
                    b"w:tbl" => {
                        table_rows.clear();
                        cur_row.clear();
                    }
                    b"w:tr" => cur_row.clear(),
                    b"w:tc" => {
                        in_cell += 1;
                        stack.push(std::mem::take(&mut cur));
                    }
                    b"m:oMath" | b"m:oMathPara" => {
                        math_depth = 1;
                        math_display = n == b"m:oMathPara";
                        math_start = reader.buffer_position() as usize;
                    }
                    _ => {}
                }
            }
            Event::Empty(e) => {
                if math_depth > 0 {
                    continue;
                }
                match e.name().as_ref() {
                    b"w:pStyle" if in_ppr => {
                        if let Some(v) = attr_val(&e, b"w:val") {
                            pstyle = v;
                        }
                    }
                    b"w:numPr" if in_ppr => is_list = true,
                    b"w:b" if in_rpr => run_b = !attr_off(&e),
                    b"w:i" if in_rpr => run_i = !attr_off(&e),
                    b"w:br" => cur.push(DocxSeg::Text {
                        s: "  \n".into(),
                        bold: false,
                        italic: false,
                    }),
                    b"w:tab" => cur.push(DocxSeg::Text {
                        s: " ".into(),
                        bold: false,
                        italic: false,
                    }),
                    _ => {}
                }
            }
            Event::Text(e) => {
                if in_wt && math_depth == 0 {
                    let t = e.unescape().unwrap_or_default().into_owned();
                    cur.push(DocxSeg::Text {
                        s: t,
                        bold: run_b,
                        italic: run_i,
                    });
                }
            }
            Event::End(e) => {
                let name = e.name();
                let n = name.as_ref();
                if math_depth > 0 {
                    if n == b"m:oMath" || n == b"m:oMathPara" {
                        math_depth -= 1;
                        if math_depth == 0 {
                            let end_tag_len = n.len() + 3; // "</" + name + ">"
                            let before =
                                (reader.buffer_position() as usize).saturating_sub(end_tag_len);
                            let inner = xml.get(math_start..before).unwrap_or("");
                            let latex = omml_to_latex(inner);
                            cur.push(DocxSeg::Math {
                                latex,
                                display: math_display,
                            });
                        }
                    }
                    continue;
                }
                match n {
                    b"w:pPr" => in_ppr = false,
                    b"w:rPr" => in_rpr = false,
                    b"w:t" => in_wt = false,
                    b"w:hyperlink" => {
                        let inner = render_docx_segs(std::mem::take(&mut cur));
                        cur = stack.pop().unwrap_or_default();
                        let url = link_url.pop().flatten();
                        let text = inner.trim();
                        if !text.is_empty() {
                            let s = match url {
                                Some(u) if !u.is_empty() => format!("[{}]({})", text, u),
                                _ => text.to_string(),
                            };
                            cur.push(DocxSeg::Text {
                                s,
                                bold: false,
                                italic: false,
                            });
                        }
                    }
                    b"w:tc" => {
                        let cell = render_docx_segs(std::mem::take(&mut cur)).trim().to_string();
                        cur = stack.pop().unwrap_or_default();
                        in_cell = in_cell.saturating_sub(1);
                        cur_row.push(cell);
                    }
                    b"w:tr" => table_rows.push(std::mem::take(&mut cur_row)),
                    b"w:tbl" => {
                        ensure_blank(&mut md);
                        md.push_str(&gfm_table(&table_rows));
                        md.push('\n');
                        table_rows.clear();
                    }
                    b"w:p" => {
                        if in_cell > 0 {
                            cur.push(DocxSeg::Text {
                                s: " ".into(),
                                bold: false,
                                italic: false,
                            });
                        } else {
                            let text = render_docx_segs(std::mem::take(&mut cur));
                            let t = text.trim();
                            if let Some(lvl) = heading_level(&pstyle) {
                                if !t.is_empty() {
                                    ensure_blank(&mut md);
                                    for _ in 0..lvl {
                                        md.push('#');
                                    }
                                    md.push(' ');
                                    md.push_str(t);
                                    md.push_str("\n\n");
                                }
                            } else if is_list {
                                if !t.is_empty() {
                                    md.push_str(&"  ".repeat(list_ilvl));
                                    md.push_str("- ");
                                    md.push_str(t);
                                    md.push('\n');
                                }
                            } else if !t.is_empty() {
                                ensure_blank(&mut md);
                                md.push_str(t);
                                md.push_str("\n\n");
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    let out = collapse_blanks(&md);
    if out.trim().is_empty() {
        Err("DOCX quick-xml: empty result".into())
    } else {
        Ok(out)
    }
}

// ── ODT (content.xml) ────────────────────────────────────────────────────────

pub(crate) fn odt_content_to_md(xml: &str) -> Result<String, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().check_end_names = false; // lenient: tolerate slightly imperfect files
    let mut md = String::new();

    // Automatic-styles map: style-name -> (bold, italic).
    let mut styles: HashMap<String, (bool, bool)> = HashMap::new();
    let mut cur_style_name: Option<String> = None;

    let mut fmt_stack: Vec<(bool, bool)> = Vec::new();
    let mut in_text_block = false;
    let mut cur: Vec<DocxSeg> = Vec::new();
    let mut stack: Vec<Vec<DocxSeg>> = Vec::new();
    let mut heading_lvl: Option<u8> = None;
    let mut list_depth: usize = 0;

    let mut table_rows: Vec<Vec<String>> = Vec::new();
    let mut cur_row: Vec<String> = Vec::new();
    let mut in_cell = 0usize;

    let cur_fmt = |stk: &[(bool, bool)]| -> (bool, bool) {
        (stk.iter().any(|x| x.0), stk.iter().any(|x| x.1))
    };

    loop {
        let ev = reader.read_event().map_err(|e| format!("ODT XML: {}", e))?;
        match ev {
            Event::Eof => break,
            Event::Start(e) => match e.name().as_ref() {
                b"style:style" => {
                    cur_style_name = attr_val(&e, b"style:name");
                }
                b"style:text-properties" => {
                    if let Some(name) = &cur_style_name {
                        let bold = attr_val(&e, b"fo:font-weight")
                            .map(|v| v == "bold" || v == "bolder")
                            .unwrap_or(false);
                        let italic = attr_val(&e, b"fo:font-style")
                            .map(|v| v == "italic" || v == "oblique")
                            .unwrap_or(false);
                        styles.insert(name.clone(), (bold, italic));
                    }
                }
                b"text:h" => {
                    let level = attr_val(&e, b"text:outline-level")
                        .and_then(|s| s.parse::<u8>().ok())
                        .unwrap_or(1)
                        .clamp(1, 6);
                    heading_lvl = Some(level);
                    in_text_block = true;
                }
                b"text:p" => in_text_block = true,
                b"text:span" => {
                    let f = attr_val(&e, b"text:style-name")
                        .and_then(|sn| styles.get(&sn).copied())
                        .unwrap_or((false, false));
                    fmt_stack.push(f);
                }
                b"text:list" => list_depth += 1,
                b"table:table" => {
                    table_rows.clear();
                    cur_row.clear();
                }
                b"table:table-row" => cur_row.clear(),
                b"table:table-cell" => {
                    in_cell += 1;
                    stack.push(std::mem::take(&mut cur));
                    in_text_block = true;
                }
                _ => {}
            },
            Event::Empty(e) => match e.name().as_ref() {
                b"style:text-properties" => {
                    if let Some(name) = &cur_style_name {
                        let bold = attr_val(&e, b"fo:font-weight")
                            .map(|v| v == "bold" || v == "bolder")
                            .unwrap_or(false);
                        let italic = attr_val(&e, b"fo:font-style")
                            .map(|v| v == "italic" || v == "oblique")
                            .unwrap_or(false);
                        styles.insert(name.clone(), (bold, italic));
                    }
                }
                b"text:s" if in_text_block => cur.push(DocxSeg::Text {
                    s: " ".into(),
                    bold: false,
                    italic: false,
                }),
                b"text:tab" if in_text_block => cur.push(DocxSeg::Text {
                    s: " ".into(),
                    bold: false,
                    italic: false,
                }),
                b"text:line-break" if in_text_block => cur.push(DocxSeg::Text {
                    s: "  \n".into(),
                    bold: false,
                    italic: false,
                }),
                _ => {}
            },
            Event::Text(e) => {
                if in_text_block {
                    let t = e.unescape().unwrap_or_default().into_owned();
                    if !t.is_empty() {
                        let (b, i) = cur_fmt(&fmt_stack);
                        cur.push(DocxSeg::Text {
                            s: t,
                            bold: b,
                            italic: i,
                        });
                    }
                }
            }
            Event::End(e) => match e.name().as_ref() {
                b"style:style" => cur_style_name = None,
                b"text:span" => {
                    fmt_stack.pop();
                }
                b"text:h" => {
                    let text = render_docx_segs(std::mem::take(&mut cur));
                    let t = text.trim();
                    if let (Some(lvl), false) = (heading_lvl, t.is_empty()) {
                        ensure_blank(&mut md);
                        for _ in 0..lvl {
                            md.push('#');
                        }
                        md.push(' ');
                        md.push_str(t);
                        md.push_str("\n\n");
                    }
                    heading_lvl = None;
                    in_text_block = false;
                }
                b"text:p" => {
                    if in_cell > 0 {
                        cur.push(DocxSeg::Text {
                            s: " ".into(),
                            bold: false,
                            italic: false,
                        });
                    } else {
                        let text = render_docx_segs(std::mem::take(&mut cur));
                        let t = text.trim();
                        if !t.is_empty() {
                            if list_depth > 0 {
                                md.push_str(&"  ".repeat(list_depth.saturating_sub(1)));
                                md.push_str("- ");
                                md.push_str(t);
                                md.push('\n');
                            } else {
                                ensure_blank(&mut md);
                                md.push_str(t);
                                md.push_str("\n\n");
                            }
                        }
                    }
                    in_text_block = false;
                }
                b"text:list" => list_depth = list_depth.saturating_sub(1),
                b"table:table-cell" => {
                    let cell = render_docx_segs(std::mem::take(&mut cur)).trim().to_string();
                    cur = stack.pop().unwrap_or_default();
                    in_cell = in_cell.saturating_sub(1);
                    cur_row.push(cell);
                    in_text_block = false;
                }
                b"table:table-row" => table_rows.push(std::mem::take(&mut cur_row)),
                b"table:table" => {
                    ensure_blank(&mut md);
                    md.push_str(&gfm_table(&table_rows));
                    md.push('\n');
                    table_rows.clear();
                }
                _ => {}
            },
            _ => {}
        }
    }

    let out = collapse_blanks(&md);
    if out.trim().is_empty() {
        Err("ODT quick-xml: empty result".into())
    } else {
        Ok(out)
    }
}
