//! Shared string/XML helpers for the copied importers.
//!
//! Provenance: lifted from an upstream Markdown converter,
//! `crates/core/src/import.rs` (the private helpers shared across its importer
//! functions: `collapse_blank_lines`, `decode_entities`, `ensure_double_newline`,
//! `extract_xml_attr`, `normalize_path`, and the inline markup helpers
//! `replace_delim_pair`, `regex_replace_inline`, `xml_tag_to_inline`). Pure
//! string processing, no external crate. Collected here so every copied importer
//! in [`crate::import`] shares one copy. Re-sync from the upstream converter if that tree's
//! copies move.
//!
//! `html.rs` keeps its own private copies of the HTML-specific subset because it
//! was copied earlier as a self-contained unit; that duplication is intentional
//! (each copied module names its own provenance) and harmless.

/// Hard cap on bytes read from any single ZIP archive entry (zip-bomb guard).
/// A malformed or hostile container advertising a huge (or streaming) entry is
/// bounded here, so import degrades to a truncated read instead of exhausting
/// memory. 128 MiB is far above any legitimate document part / EPUB chapter.
pub(crate) const MAX_ZIP_ENTRY_BYTES: u64 = 128 << 20;

/// Collapse runs of blank lines to at most two, and normalise the trailing
/// newline. Applied as the final pass of most importers.
pub(crate) fn collapse_blank_lines(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut blank = 0u32;
    for line in s.lines() {
        if line.trim().is_empty() {
            blank += 1;
            if blank <= 2 {
                out.push('\n');
            }
        } else {
            blank = 0;
            out.push_str(line);
            out.push('\n');
        }
    }
    let result = out.trim_start_matches('\n').trim_end_matches('\n');
    format!("{}\n", result)
}

/// Decode the common named/numeric HTML/XML entities to their characters.
pub(crate) fn decode_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
        .replace("&mdash;", "-")
        .replace("&ndash;", "-")
        .replace("&hellip;", "...")
        .replace("&copy;", "\u{00A9}") // ©
        .replace("&reg;", "\u{00AE}") // ®
        .replace("&trade;", "\u{2122}") // ™
}

/// Ensure the buffer ends with a blank line (two newlines), used before block
/// elements so paragraphs and headings separate cleanly.
pub(crate) fn ensure_double_newline(md: &mut String) {
    if md.ends_with("\n\n") || md.is_empty() {
        return;
    }
    if md.ends_with('\n') {
        md.push('\n');
    } else {
        md.push_str("\n\n");
    }
}

/// Read the value of an XML attribute (double- or single-quoted) from a tag or
/// element string. Returns the first match found.
pub(crate) fn extract_xml_attr(xml: &str, attr: &str) -> Option<String> {
    for pat in [format!("{}=\"", attr), format!("{}='", attr)] {
        if let Some(p) = xml.find(&pat) {
            let start = p + pat.len();
            let close = if pat.ends_with('"') { '"' } else { '\'' };
            if let Some(end) = xml[start..].find(close) {
                return Some(xml[start..start + end].to_string());
            }
        }
    }
    None
}

/// Normalise a relative archive path, resolving `.` and `..` segments. Used to
/// resolve EPUB chapter hrefs against the OPF directory.
pub(crate) fn normalize_path(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            ".." => {
                parts.pop();
            }
            "." | "" => {}
            s => parts.push(s),
        }
    }
    parts.join("/")
}

// ── Shared inline conversion helpers (used by org / rst / wiki / adoc / typ) ──

/// Replace each `delim`-delimited span with `md` markers (e.g. `'''x'''` -> `**x**`).
pub(crate) fn replace_delim_pair(s: &str, delim: &str, md: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(p) = rest.find(delim) {
        out.push_str(&rest[..p]);
        rest = &rest[p + delim.len()..];
        out.push_str(md);
    }
    out.push_str(rest);
    out
}

/// Replace each `open`..`close` span with `md_open`..`md_close` (e.g. an RST
/// ``` ``code`` ``` role to a Markdown code span).
pub(crate) fn regex_replace_inline(
    s: &str,
    open: &str,
    close: &str,
    md_open: &str,
    md_close: &str,
) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(p) = rest.find(open) {
        out.push_str(&rest[..p]);
        rest = &rest[p + open.len()..];
        if let Some(e) = rest.find(close) {
            out.push_str(md_open);
            out.push_str(&rest[..e]);
            out.push_str(md_close);
            rest = &rest[e + close.len()..];
        }
    }
    out.push_str(rest);
    out
}

/// Replace each `<tag>..</tag>` span with `open_md`..`close_md` (e.g. a MediaWiki
/// `<math>` element to a Markdown math span).
pub(crate) fn xml_tag_to_inline(s: &str, tag: &str, open_md: &str, close_md: &str) -> String {
    let open_tag = format!("<{}>", tag);
    let close_tag = format!("</{}>", tag);
    let mut out = String::new();
    let mut rest = s;
    while let Some(p) = rest.find(&open_tag) {
        out.push_str(&rest[..p]);
        rest = &rest[p + open_tag.len()..];
        if let Some(e) = rest.find(&close_tag) {
            out.push_str(open_md);
            out.push_str(&rest[..e]);
            out.push_str(close_md);
            rest = &rest[e + close_tag.len()..];
        }
    }
    out.push_str(rest);
    out
}
