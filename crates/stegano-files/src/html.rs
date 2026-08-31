//! HTML to Markdown text extraction (hand-rolled tag scanner).
//!
//! Provenance: lifted from an upstream Markdown converter,
//! `crates/core/src/import.rs` (`html_to_md` and its private helpers). Pure
//! string processing, no external crate. Inline `$...$` / `\(...\)` math is
//! passed through unchanged; script/style/head content is dropped.

/// Convert an HTML string to Markdown.
///
/// Preserves: headings (h1-h6), bold, italic, code/pre, ordered/unordered
/// lists, blockquotes, horizontal rules, images.  Inline `$...$` / `\(...\)` /
/// `$$...$$` / `\[...\]` math is passed through unchanged.
pub(crate) fn html_to_md(html: &str) -> Result<String, String> {
    // Pre-process: extract math before general HTML stripping
    let html = preprocess_html_math(html);
    let mut md     = String::with_capacity(html.len());
    let html = html.as_str();
    let bytes      = html.as_bytes();
    let len        = bytes.len();
    let mut pos    = 0usize;

    // Visibility flags
    let mut in_head   = false;
    let mut in_script = false;
    let mut in_style  = false;
    let mut in_pre    = false;

    // Inline formatting
    let mut bold_depth   = 0i32;
    let mut italic_depth = 0i32;
    let mut code_depth   = 0i32;

    // Block state
    let mut list_stack: Vec<bool> = Vec::new(); // true = ordered
    let mut ord_counters: Vec<u64> = Vec::new();

    while pos < len {
        if bytes[pos] != b'<' {
            // Text node
            if !in_head && !in_script && !in_style {
                let start = pos;
                while pos < len && bytes[pos] != b'<' { pos += 1; }
                let raw  = &html[start..pos];
                let text = decode_entities(raw);
                if in_pre {
                    md.push_str(&text);
                } else {
                    // Collapse internal whitespace, trim edges
                    let collapsed = collapse_ws(&text);
                    if !collapsed.is_empty() {
                        md.push_str(&collapsed);
                    }
                }
            } else {
                while pos < len && bytes[pos] != b'<' { pos += 1; }
            }
            continue;
        }

        // Parse tag: <...>
        pos += 1; // skip <
        if pos >= len { break; }

        // Handle comments <!-- ... -->
        if html[pos..].starts_with("!--") {
            if let Some(end) = html[pos..].find("-->") {
                pos += end + 3;
            } else {
                pos = len;
            }
            continue;
        }

        let tag_content_start = pos;
        // Find closing >
        let mut in_quotes = false;
        let mut quote_char = b'"';
        while pos < len {
            if in_quotes {
                if bytes[pos] == quote_char { in_quotes = false; }
            } else if bytes[pos] == b'"' || bytes[pos] == b'\'' {
                in_quotes = true;
                quote_char = bytes[pos];
            } else if bytes[pos] == b'>' {
                break;
            }
            pos += 1;
        }
        let tag_inner = &html[tag_content_start..pos];
        if pos < len { pos += 1; } // skip >

        let closing  = tag_inner.starts_with('/');
        let self_closing = tag_inner.ends_with('/');
        let tag_body = if closing { tag_inner[1..].trim() } else { tag_inner.trim() };
        let tag_name = tag_body.split(|c: char| !c.is_alphanumeric())
                               .next().unwrap_or("").to_lowercase();

        match tag_name.as_str() {
            // Invisible sections
            "head"   => { in_head   = !closing; }
            "script" => { in_script = !closing; }
            "style"  => { in_style  = !closing; }

            // Headings
            "h1"|"h2"|"h3"|"h4"|"h5"|"h6" => {
                let level = (tag_name.as_bytes()[1] - b'0') as usize;
                if !closing {
                    ensure_double_newline(&mut md);
                    for _ in 0..level { md.push('#'); }
                    md.push(' ');
                } else {
                    md.push_str("\n\n");
                }
            }

            // Block elements
            "p" | "div" | "article" | "section" | "main" | "header" | "footer" | "aside" => {
                if !closing && !self_closing {
                    ensure_double_newline(&mut md);
                } else if closing {
                    ensure_double_newline(&mut md);
                }
            }
            "br" => { md.push_str("  \n"); }
            "hr" => { ensure_double_newline(&mut md); md.push_str("---\n\n"); }

            // Inline formatting
            "strong" | "b" => {
                if !closing { bold_depth += 1; md.push_str("**"); }
                else if bold_depth > 0 { bold_depth -= 1; md.push_str("**"); }
            }
            "em" | "i" => {
                if !closing { italic_depth += 1; md.push('*'); }
                else if italic_depth > 0 { italic_depth -= 1; md.push('*'); }
            }
            "u" => {} // underline: no MD equivalent, skip markers
            "s" | "del" | "strike" => {
                if !closing { md.push_str("~~"); } else { md.push_str("~~"); }
            }
            "sup" => {
                if !closing { md.push_str("<sup>"); } else { md.push_str("</sup>"); }
            }
            "sub" => {
                if !closing { md.push_str("<sub>"); } else { md.push_str("</sub>"); }
            }

            // Code
            "code" => {
                if !closing {
                    code_depth += 1;
                    if !in_pre { md.push('`'); }
                } else if code_depth > 0 {
                    code_depth -= 1;
                    if !in_pre { md.push('`'); }
                }
            }
            "pre" => {
                if !closing {
                    in_pre = true;
                    // Try to extract language from class="language-xxx"
                    let lang = extract_attr(tag_inner, "class")
                        .and_then(|c| c.strip_prefix("language-").map(str::to_string))
                        .unwrap_or_default();
                    ensure_double_newline(&mut md);
                    md.push_str("```");
                    md.push_str(&lang);
                    md.push('\n');
                } else {
                    in_pre = false;
                    if !md.ends_with('\n') { md.push('\n'); }
                    md.push_str("```\n\n");
                }
            }

            // Lists
            "ul" => {
                if !closing {
                    list_stack.push(false);
                    ord_counters.push(0);
                    ensure_newline(&mut md);
                } else {
                    list_stack.pop();
                    ord_counters.pop();
                    md.push('\n');
                }
            }
            "ol" => {
                if !closing {
                    list_stack.push(true);
                    ord_counters.push(0);
                    ensure_newline(&mut md);
                } else {
                    list_stack.pop();
                    ord_counters.pop();
                    md.push('\n');
                }
            }
            "li" => {
                if !closing {
                    let depth  = list_stack.len().saturating_sub(1);
                    let indent = "  ".repeat(depth);
                    let is_ord = list_stack.last().copied().unwrap_or(false);
                    if is_ord {
                        if let Some(n) = ord_counters.last_mut() { *n += 1; }
                        let n = ord_counters.last().copied().unwrap_or(1);
                        md.push_str(&format!("{}{}. ", indent, n));
                    } else {
                        md.push_str(&format!("{}- ", indent));
                    }
                } else {
                    ensure_newline(&mut md);
                }
            }

            // Blockquote
            "blockquote" => {
                if !closing {
                    ensure_double_newline(&mut md);
                    md.push_str("> ");
                } else {
                    md.push_str("\n\n");
                }
            }

            // Links
            "a" => {
                // Simplified: emit link text only (href reconstruction requires
                // lookahead state machine - out of scope for best-effort import)
            }

            // Images
            "img" => {
                let src = extract_attr(tag_inner, "src").unwrap_or_default();
                let alt = extract_attr(tag_inner, "alt").unwrap_or_default();
                md.push_str(&format!("![{}]({})", alt, src));
            }

            // Table (basic: emit pipe-separated text)
            "table" => {}
            "tr" => {
                if !closing { md.push('\n'); } else { md.push_str(" |"); }
            }
            "th" | "td" => {
                if !closing { md.push_str("| "); }
            }

            // Ignore everything else
            _ => {}
        }
    }

    Ok(collapse_blank_lines(&fix_gfm_tables(&md)))
}

/// Insert the GFM delimiter row (`| --- | --- |`) after the header of each pipe
/// table that lacks one. The streaming HTML table handler emits header and body
/// rows but no delimiter, so without this the output is not valid GFM.
fn fix_gfm_tables(md: &str) -> String {
    let is_row = |l: &str| l.trim_start().starts_with('|');
    let is_delim = |l: &str| {
        let t = l.trim();
        t.starts_with('|') && t.chars().all(|c| matches!(c, '|' | '-' | ':' | ' '))
            && t.contains('-')
    };
    let lines: Vec<&str> = md.lines().collect();
    let mut out: Vec<String> = Vec::with_capacity(lines.len() + 4);
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        // Start of a table block: a row whose previous emitted line is not a row.
        let prev_is_row = out.last().map(|l| is_row(l)).unwrap_or(false);
        if is_row(line) && !prev_is_row {
            out.push(line.to_string());
            // If the next line is not already a delimiter, synthesize one.
            let next_is_delim = lines.get(i + 1).map(|l| is_delim(l)).unwrap_or(false);
            if !next_is_delim {
                let cols = line.split('|').filter(|c| !c.trim().is_empty()).count().max(1);
                let delim = format!("|{}", " --- |".repeat(cols));
                out.push(delim);
            }
            i += 1;
            continue;
        }
        out.push(line.to_string());
        i += 1;
    }
    out.join("\n")
}

// ── HTML math pre-processing ─────────────────────────────────────────────────

/// Replace math blocks in HTML with plain `$...$` / `$$...$$` before tag stripping.
///
/// Handles (in priority order):
///   1. KaTeX/MathJax3 `<annotation encoding="application/x-tex">` - exact LaTeX source
///   2. MathJax2 `<script type="math/tex">` / `type="math/tex; mode=display"`
///   3. Pandoc `<span class="math inline">` / `class="math display"`
fn preprocess_html_math(html: &str) -> String {
    let _out  = String::with_capacity(html.len());
    let rest = html;

    // Pass 1: replace <math>...</math> blocks (KaTeX/MathML). Extract
    // <annotation encoding="application/x-tex">LATEX</annotation> and drop the
    // surrounding <math>...</math> block.
    let mut buf = String::with_capacity(rest.len());
    let mut scan = rest;
    while let Some(p) = scan.find("<math") {
        buf.push_str(&scan[..p]);
        scan = &scan[p..];
        // Find end of <math...>
        if let Some(open_end) = scan.find('>') {
            let math_open = &scan[..open_end+1];
            scan = &scan[open_end+1..];
            // Find matching </math>
            if let Some(close) = scan.find("</math>") {
                let math_body = &scan[..close];
                scan = &scan[close+7..];
                // Try to extract LaTeX annotation
                let latex_opt = extract_math_annotation(math_body);
                // Determine display vs inline from opening tag
                let is_display = math_open.contains("display") || math_open.contains("block");
                if let Some(latex) = latex_opt {
                    if is_display {
                        buf.push_str(&format!("\n$$\n{}\n$$\n", latex));
                    } else {
                        buf.push_str(&format!("${}$", latex));
                    }
                } else {
                    // No annotation - fall back to extracting <mi><mn><mo> text
                    let text = extract_mathml_text(math_body);
                    if !text.trim().is_empty() {
                        if is_display { buf.push_str(&format!("\n$$\n{}\n$$\n", text.trim())); }
                        else { buf.push_str(&format!("${}$", text.trim())); }
                    }
                }
            } else {
                buf.push_str(math_open);
            }
        } else {
            buf.push_str(scan);
            scan = "";
        }
    }
    buf.push_str(scan);
    let html = buf;

    // Pass 2: MathJax2 <script type="math/tex...">
    let mut buf2 = String::with_capacity(html.len());
    let mut scan = html.as_str();
    while let Some(p) = scan.find("<script") {
        buf2.push_str(&scan[..p]);
        scan = &scan[p..];
        let tag_end = scan.find('>').unwrap_or(scan.len());
        let tag = &scan[..tag_end+1];
        let is_math   = tag.contains("math/tex");
        let is_display = tag.contains("mode=display") || tag.contains("mode%3Ddisplay");
        scan = &scan[tag_end+1..];
        if is_math {
            if let Some(close) = scan.find("</script>") {
                let content = scan[..close].trim();
                if is_display {
                    buf2.push_str(&format!("\n$$\n{}\n$$\n", content));
                } else {
                    buf2.push_str(&format!("${}$", content));
                }
                scan = &scan[close+9..];
            }
        } else {
            buf2.push_str(tag);
        }
    }
    buf2.push_str(scan);
    let html = buf2;

    // Pass 3: Pandoc <span class="math inline/display">...</span>
    let mut buf3 = String::with_capacity(html.len());
    let mut scan = html.as_str();
    while let Some(p) = scan.find("<span") {
        buf3.push_str(&scan[..p]);
        scan = &scan[p..];
        let tag_end = scan.find('>').unwrap_or(scan.len());
        let tag = &scan[..tag_end+1];
        let tl = tag.to_lowercase();
        let is_inline  = tl.contains("math inline") || tl.contains("math-inline");
        let is_display = tl.contains("math display") || tl.contains("math-display");
        if is_inline || is_display {
            scan = &scan[tag_end+1..];
            if let Some(close) = scan.find("</span>") {
                let content = scan[..close].trim();
                // Content from Pandoc is already \(...\) or \[...\] - pass through
                if is_display { buf3.push_str(&format!("\n{}\n", content)); }
                else { buf3.push_str(content); }
                scan = &scan[close+7..];
            } else {
                buf3.push_str(tag);
            }
        } else {
            buf3.push_str(tag);
            scan = &scan[tag_end+1..];
        }
    }
    buf3.push_str(scan);
    buf3
}

fn extract_math_annotation(math_body: &str) -> Option<String> {
    let open = "<annotation encoding=\"application/x-tex\">";
    let open2 = "<annotation encoding='application/x-tex'>";
    let start = math_body.find(open).map(|p| (p, open.len()))
        .or_else(|| math_body.find(open2).map(|p| (p, open2.len())));
    if let Some((p, len)) = start {
        let after = &math_body[p+len..];
        if let Some(end) = after.find("</annotation>") {
            return Some(after[..end].trim().to_string());
        }
    }
    None
}

fn extract_mathml_text(xml: &str) -> String {
    // Extract text content from MathML presentation elements mi, mn, mo, mtext
    let mut text = String::new();
    let leaves = ["<mi>", "<mn>", "<mo>", "<mtext>"];
    let closes = ["</mi>", "</mn>", "</mo>", "</mtext>"];
    let mut pos = 0;
    while pos < xml.len() {
        let mut found = false;
        for (open, close) in leaves.iter().zip(closes.iter()) {
            if xml[pos..].starts_with(open) {
                let after = &xml[pos+open.len()..];
                if let Some(e) = after.find(close) {
                    text.push_str(&after[..e]);
                    pos += open.len() + e + close.len();
                    found = true;
                    break;
                }
            }
        }
        if !found { pos += 1; }
    }
    text
}

// ── HTML helpers ──────────────────────────────────────────────────────────────

fn decode_entities(s: &str) -> String {
    s.replace("&amp;",   "&")
     .replace("&lt;",    "<")
     .replace("&gt;",    ">")
     .replace("&quot;",  "\"")
     .replace("&#39;",   "'")
     .replace("&apos;",  "'")
     .replace("&nbsp;",  " ")
     .replace("&mdash;", "-")
     .replace("&ndash;", "-")
     .replace("&hellip;","...")
     .replace("&copy;",  "\u{00A9}")  // ©
     .replace("&reg;",   "\u{00AE}")  // ®
     .replace("&trade;", "\u{2122}")  // ™
}

fn collapse_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_space = true;
    for c in s.chars() {
        if c.is_ascii_whitespace() {
            if !last_space { out.push(' '); last_space = true; }
        } else {
            last_space = false;
            out.push(c);
        }
    }
    out
}

fn ensure_newline(md: &mut String) {
    if !md.ends_with('\n') { md.push('\n'); }
}

fn ensure_double_newline(md: &mut String) {
    if md.ends_with("\n\n") || md.is_empty() { return; }
    if md.ends_with('\n') { md.push('\n'); } else { md.push_str("\n\n"); }
}

fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    for pat in [format!("{}=\"", attr), format!("{}='", attr)] {
        if let Some(p) = tag.to_lowercase().find(&pat.to_lowercase()) {
            let start = p + pat.len();
            let close = if pat.ends_with('"') { '"' } else { '\'' };
            if let Some(end) = tag[start..].find(close) {
                return Some(tag[start..start+end].to_string());
            }
        }
    }
    // Also handle unquoted value (href=foo)
    let bare = format!("{}=", attr);
    if let Some(p) = tag.to_lowercase().find(&bare.to_lowercase()) {
        let start = p + bare.len();
        let end = tag[start..].find(|c: char| c.is_ascii_whitespace() || c == '>' || c == '/')
                              .unwrap_or(tag.len() - start);
        return Some(tag[start..start+end].to_string());
    }
    None
}

fn collapse_blank_lines(s: &str) -> String {
    let mut out   = String::with_capacity(s.len());
    let mut blank = 0u32;
    for line in s.lines() {
        if line.trim().is_empty() {
            blank += 1;
            if blank <= 2 { out.push('\n'); }
        } else {
            blank = 0;
            out.push_str(line);
            out.push('\n');
        }
    }
    let result = out.trim_start_matches('\n').trim_end_matches('\n');
    format!("{}\n", result)
}
