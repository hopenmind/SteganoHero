//! Shared DOCX paragraph model and OMML (Office Math) to LaTeX descent.
//!
//! Provenance: lifted from an upstream Markdown converter,
//! `crates/core/src/import.rs` (the `DocxSeg` / `render_docx_segs` paragraph
//! model and the `omml_to_latex` chain). These are the pieces the namespace-aware
//! DOCX parser in `office_xml` depends on. Pure Rust, no external crate.

/// One in-order piece of a paragraph: formatted text or an equation.
pub(crate) enum DocxSeg {
    Text { s: String, bold: bool, italic: bool },
    Math { latex: String, display: bool },
}

/// Coalesce adjacent same-format text segments, then render to Markdown with
/// emphasis markers placed outside surrounding whitespace (so `**` never sits
/// next to a space, which would break the emphasis).
pub(crate) fn render_docx_segs(segs: Vec<DocxSeg>) -> String {
    let mut merged: Vec<DocxSeg> = Vec::new();
    for seg in segs {
        if let DocxSeg::Text { s, bold, italic } = &seg {
            if let Some(DocxSeg::Text { s: ps, bold: pb, italic: pi }) = merged.last_mut() {
                if *pb == *bold && *pi == *italic {
                    ps.push_str(s);
                    continue;
                }
            }
        }
        merged.push(seg);
    }

    let mut out = String::new();
    for seg in merged {
        match seg {
            DocxSeg::Text { s, bold, italic } => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    out.push_str(&s);
                    continue;
                }
                let lead = &s[..s.len() - s.trim_start().len()];
                let trail = &s[s.trim_end().len()..];
                let (open, close) = match (bold, italic) {
                    (true, true) => ("***", "***"),
                    (true, false) => ("**", "**"),
                    (false, true) => ("*", "*"),
                    (false, false) => ("", ""),
                };
                out.push_str(lead);
                out.push_str(open);
                out.push_str(trimmed);
                out.push_str(close);
                out.push_str(trail);
            }
            DocxSeg::Math { latex, display } => {
                let l = latex.trim();
                if l.is_empty() {
                    continue;
                }
                if display {
                    out.push_str(&format!("\n$$\n{}\n$$\n", l));
                } else {
                    out.push_str(&format!("${}$", l));
                }
            }
        }
    }
    out
}

// ── OMML (Office Math) → LaTeX ────────────────────────────────────────────────

pub(crate) fn omml_to_latex(xml: &str) -> String {
    omml_node(xml)
}

// Recursion-depth firewall for the OMML->LaTeX descent. A crafted document.xml
// with thousands of nested <m:f>/<m:e> would otherwise drive native-stack
// recursion to a stack overflow. Past the bound we return empty (bounded output)
// instead. The Drop guard decrements the counter on every exit, including a
// panic-unwind.
const MAX_OMML_DEPTH: u32 = 96;
thread_local! {
    static OMML_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}
struct OmmlDepthGuard;
impl Drop for OmmlDepthGuard {
    fn drop(&mut self) {
        OMML_DEPTH.with(|c| c.set(c.get().saturating_sub(1)));
    }
}

fn omml_node(xml: &str) -> String {
    let depth = OMML_DEPTH.with(|c| {
        let v = c.get() + 1;
        c.set(v);
        v
    });
    let _guard = OmmlDepthGuard;
    if depth > MAX_OMML_DEPTH {
        return String::new();
    }
    let mut out = String::new();
    let mut pos = 0;

    while pos < xml.len() {
        if !xml[pos..].starts_with('<') {
            // Text node
            let end = xml[pos..].find('<').unwrap_or(xml.len() - pos);
            out.push_str(&xml[pos..pos+end]);
            pos += end;
            continue;
        }
        pos += 1; // skip <
        let _ts = pos;
        let tag_end = xml[pos..].find('>').unwrap_or(xml.len() - pos);
        let tag = &xml[pos..pos+tag_end];
        pos += tag_end + 1;

        if tag.starts_with('/') { break; } // closing tag - stop this level
        let self_closing = tag.ends_with('/');
        if self_closing { continue; }

        let tag_name = tag.split(|c: char| !c.is_alphanumeric() && c != ':')
                          .next().unwrap_or("").to_string();

        // Find the matching closing tag, honoring nested same-name tags (a naive
        // first-match truncated bodies that contained nested `<m:e>` etc.).
        let close_tag = format!("</{}>", tag_name);
        let body = if let Some(end) = omml_matching_close(xml, &tag_name, pos) {
            let b = xml[pos..end].to_string();
            pos = end + close_tag.len();
            b
        } else {
            String::new()
        };

        match tag_name.as_str() {
            // Fraction: \frac{num}{den}
            "m:f" => {
                let num = omml_child(&body, "m:num");
                let den = omml_child(&body, "m:den");
                out.push_str(&format!("\\frac{{{}}}{{{}}}", omml_node(&num), omml_node(&den)));
            }
            // Superscript: base^{exp}
            "m:sSup" => {
                let base = omml_child(&body, "m:e");
                let sup  = omml_child(&body, "m:sup");
                out.push_str(&format!("{}^{{{}}}", omml_node(&base), omml_node(&sup)));
            }
            // Subscript: base_{sub}
            "m:sSub" => {
                let base = omml_child(&body, "m:e");
                let sub  = omml_child(&body, "m:sub");
                out.push_str(&format!("{}_{{{}}}",  omml_node(&base), omml_node(&sub)));
            }
            // Sub+superscript: base_{sub}^{sup}
            "m:sSubSup" => {
                let base = omml_child(&body, "m:e");
                let sub  = omml_child(&body, "m:sub");
                let sup  = omml_child(&body, "m:sup");
                out.push_str(&format!("{}_{{{}}}", omml_node(&base), omml_node(&sub)));
                out.push_str(&format!("^{{{}}}", omml_node(&sup)));
            }
            // Radical: \sqrt[deg]{body}
            "m:rad" => {
                let deg  = omml_child(&body, "m:deg");
                let e    = omml_child(&body, "m:e");
                let deg_latex = omml_node(&deg);
                if deg_latex.trim().is_empty() {
                    out.push_str(&format!("\\sqrt{{{}}}", omml_node(&e)));
                } else {
                    out.push_str(&format!("\\sqrt[{}]{{{}}}", deg_latex.trim(), omml_node(&e)));
                }
            }
            // n-ary operator (sum, product, integral, etc.)
            "m:nary" => {
                let chr   = omml_nary_chr(&body);
                let sub   = omml_child(&body, "m:sub");
                let sup   = omml_child(&body, "m:sup");
                let e     = omml_child(&body, "m:e");
                out.push_str(&chr);
                if !sub.is_empty()  { out.push_str(&format!("_{{{}}}", omml_node(&sub))); }
                if !sup.is_empty()  { out.push_str(&format!("^{{{}}}", omml_node(&sup))); }
                // Separate the operator command from its operand: "\sum A", never
                // "\sumA" (which LaTeX/KaTeX/Typst read as one unknown command).
                out.push(' ');
                out.push_str(&omml_node(&e));
            }
            // Delimiter: \left(...\right) or similar
            "m:d" => {
                let (open_d, close_d) = omml_delimiters(&body);
                let e = omml_child(&body, "m:e");
                out.push_str(&format!("\\left{}{}\\right{}", open_d, omml_node(&e), close_d));
            }
            // Matrix (array)
            "m:m" => {
                let rows: Vec<String> = omml_children_all(&body, "m:mr")
                    .into_iter()
                    .map(|row| {
                        let cells: Vec<String> = omml_children_all(&row, "m:e")
                            .into_iter().map(|c| omml_node(&c)).collect();
                        cells.join(" & ")
                    })
                    .collect();
                out.push_str(&format!("\\begin{{matrix}}{}\n\\end{{matrix}}", rows.join(" \\\\\n")));
            }
            // Text run leaf - the actual characters
            "m:r" => {
                out.push_str(&omml_run_text(&body));
            }
            // Math properties - skip
            "m:rPr" | "m:rSPr" | "m:sPrePr" | "m:sSupPr" | "m:sSubPr" |
            "m:sSubSupPr" | "m:radPr" | "m:fPr" | "m:dPr" | "m:naryPr" |
            "m:mPr" | "m:mrPr" | "m:limLocPr" | "m:groupChrPr" => {}
            // Everything else: recurse into children
            _ => { out.push_str(&omml_node(&body)); }
        }
    }
    out
}

/// True when `name_end` (index just past a tag name) is a real tag-name
/// boundary, so `<m:e` does not match `<m:endChr` / `<m:eqArr`.
fn omml_name_boundary(xml: &str, name_end: usize) -> bool {
    matches!(
        xml[name_end..].chars().next(),
        Some(' ') | Some('>') | Some('/') | Some('\t') | Some('\n') | Some('\r')
    )
}

/// Find the `</tag>` matching an open already consumed, honoring nesting of the
/// SAME tag and ignoring self-closing `<tag/>`. `from` is just past the opening
/// tag's `>`. Returns the byte offset of the `<` of the matching close.
fn omml_matching_close(xml: &str, tag: &str, from: usize) -> Option<usize> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);
    let mut depth = 1usize;
    let mut i = from;
    loop {
        let no = xml[i..].find(&open).map(|p| i + p);
        let nc = xml[i..].find(&close).map(|p| i + p);
        match (no, nc) {
            (Some(o), maybe_c) if maybe_c.map_or(true, |c| o < c) => {
                if omml_name_boundary(xml, o + open.len()) {
                    let gt = xml[o..].find('>').map(|g| o + g)?;
                    if !xml[..gt].ends_with('/') {
                        depth += 1;
                    }
                    i = gt + 1;
                } else {
                    i = o + open.len();
                }
            }
            (_, Some(c)) => {
                depth -= 1;
                if depth == 0 {
                    return Some(c);
                }
                i = c + close.len();
            }
            _ => return None,
        }
    }
}

/// Content of the first real `<tag ...>...</tag>` (boundary- and nesting-aware).
fn omml_child(xml: &str, tag: &str) -> String {
    let open = format!("<{}", tag);
    let mut i = 0;
    while let Some(p) = xml[i..].find(&open).map(|x| i + x) {
        if omml_name_boundary(xml, p + open.len()) {
            if let Some(gt) = xml[p..].find('>').map(|g| p + g) {
                if xml[..gt].ends_with('/') {
                    return String::new(); // self-closing: no body
                }
                let body_start = gt + 1;
                if let Some(end) = omml_matching_close(xml, tag, body_start) {
                    return xml[body_start..end].to_string();
                }
            }
        }
        i = p + open.len();
    }
    String::new()
}

/// Extract all top-level occurrences of `<tag ...>...</tag>` (boundary- and
/// nesting-aware, so a nested same-name tag does not split a parent).
fn omml_children_all(xml: &str, tag: &str) -> Vec<String> {
    let mut results = Vec::new();
    let open  = format!("<{}", tag);
    let close = format!("</{}>", tag);
    let mut pos = 0;
    while let Some(p) = xml[pos..].find(&open).map(|x| pos + x) {
        if !omml_name_boundary(xml, p + open.len()) {
            pos = p + open.len();
            continue;
        }
        let Some(gt) = xml[p..].find('>').map(|g| p + g) else { break };
        if xml[..gt].ends_with('/') { pos = gt + 1; continue; } // self-closing
        let body_start = gt + 1;
        match omml_matching_close(xml, tag, body_start) {
            Some(end) => {
                results.push(xml[body_start..end].to_string());
                pos = end + close.len();
            }
            None => break,
        }
    }
    results
}

/// Extract the LaTeX character from `<m:nary>` based on the `<m:chr>` value.
fn omml_nary_chr(body: &str) -> &'static str {
    if let Some(p) = body.find("m:chr=\"") {
        let val = &body[p+7..];
        let end = val.find('"').unwrap_or(val.len());
        return match &val[..end] {
            "\u{2211}" | "\u{03A3}" => "\\sum",   // U+2211 n-ary sum, U+03A3 Sigma
            "\u{220F}" | "\u{03A0}" => "\\prod",  // U+220F n-ary product, U+03A0 Pi
            "\u{222B}"              => "\\int",   // U+222B integral
            "\u{222C}"              => "\\iint",  // U+222C double integral
            "\u{222D}"              => "\\iiint", // U+222D triple integral
            "\u{222E}"              => "\\oint",  // U+222E contour integral
            _                       => "\\sum",
        };
    }
    "\\sum"
}

/// Extract opening/closing delimiter characters from `<m:d>`.
fn omml_delimiters(body: &str) -> (&'static str, &'static str) {
    let open  = extract_xml_attr(body, "m:begChr").unwrap_or_default();
    let close = extract_xml_attr(body, "m:endChr").unwrap_or_default();
    let open_d  = match open.as_str()  { "(" => "(", "[" => "[", "{" => "\\{", "|" => "|", _ => "(" };
    let close_d = match close.as_str() { ")" => ")", "]" => "]", "}" => "\\}", "|" => "|", _ => ")" };
    (open_d, close_d)
}

/// Extract text content from an OMML run `<m:r>...</m:r>`.
/// Maps common Unicode math symbols to LaTeX commands.
fn omml_run_text(body: &str) -> String {
    // A run may carry several <m:t> leaves - gather them all (not just the first),
    // otherwise multi-part runs lose text.
    let parts = omml_children_all(body, "m:t");
    let raw: String = if parts.is_empty() {
        omml_child(body, "m:t")
    } else {
        parts.join("")
    };
    if raw.is_empty() {
        return String::new();
    }

    let is_normal = body.contains("<m:nor") || body.contains("m:val=\"p\"");

    // Map math symbols / Greek to LaTeX FIRST so Greek (non-ASCII) becomes ASCII
    // (\alpha) and is not mistaken for accented prose in the check below.
    let mapped: String = raw.chars().map(|c| {
        let m = map_math_char(c);
        // Commands map to multi-letter tokens; a LEADING space stops them gluing
        // onto a preceding letter. Math-mode whitespace is insignificant.
        if m.starts_with('\\') { format!(" {m}") } else { m }
    }).collect();

    // Upright \text{} for plain-text runs, or when ANY non-ASCII char remains
    // after mapping (accents, Unicode super/subscripts, stray arrows). Real math
    // symbols are already mapped to ASCII \commands, so a leftover non-ASCII is
    // prose that should render with the text font.
    let needs_text = is_normal || mapped.chars().any(|c| !c.is_ascii());
    if needs_text {
        let escaped: String = raw.chars().map(|c| match c {
            '\\' => "\\textbackslash{}".to_string(),
            '{' => "\\{".to_string(),
            '}' => "\\}".to_string(),
            '%' => "\\%".to_string(),
            '&' => "\\&".to_string(),
            '#' => "\\#".to_string(),
            '_' => "\\_".to_string(),
            '$' => "\\$".to_string(),
            other => other.to_string(),
        }).collect();
        return format!("\\text{{{}}}", escaped);
    }
    mapped
}

/// Map a single math char to its LaTeX command (Greek letters, operators); any
/// other char maps to itself. Non-ASCII source chars are written as `\u{...}`
/// escapes so this file stays pure ASCII (invariant: English in code).
fn map_math_char(c: char) -> String {
    match c {
        '\u{00D7}' => "\\times ".to_string(),                 // ×
        '\u{00B7}' | '\u{22C5}' => "\\cdot ".to_string(),     // · ⋅
        '\u{00F7}' => "\\div ".to_string(),                   // ÷
        '\u{00B1}' => "\\pm ".to_string(),                    // ±
        '\u{2213}' => "\\mp ".to_string(),                    // ∓
        '\u{2212}' => "-".to_string(),                        // U+2212 minus sign → ASCII hyphen
        '\u{221D}' => "\\propto ".to_string(),                // ∝
        '\u{2261}' => "\\equiv ".to_string(),                 // ≡
        '\u{2245}' => "\\cong ".to_string(),                  // ≅
        '\u{223C}' => "\\sim ".to_string(),                   // ∼
        '\u{2218}' => "\\circ ".to_string(),                  // ∘
        '\u{2217}' => "*".to_string(),                        // ∗
        '\u{2286}' => "\\subseteq ".to_string(),              // ⊆
        '\u{2287}' => "\\supseteq ".to_string(),              // ⊇
        '\u{2295}' => "\\oplus ".to_string(),                 // ⊕
        '\u{2297}' => "\\otimes ".to_string(),                // ⊗
        '\u{2299}' => "\\odot ".to_string(),                  // ⊙
        '\u{2227}' => "\\wedge ".to_string(),                 // ∧
        '\u{2228}' => "\\vee ".to_string(),                   // ∨
        '\u{2200}' => "\\forall ".to_string(),                // ∀
        '\u{2203}' => "\\exists ".to_string(),                // ∃
        '\u{21A6}' => "\\mapsto ".to_string(),                // ↦
        '\u{27E8}' => "\\langle ".to_string(),                // ⟨
        '\u{27E9}' => "\\rangle ".to_string(),                // ⟩
        '\u{2264}' => "\\leq ".to_string(),                   // ≤
        '\u{2265}' => "\\geq ".to_string(),                   // ≥
        '\u{2260}' => "\\neq ".to_string(),                   // ≠
        '\u{2248}' => "\\approx ".to_string(),                // ≈
        '\u{221E}' => "\\infty ".to_string(),                 // ∞
        '\u{2202}' => "\\partial ".to_string(),               // ∂
        '\u{2207}' => "\\nabla ".to_string(),                 // ∇
        '\u{2208}' => "\\in ".to_string(),                    // ∈
        '\u{2209}' => "\\notin ".to_string(),                 // ∉
        '\u{2282}' => "\\subset ".to_string(),                // ⊂
        '\u{2283}' => "\\supset ".to_string(),                // ⊃
        '\u{2229}' => "\\cap ".to_string(),                   // ∩
        '\u{222A}' => "\\cup ".to_string(),                   // ∪
        '\u{2192}' => "\\rightarrow ".to_string(),            // →
        '\u{2190}' => "\\leftarrow ".to_string(),             // ←
        '\u{2194}' => "\\leftrightarrow ".to_string(),        // ↔
        '\u{21D2}' => "\\Rightarrow ".to_string(),            // ⇒
        '\u{21D4}' => "\\Leftrightarrow ".to_string(),        // ⇔
        '\u{03B1}' => "\\alpha ".to_string(),                 // α
        '\u{03B2}' => "\\beta ".to_string(),                  // β
        '\u{03B3}' => "\\gamma ".to_string(),                 // γ
        '\u{03B4}' => "\\delta ".to_string(),                 // δ
        '\u{03B5}' => "\\epsilon ".to_string(),               // ε
        '\u{03B8}' => "\\theta ".to_string(),                 // θ
        '\u{03BB}' => "\\lambda ".to_string(),                // λ
        '\u{03BC}' => "\\mu ".to_string(),                    // μ
        '\u{03C0}' => "\\pi ".to_string(),                    // π
        '\u{03C3}' => "\\sigma ".to_string(),                 // σ
        '\u{03C6}' | '\u{03D5}' => "\\phi ".to_string(),      // φ ϕ
        '\u{03C9}' => "\\omega ".to_string(),                 // ω
        '\u{0393}' => "\\Gamma ".to_string(),                 // Γ
        '\u{0394}' => "\\Delta ".to_string(),                 // Δ
        '\u{0398}' => "\\Theta ".to_string(),                 // Θ
        '\u{039B}' => "\\Lambda ".to_string(),                // Λ
        '\u{03A0}' => "\\Pi ".to_string(),                    // Π
        '\u{03A3}' => "\\Sigma ".to_string(),                 // Σ
        '\u{03A6}' => "\\Phi ".to_string(),                   // Φ
        '\u{03A8}' => "\\Psi ".to_string(),                   // Ψ
        '\u{03A9}' => "\\Omega ".to_string(),                 // Ω
        '\u{221A}' => "\\sqrt".to_string(),                   // √
        '\u{2211}' => "\\sum ".to_string(),                   // ∑
        '\u{220F}' => "\\prod ".to_string(),                  // ∏
        '\u{222B}' => "\\int ".to_string(),                   // ∫
        c   => c.to_string(),
    }
}

/// Extract an XML attribute value by name (quote-aware). Shared with the OMML
/// delimiter reader.
pub(crate) fn extract_xml_attr(xml: &str, attr: &str) -> Option<String> {
    for pat in [format!("{}=\"", attr), format!("{}='", attr)] {
        if let Some(p) = xml.find(&pat) {
            let start = p + pat.len();
            let close = if pat.ends_with('"') { '"' } else { '\'' };
            if let Some(end) = xml[start..].find(close) {
                return Some(xml[start..start+end].to_string());
            }
        }
    }
    None
}
