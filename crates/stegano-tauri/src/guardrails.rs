//! Guardrails for the interface layer.
//!
//! These tests read the shipped markup, script and stylesheet and fail the
//! build when a rule the owner set is broken:
//!
//! - no user-visible string outside the locale catalogues,
//! - every catalogue holds exactly the same keys,
//! - every key the interface asks for exists,
//! - no surface colour is ever chosen independently of its foreground,
//! - every contrast pair still meets its target on the root (dark) palette and
//!   on that palette pushed through the light-theme inversion filter,
//! - no layout property is animated,
//! - the light theme is a filter over the one root palette, not a second one,
//! - the two routes into the light theme apply the same filter,
//! - catalogue copy avoids the marks the owner rejected.
//!
//! They use no parser and no crate beyond the standard library, deliberately:
//! the application ships no runtime dependency it does not need, and a test
//! dependency is still a dependency.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::registry;

/// Proper nouns that are never translated and may appear as literals.
const BRAND_TOKENS: [&str; 2] = ["SteganoHero", "Hope 'n Mind"];

/// Properties that must never be animated: every one of them forces layout.
const LAYOUT_PROPERTIES: [&str; 20] = [
    "width", "height", "min-width", "min-height", "max-width", "max-height", "top", "right",
    "bottom", "left", "inset", "margin", "padding", "font-size", "line-height", "flex", "flex-basis",
    "grid-template-columns", "gap", "border-width",
];

/// Attributes whose value reaches the reader.
const VISIBLE_ATTRIBUTES: [&str; 5] = ["placeholder", "title", "aria-label", "alt", "value"];

/// Properties in the script whose value reaches the reader.
const VISIBLE_PROPERTIES: [&str; 6] = [
    "textContent",
    "innerText",
    "innerHTML",
    "placeholder",
    "ariaLabel",
    "title",
];

/// Surface tokens, each paired with the single foreground allowed on it.
const SURFACE_SUFFIXES: [&str; 9] = [
    "page", "panel", "raised", "field", "accent", "success", "warning", "danger", "info",
];

/// Pairs that must reach 4.5:1, the target for body text.
const BODY_PAIRS: [(&str, &str); 13] = [
    ("--text-on-page", "--surface-page"),
    ("--text-on-panel", "--surface-panel"),
    ("--text-on-raised", "--surface-raised"),
    ("--text-on-field", "--surface-field"),
    ("--text-on-accent", "--surface-accent"),
    ("--text-on-success", "--surface-success"),
    ("--text-on-warning", "--surface-warning"),
    ("--text-on-danger", "--surface-danger"),
    ("--text-on-info", "--surface-info"),
    ("--text-muted-on-page", "--surface-page"),
    ("--text-muted-on-panel", "--surface-panel"),
    ("--text-muted-on-raised", "--surface-raised"),
    ("--link-on-panel", "--surface-panel"),
];

/// Pairs that must reach 3:1, the target for large text and interface borders.
const INTERFACE_PAIRS: [(&str, &str); 10] = [
    ("--border-on-page", "--surface-page"),
    ("--border-on-panel", "--surface-panel"),
    ("--border-on-raised", "--surface-raised"),
    ("--border-on-field", "--surface-field"),
    ("--focus-ring", "--surface-page"),
    ("--focus-ring", "--surface-panel"),
    ("--focus-ring", "--surface-raised"),
    ("--accent-line", "--surface-page"),
    ("--accent-line", "--surface-panel"),
    ("--meter-fill", "--meter-track"),
];

// ─── Paths ──────────────────────────────────────────────────────

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn frontend(file: &str) -> PathBuf {
    crate_root().join("frontend").join(file)
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The names of every Tauri command whose FIRST parameter is `request` (a struct
/// the frontend must pass as `{ request: {...} }`). Parsed from the backend so a
/// new such command is covered without editing this list.
fn request_taking_commands(rust: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut idx = 0;
    while let Some(rel) = rust[idx..].find("#[tauri::command]") {
        let pos = idx + rel;
        let Some(frel) = rust[pos..].find("fn ") else { break };
        let fpos = pos + frel + 3;
        let Some(paren) = rust[fpos..].find('(') else {
            idx = fpos;
            continue;
        };
        let name = rust[fpos..fpos + paren].trim().to_string();
        let rest = rust[fpos + paren + 1..].trim_start();
        // The first parameter is `request` when the name is followed by a type
        // colon, a comma, or the closing paren, so a field merely starting with
        // "request..." is not mistaken for it.
        if let Some(after) = rest.strip_prefix("request") {
            if matches!(after.chars().next(), Some(':') | Some(',') | Some(')') | Some(' ')) {
                out.push(name);
            }
        }
        idx = fpos + paren + 1;
    }
    out
}

/// For each `invoke("command", ...)` call in the frontend, whether a `request`
/// key appears in its arguments (before the next invoke and within a small
/// window). Byte offsets only, so no slice lands mid-character.
fn invoke_passes_request(js: &str, command: &str) -> Vec<bool> {
    let needle = format!("invoke(\"{command}\"");
    let mut results = Vec::new();
    let mut idx = 0;
    while let Some(rel) = js[idx..].find(&needle) {
        let after = idx + rel + needle.len();
        let tail = &js[after..];
        let boundary = tail.find("invoke(").unwrap_or(usize::MAX);
        let ok = match tail.find("request") {
            Some(r) => r < boundary && r < 400,
            None => false,
        };
        results.push(ok);
        idx = after;
    }
    results
}

/// For each `invoke("command", ...)` call in the frontend, whether `key` appears
/// in its arguments (before the next invoke and within a small window). Used to
/// pin that a flat-argument command is always handed every required key: a Tauri
/// command with a plain, non-defaulted parameter errors at runtime the moment an
/// invoke omits it (this is what "missing required key robust" was).
fn invoke_passes_key(js: &str, command: &str, key: &str) -> Vec<bool> {
    let needle = format!("invoke(\"{command}\"");
    let mut results = Vec::new();
    let mut idx = 0;
    while let Some(rel) = js[idx..].find(&needle) {
        let after = idx + rel + needle.len();
        let tail = &js[after..];
        let boundary = tail.find("invoke(").unwrap_or(usize::MAX);
        let ok = match tail.find(key) {
            Some(r) => r < boundary && r < 400,
            None => false,
        };
        results.push(ok);
        idx = after;
    }
    results
}

// ─── Text scanning helpers ──────────────────────────────────────

fn has_letter(text: &str) -> bool {
    text.chars().any(|c| c.is_alphabetic())
}

fn is_brand(text: &str) -> bool {
    BRAND_TOKENS.iter().any(|brand| text.trim() == *brand)
}

/// Remove `<!-- ... -->` sections.
fn strip_html_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        match rest[start..].find("-->") {
            Some(end) => rest = &rest[start + end + 3..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// Split an HTML document into tag bodies and text nodes.
fn split_html(source: &str) -> (Vec<String>, Vec<String>) {
    let mut tags = Vec::new();
    let mut texts = Vec::new();
    let mut rest = source;
    while let Some(open) = rest.find('<') {
        let text = &rest[..open];
        if !text.trim().is_empty() {
            texts.push(text.trim().to_string());
        }
        let after = &rest[open + 1..];
        match after.find('>') {
            Some(close) => {
                tags.push(after[..close].to_string());
                rest = &after[close + 1..];
            }
            None => return (tags, texts),
        }
    }
    if !rest.trim().is_empty() {
        texts.push(rest.trim().to_string());
    }
    (tags, texts)
}

/// Read `name="value"` pairs out of a tag body.
fn tag_attributes(tag: &str) -> Vec<(String, String)> {
    let mut attributes = Vec::new();
    let bytes: Vec<char> = tag.chars().collect();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && (bytes[index].is_whitespace() || bytes[index] == '/') {
            index += 1;
        }
        let start = index;
        while index < bytes.len() && !bytes[index].is_whitespace() && bytes[index] != '=' {
            index += 1;
        }
        if start == index {
            index += 1;
            continue;
        }
        let name: String = bytes[start..index].iter().collect();
        while index < bytes.len() && bytes[index].is_whitespace() {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] != '=' {
            attributes.push((name, String::new()));
            continue;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_whitespace() {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        let quote = bytes[index];
        if quote != '"' && quote != '\'' {
            let value_start = index;
            while index < bytes.len() && !bytes[index].is_whitespace() {
                index += 1;
            }
            attributes.push((name, bytes[value_start..index].iter().collect()));
            continue;
        }
        index += 1;
        let value_start = index;
        while index < bytes.len() && bytes[index] != quote {
            index += 1;
        }
        attributes.push((name, bytes[value_start..index].iter().collect()));
        index += 1;
    }
    attributes
}

/// Remove `${...}` interpolations and `<...>` markup from a literal, leaving
/// only what the reader would actually see as words.
fn literal_payload(literal: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = literal.chars().collect();
    let mut index = 0;
    let mut depth = 0;
    while index < chars.len() {
        if chars[index] == '$' && index + 1 < chars.len() && chars[index + 1] == '{' {
            depth += 1;
            index += 2;
            continue;
        }
        if depth > 0 {
            if chars[index] == '}' {
                depth -= 1;
            }
            index += 1;
            continue;
        }
        if chars[index] == '<' {
            while index < chars.len() && chars[index] != '>' {
                index += 1;
            }
            index += 1;
            continue;
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

/// Remove `//` and `/* */` comments from a script, ignoring both inside
/// string literals.
fn strip_js_comments(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut index = 0;
    let mut quote: Option<char> = None;
    while index < chars.len() {
        let c = chars[index];
        if let Some(active) = quote {
            out.push(c);
            if c == '\\' && index + 1 < chars.len() {
                out.push(chars[index + 1]);
                index += 2;
                continue;
            }
            if c == active {
                quote = None;
            }
            index += 1;
            continue;
        }
        if c == '"' || c == '\'' || c == '`' {
            quote = Some(c);
            out.push(c);
            index += 1;
            continue;
        }
        if c == '/' && index + 1 < chars.len() && chars[index + 1] == '/' {
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            continue;
        }
        if c == '/' && index + 1 < chars.len() && chars[index + 1] == '*' {
            index += 2;
            while index + 1 < chars.len() && !(chars[index] == '*' && chars[index + 1] == '/') {
                index += 1;
            }
            index += 2;
            continue;
        }
        out.push(c);
        index += 1;
    }
    out
}

/// Every position at which `needle` occurs, counted in characters.
fn find_all(chars: &[char], needle: &str) -> Vec<usize> {
    let pattern: Vec<char> = needle.chars().collect();
    let mut hits = Vec::new();
    if pattern.is_empty() || chars.len() < pattern.len() {
        return hits;
    }
    for start in 0..=(chars.len() - pattern.len()) {
        if chars[start..start + pattern.len()] == pattern[..] {
            hits.push(start);
        }
    }
    hits
}

/// Read the string literal that starts at `index`, if there is one.
fn read_literal(chars: &[char], index: usize) -> Option<(String, usize)> {
    if index >= chars.len() {
        return None;
    }
    let quote = chars[index];
    if quote != '"' && quote != '\'' && quote != '`' {
        return None;
    }
    let mut out = String::new();
    let mut cursor = index + 1;
    while cursor < chars.len() {
        if chars[cursor] == '\\' && cursor + 1 < chars.len() {
            out.push(chars[cursor + 1]);
            cursor += 2;
            continue;
        }
        if chars[cursor] == quote {
            return Some((out, cursor + 1));
        }
        out.push(chars[cursor]);
        cursor += 1;
    }
    None
}

// ─── Catalogue helpers ──────────────────────────────────────────

fn locale_directory() -> PathBuf {
    crate::locales::directory().expect("locale directory must resolve")
}

fn catalogues() -> BTreeMap<String, BTreeMap<String, String>> {
    let dir = locale_directory();
    let mut all = BTreeMap::new();
    for descriptor in crate::locales::discover(&dir).expect("discovery must succeed") {
        let catalogue = crate::locales::load(&descriptor.code).expect("catalogue must load");
        all.insert(descriptor.code, catalogue);
    }
    all
}

/// Every key the interface asks for: the ones written in the markup, plus the
/// ones the script builds from an identifier at runtime.
fn required_keys() -> BTreeSet<String> {
    let mut keys = BTreeSet::new();

    let html = strip_html_comments(&read(&frontend("index.html")));
    let (tags, _) = split_html(&html);
    for tag in &tags {
        for (name, value) in tag_attributes(tag) {
            if name.starts_with("data-i18n") && !value.is_empty() {
                keys.insert(value);
            }
        }
    }

    for id in registry::CARRIER_ORDER {
        keys.insert(format!("carrier.{id}.name"));
        keys.insert(format!("carrier.{id}.note"));
    }
    for id in registry::CIPHER_ORDER {
        keys.insert(format!("cipher.{id}.name"));
        keys.insert(format!("cipher.{id}.note"));
    }
    keys.insert("cipher.none.name".to_string());
    keys.insert("cipher.none.note".to_string());

    for tab in ["compose", "decode", "analyze", "about"] {
        keys.insert(format!("nav.{tab}"));
    }
    for mode in ["system", "light", "dark"] {
        keys.insert(format!("chrome.theme.{mode}"));
    }
    for state in ["ready", "working", "done", "error", "copied"] {
        keys.insert(format!("status.{state}"));
    }
    for verdict in ["Clean", "Suspicious", "Modified", "Confirmed"] {
        keys.insert(format!("analyze.verdict.{verdict}"));
    }
    for note in [
        "clean_note",
        "suspicious_note",
        "modified_note",
        "confirmed_note",
    ] {
        keys.insert(format!("analyze.verdict.{note}"));
    }
    for key in [
        "compose.capacity.bits",
        "compose.capacity.unmeasured",
        "compose.capacity.sufficient",
        "compose.capacity.insufficient",
        "compose.capacity.unlimited",
        "compose.carriers.read_path_broken",
        "compose.carriers.read_path_broken_detail",
        "compose.carriers.invalid_combination",
        "compose.error.no_secret",
        "compose.error.no_cover",
        "compose.error.no_carrier",
        "compose.error.no_password",
        "compose.error.no_recipient",
        "export.error.empty",
        "compose.result.carriers",
        "compose.result.cipher",
        "compose.result.recipient",
        "compose.result.used",
        "compose.result.hint",
        "compose.recipient.measure_note",
        "compose.recipient.file_unsupported",
        "cipher.recipient_pqc.name",
        "cipher.recipient_pqc.note",
        "decode.error.no_text",
        "decode.result.carriers",
        "decode.result.cipher",
        "decode.result.cipher_none",
        "decode.result.recipient",
        "decode.result.integrity_ok",
        "decode.result.integrity_failed",
        "decode.recipient.file_unsupported",
        "decode.carriers.auto",
        "analyze.error.no_text",
        "analyze.error.no_pair",
        "analyze.signatures.empty",
        "analyze.signatures.confidence",
        "analyze.signatures.decodable_yes",
        "analyze.signatures.decodable_no",
        "analyze.signatures.payload",
        "analyze.signatures.bytes",
        "analyze.unicode.total",
        "analyze.unicode.visible",
        "analyze.unicode.invisible",
        "analyze.unicode.bidi_controls",
        "analyze.unicode.breakdown_empty",
        "analyze.unicode.scripts_empty",
        "analyze.unicode.unusual_empty",
        "analyze.unicode.script_primary",
        "analyze.unicode.script_secondary",
        "analyze.unicode.script_count",
        "analyze.unicode.script_pattern",
        "analyze.unicode.column_codepoint",
        "analyze.unicode.column_category",
        "analyze.unicode.column_count",
        "analyze.stats.entropy",
        "analyze.stats.entropy_unit",
        "analyze.stats.noise_density",
        "analyze.stats.homoglyph_density",
        "analyze.stats.assessment",
        "analyze.compare.shannon",
        "analyze.compare.noise",
        "analyze.compare.perplexity",
        "about.build.version",
        "about.build.identifier",
        "about.build.locale_directory",
        "about.build.locale_active",
        "about.build.locale_found",
        "compose.recommend.fits",
        "compose.recommend.nofit",
        "compose.recommend.carrier",
        "compose.recommend.mission",
        "compose.recommend.density",
        "compose.recommend.fill",
        "compose.recommend.empty",
        "compose.result.density",
        "compose.result.verdict",
    ] {
        keys.insert(key.to_string());
    }
    keys
}

// ─── Stylesheet helpers ─────────────────────────────────────────

/// Remove `/* ... */` sections, so a comment sitting between two declarations
/// cannot hide the declaration that follows it.
fn strip_css_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        match rest[start..].find("*/") {
            Some(end) => rest = &rest[start + end + 2..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// The stylesheet with its commentary removed, which is what every structural
/// check below reads.
fn stylesheet() -> String {
    strip_css_comments(&read(&frontend("style.css")))
}

/// Every declaration block in the stylesheet, innermost first, so nesting
/// inside a media query is handled without a parser.
fn declaration_blocks(css: &str) -> Vec<String> {
    css.split('}')
        .map(|chunk| match chunk.rfind('{') {
            Some(brace) => chunk[brace + 1..].to_string(),
            None => String::new(),
        })
        .filter(|block| !block.trim().is_empty())
        .collect()
}

/// Read the balanced block that follows a selector.
fn block_after(css: &str, selector: &str) -> String {
    let start = css
        .find(selector)
        .unwrap_or_else(|| panic!("selector '{selector}' must exist in the stylesheet"));
    let open_byte = css[start..]
        .find('{')
        .unwrap_or_else(|| panic!("selector '{selector}' must open a block"))
        + start;
    // The stylesheet holds characters outside ASCII in its comments, so the
    // scan must count characters rather than bytes.
    let open = css[..open_byte].chars().count();
    let chars: Vec<char> = css.chars().collect();
    let mut depth = 0;
    let mut index = open;
    let mut out = String::new();
    while index < chars.len() {
        match chars[index] {
            '{' => {
                depth += 1;
                if depth > 1 {
                    out.push('{');
                }
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return out;
                }
                out.push('}');
            }
            c => out.push(c),
        }
        index += 1;
    }
    out
}

/// Read `--token: value;` declarations out of a block.
fn tokens_in(block: &str) -> BTreeMap<String, String> {
    let mut tokens = BTreeMap::new();
    for line in block.split(';') {
        let line = line.trim();
        if !line.starts_with("--") {
            continue;
        }
        let Some(colon) = line.find(':') else { continue };
        let name = line[..colon].trim().to_string();
        let mut value = line[colon + 1..].trim().to_string();
        if let Some(comment) = value.find("/*") {
            value = value[..comment].trim().to_string();
        }
        tokens.insert(name, value);
    }
    tokens
}

/// The palette lives once, on the bare :root, and IS the dark (root) theme;
/// the light theme is a filter applied over it, not a second set of tokens.
fn root_tokens(css: &str) -> BTreeMap<String, String> {
    tokens_in(&block_after(css, "\n:root {"))
}

/// Reproduce the CSS filter `invert(1) hue-rotate(180deg)` on a #rrggbb
/// colour, exactly as a browser paints the light theme, so the light palette
/// is verified rather than assumed. invert(1) maps each channel c -> 255 - c;
/// hue-rotate(180deg) is the CSS Filter Effects hueRotate matrix evaluated at
/// 180 degrees (cos = -1, sin = 0). Channels are clamped to [0, 255] after the
/// matrix, as the browser does.
fn filtered_hex(hex: &str) -> String {
    let hex = hex.trim().trim_start_matches('#');
    assert_eq!(hex.len(), 6, "expected a six digit colour, got '{hex}'");
    let comp = |from: usize| {
        u8::from_str_radix(&hex[from..from + 2], 16)
            .unwrap_or_else(|e| panic!("colour '{hex}' is not hexadecimal: {e}")) as f64
    };
    let (r, g, b) = (255.0 - comp(0), 255.0 - comp(2), 255.0 - comp(4));
    let rr = -0.574 * r + 1.430 * g + 0.144 * b;
    let gg = 0.426 * r + 0.430 * g + 0.144 * b;
    let bb = 0.426 * r + 1.430 * g - 0.856 * b;
    let clamp = |v: f64| v.max(0.0).min(255.0).round() as u8;
    format!("#{:02x}{:02x}{:02x}", clamp(rr), clamp(gg), clamp(bb))
}

/// The value of the `filter:` declaration inside a block, trimmed. Empty when
/// the block sets no filter.
fn filter_of(block: &str) -> String {
    for line in block.split(';') {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("filter:") {
            return rest.trim().to_string();
        }
    }
    String::new()
}

fn channel(component: f64) -> f64 {
    let c = component / 255.0;
    if c <= 0.04045 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

fn luminance(hex: &str) -> f64 {
    let hex = hex.trim().trim_start_matches('#');
    assert_eq!(hex.len(), 6, "expected a six digit colour, got '{hex}'");
    let value = |from: usize| {
        u8::from_str_radix(&hex[from..from + 2], 16)
            .unwrap_or_else(|e| panic!("colour '{hex}' is not hexadecimal: {e}")) as f64
    };
    0.2126 * channel(value(0)) + 0.7152 * channel(value(2)) + 0.0722 * channel(value(4))
}

fn contrast(a: &str, b: &str) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    let (high, low) = if la > lb { (la, lb) } else { (lb, la) };
    (high + 0.05) / (low + 0.05)
}

// ─── Tests ──────────────────────────────────────────────────────

#[test]
fn no_user_visible_literals_in_the_markup() {
    let html = strip_html_comments(&read(&frontend("index.html")));
    let (tags, texts) = split_html(&html);

    for text in &texts {
        if !has_letter(text) || is_brand(text) {
            continue;
        }
        panic!("index.html carries a user-visible literal: '{text}'");
    }

    for tag in &tags {
        for (name, value) in tag_attributes(tag) {
            if !VISIBLE_ATTRIBUTES.contains(&name.as_str()) {
                continue;
            }
            if !has_letter(&value) || is_brand(&value) {
                continue;
            }
            panic!("index.html sets '{name}' to the literal '{value}'");
        }
    }
}

#[test]
fn no_user_visible_literals_in_the_script() {
    let source = strip_js_comments(&read(&frontend("app.js")));
    let chars: Vec<char> = source.chars().collect();

    for property in VISIBLE_PROPERTIES {
        let needle = format!(".{property}");
        for hit in find_all(&chars, &needle) {
            let mut position = hit + needle.chars().count();
            // Skip a longer identifier that merely starts with this name.
            if position < chars.len()
                && (chars[position].is_alphanumeric() || chars[position] == '_')
            {
                continue;
            }
            while position < chars.len() && chars[position].is_whitespace() {
                position += 1;
            }
            if position >= chars.len() || chars[position] != '=' {
                continue;
            }
            // A comparison, not an assignment.
            if position + 1 < chars.len() && chars[position + 1] == '=' {
                continue;
            }
            position += 1;
            while position < chars.len() && chars[position].is_whitespace() {
                position += 1;
            }
            if let Some((literal, _)) = read_literal(&chars, position) {
                let payload = literal_payload(&literal);
                assert!(
                    !has_letter(&payload) || is_brand(&payload),
                    "app.js assigns the literal '{literal}' to .{property}"
                );
            }
        }
    }

    for attribute in VISIBLE_ATTRIBUTES {
        let needle = format!("setAttribute(\"{attribute}\"");
        assert!(
            !source.contains(&needle),
            "app.js sets '{attribute}' through setAttribute; bind it in the markup instead"
        );
    }
}

#[test]
fn every_catalogue_holds_the_same_keys() {
    let all = catalogues();
    assert!(all.len() >= 2, "at least two catalogues are expected");

    let base = all
        .get(crate::locales::BASE_LOCALE)
        .expect("the base catalogue must exist");
    let base_keys: BTreeSet<&String> = base.keys().collect();

    for (code, catalogue) in &all {
        let keys: BTreeSet<&String> = catalogue.keys().collect();
        let missing: Vec<&&String> = base_keys.difference(&keys).collect();
        let extra: Vec<&&String> = keys.difference(&base_keys).collect();
        assert!(
            missing.is_empty(),
            "catalogue '{code}' is missing keys: {missing:?}"
        );
        assert!(
            extra.is_empty(),
            "catalogue '{code}' holds keys the base does not: {extra:?}"
        );
        for (key, value) in catalogue.iter() {
            assert!(!value.trim().is_empty(), "catalogue '{code}' leaves '{key}' empty");
        }
    }
}

#[test]
fn every_key_the_interface_asks_for_exists() {
    let all = catalogues();
    let required = required_keys();
    for (code, catalogue) in &all {
        let missing: Vec<&String> = required
            .iter()
            .filter(|key| !catalogue.contains_key(*key))
            .collect();
        assert!(
            missing.is_empty(),
            "catalogue '{code}' is missing keys the interface asks for: {missing:?}"
        );
    }
}

#[test]
fn every_locale_catalogue_is_bundled_as_a_resource() {
    // A locale file the app ships must be listed in the bundle resources, or the
    // installed app cannot find its languages and starts with none. That bug
    // shipped once (the installer carried no locales at all); this ties the two
    // together so a new catalogue cannot be added without being bundled.
    let conf = read(&crate_root().join("tauri.conf.json"));
    let locales_dir = crate_root().join("..").join("..").join("locales");
    let listing = std::fs::read_dir(&locales_dir)
        .unwrap_or_else(|e| panic!("cannot list the locales directory: {e}"));
    for entry in listing {
        let path = entry.expect("a locale directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        assert!(
            conf.contains(&format!("locales/{name}")),
            "locale '{name}' is not bundled: add it to bundle.resources in tauri.conf.json, \
             or the installed app will not find it"
        );
    }
}

#[test]
fn every_request_command_is_invoked_with_a_request_object() {
    // A command whose first parameter is `request` must be called as
    // invoke("cmd", { request: {...} }); calling it with flat keys fails at
    // runtime with "missing required key request", which no Rust test catches
    // because the frontend/backend contract is untyped. This binds the two.
    let rust = read(&crate_root().join("src").join("main.rs"));
    let js = read(&frontend("app.js"));
    for command in request_taking_commands(&rust) {
        for (call, ok) in invoke_passes_request(&js, &command).into_iter().enumerate() {
            assert!(
                ok,
                "invoke(\"{command}\") call #{call} passes no 'request' object, but the \
                 command takes a request struct: wrap the arguments in request: {{...}}"
            );
        }
    }
}

#[test]
fn flat_commands_are_invoked_with_their_required_flags() {
    // These commands take flat, non-defaulted parameters (COMPOSE-2's `robust`,
    // SATURATE's `saturate`). A Tauri command errors at runtime the moment an
    // invoke omits a required key, and no Rust test catches it because the Tauri
    // command tests call the function directly. This binds every frontend invoke
    // of these commands to the keys they must carry. The regression it guards:
    // a capacity-refresh invoke that omitted `robust` died with
    // "missing required key robust".
    let js = read(&frontend("app.js"));
    let required: &[(&str, &[&str])] = &[
        ("carrier_capacity", &["cover", "robust"]),
        ("recommend_settings", &["robust"]),
        ("compose", &["robust", "saturate"]),
        ("compose_sealed", &["robust", "saturate"]),
    ];
    for (command, keys) in required {
        let mut seen = false;
        for key in *keys {
            let passes = invoke_passes_key(&js, command, key);
            seen = seen || !passes.is_empty();
            for (call, ok) in passes.into_iter().enumerate() {
                assert!(
                    ok,
                    "invoke(\"{command}\") call #{call} omits required key '{key}': \
                     the command takes it as a flat, non-defaulted parameter"
                );
            }
        }
        assert!(seen, "expected at least one invoke(\"{command}\") in the frontend");
    }
}

#[test]
fn catalogue_copy_avoids_the_rejected_marks() {
    for (code, catalogue) in catalogues() {
        for (key, value) in catalogue {
            for c in value.chars() {
                let rejected = matches!(c, '\u{2014}' | '\u{2013}' | '\u{2192}' | '\u{2190}'
                    | '\u{21D2}' | '\u{2022}' | '\u{00BB}' | '\u{00AB}')
                    || matches!(c as u32, 0x1F000..=0x1FAFF | 0x2600..=0x27BF);
                assert!(
                    !rejected,
                    "catalogue '{code}' key '{key}' uses the rejected character U+{:04X}",
                    c as u32
                );
            }
        }
    }
}

#[test]
fn the_online_rewrite_disclaimer_is_present_and_honest() {
    // The owner's rule: an online rewrite must surface the disclaimer, at least
    // a summary, in the user's language. Each catalogue must carry it, name that
    // the text leaves the machine, and promise no guarantee.
    let all = catalogues();
    for (code, catalogue) in &all {
        let body = catalogue
            .get("wordmark.online.disclaimer")
            .unwrap_or_else(|| panic!("catalogue '{code}' is missing the online disclaimer"));
        let low = body.to_lowercase();
        assert!(
            low.contains("external") || low.contains("externe"),
            "catalogue '{code}' online disclaimer must name the external send"
        );
        assert!(
            low.contains("no guarantee") || low.contains("aucune garantie"),
            "catalogue '{code}' online disclaimer must state there is no guarantee"
        );
        assert!(catalogue.contains_key("wordmark.online.title"));
        assert!(catalogue.contains_key("wordmark.online.acknowledge"));
    }
}

#[test]
fn surface_tokens_are_never_used_alone() {
    let css = stylesheet();
    for block in declaration_blocks(&css) {
        for suffix in SURFACE_SUFFIXES {
            let surface = format!("var(--surface-{suffix})");
            let paints_background = block
                .split(';')
                .any(|line| {
                    let trimmed = line.trim_start();
                    (trimmed.starts_with("background:")
                        || trimmed.starts_with("background-color:"))
                        && trimmed.contains(&surface)
                });
            if !paints_background {
                continue;
            }
            let foreground = format!("var(--text-on-{suffix})");
            assert!(
                block.contains(&foreground),
                "a rule paints --surface-{suffix} without setting --text-on-{suffix}:\n{block}"
            );
        }
    }
}

#[test]
fn contrast_pairs_meet_their_targets() {
    // Adapted for the theme model VISUAL-1 introduced. Before, this test read
    // two independent palettes (a light :root and a dark override) and checked
    // each. Now the palette is authored once on the bare :root and IS the dark
    // (root) theme; the light theme is not a second palette but the filter
    // invert(1) hue-rotate(180deg) applied to the app root. So we still check
    // twice, but from the one palette: once on the authored values (dark), and
    // once on the same values pushed through the exact CSS filter (light).
    // filtered_hex reproduces the CSS Filter Effects transform, so the light
    // theme's effective contrast is proven, not assumed. The 4.5:1 body and
    // 3:1 large-and-border targets, and the pair lists, are unchanged: no
    // target was weakened, the light coverage was preserved by transforming
    // the same pairs rather than reading a second set of tokens.
    let css = stylesheet();
    let root = root_tokens(&css);
    let resolve = |name: &str, filter: bool| -> String {
        let value = root
            .get(name)
            .unwrap_or_else(|| panic!("token {name} is missing from the root palette"));
        if filter {
            filtered_hex(value)
        } else {
            value.clone()
        }
    };
    for (label, filter) in [("root/dark", false), ("light-under-filter", true)] {
        for (foreground, background) in BODY_PAIRS {
            let fg = resolve(foreground, filter);
            let bg = resolve(background, filter);
            let ratio = contrast(&fg, &bg);
            assert!(
                ratio >= 4.5,
                "{label}: {foreground} on {background} is {ratio:.2}:1, body text needs 4.5:1"
            );
        }
        for (foreground, background) in INTERFACE_PAIRS {
            let fg = resolve(foreground, filter);
            let bg = resolve(background, filter);
            let ratio = contrast(&fg, &bg);
            assert!(
                ratio >= 3.0,
                "{label}: {foreground} on {background} is {ratio:.2}:1, interface parts need 3:1"
            );
        }
    }
}

#[test]
fn every_surface_token_has_its_foreground() {
    let css = stylesheet();
    let root = root_tokens(&css);
    for suffix in SURFACE_SUFFIXES {
        assert!(
            root.contains_key(&format!("--surface-{suffix}")),
            "--surface-{suffix} is missing from the root palette"
        );
        assert!(
            root.contains_key(&format!("--text-on-{suffix}")),
            "--text-on-{suffix} is missing from the root palette"
        );
    }
}

#[test]
fn the_theme_is_a_filter_not_a_second_palette() {
    // Re-pointed from no_colour_is_defined_only_inside_a_media_query. The old
    // model kept dark as a token override inside a media query, and this guard
    // made sure every such token also existed on the base :root so a colour
    // could never live only in the dark branch and silently diverge. The new
    // model has no second set of tokens at all: the light theme is a filter.
    // The equivalent, stronger invariant is that the theme branches declare NO
    // colour tokens, so the palette is defined once on :root and transformed,
    // never redefined. That preserves exactly what the old guard protected
    // (no colour hidden in a theme branch), fitted to the filter model.
    let css = stylesheet();
    for selector in [
        ":root[data-theme=\"light\"] {",
        ":root:not([data-theme=\"dark\"]) {",
    ] {
        let tokens = tokens_in(&block_after(&css, selector));
        assert!(
            tokens.is_empty(),
            "the light theme branch '{selector}' declares colour tokens {:?}; \
             the palette must live once on :root and light must be a filter, \
             not a second palette",
            tokens.keys().collect::<Vec<_>>()
        );
    }
    // And the old per-theme dark palette blocks must not reappear, or a colour
    // could once again be split between two themes.
    assert!(
        !css.contains(":root[data-theme=\"dark\"] {"),
        "a separate dark palette block reappeared; dark is the root palette now"
    );
    assert!(
        !css.contains(":root:not([data-theme=\"light\"]) {"),
        "the old media-query dark palette block reappeared; dark is the root now"
    );
}

#[test]
fn the_two_light_routes_apply_the_same_filter() {
    // Re-pointed from the_two_dark_declarations_agree. The old model reached
    // dark two ways (system preference and explicit choice) and this guard
    // proved the two token sets were identical, so the theme could not depend
    // on how it was entered. The new model inverts which theme has two routes:
    // the LIGHT theme is reached as a filter, either by an explicit light
    // choice (:root[data-theme="light"]) or by the system preference guarded so
    // an explicit dark choice still wins (@media prefers-color-scheme: light on
    // :root:not([data-theme="dark"])). The two routes must apply the same
    // filter, or the look would depend on how light was entered. The coverage
    // (two routes to one theme must agree) is preserved, re-pointed at the
    // filter. The exact string is also pinned to the transform the contrast
    // guard models, so the CSS and the proof cannot drift apart.
    let css = stylesheet();
    let explicit = filter_of(&block_after(&css, ":root[data-theme=\"light\"] {"));
    let system = filter_of(&block_after(&css, ":root:not([data-theme=\"dark\"]) {"));
    assert!(
        !explicit.is_empty(),
        "the explicit light choice must apply an inversion filter"
    );
    assert_eq!(
        explicit, system,
        "the two light routes must apply the same filter, or light depends on how it was entered"
    );
    assert_eq!(
        explicit, "invert(1) hue-rotate(180deg)",
        "the light filter must match the transform contrast_pairs_meet_their_targets models"
    );
}

#[test]
fn no_layout_property_is_animated() {
    let css = stylesheet();
    for block in declaration_blocks(&css) {
        for line in block.split(';') {
            let trimmed = line.trim_start();
            if !trimmed.starts_with("transition:") && !trimmed.starts_with("transition-property:") {
                continue;
            }
            let value = trimmed.split_once(':').map(|(_, v)| v).unwrap_or("");
            for animated in value.split(',') {
                let property = animated.trim().split_whitespace().next().unwrap_or("");
                assert!(
                    !LAYOUT_PROPERTIES.contains(&property),
                    "'{property}' forces layout and must not be animated:\n{trimmed}"
                );
            }
        }
    }
}

#[test]
fn reduced_motion_is_honoured() {
    let css = stylesheet();
    assert!(
        css.contains("@media (prefers-reduced-motion: reduce)"),
        "the stylesheet must answer prefers-reduced-motion"
    );
}

#[test]
fn the_locale_directory_sits_at_the_workspace_root() {
    let dir = locale_directory();
    assert!(
        dir.join("en.json").is_file(),
        "{} must hold the base catalogue",
        dir.display()
    );
}

#[test]
fn the_executable_is_the_product_not_the_framework() {
    // The crate keeps its workspace name (stegano-tauri), but the produced
    // executable is the product: SteganoHero.exe, never stegano-tauri.exe. The
    // Cargo bin target and tauri's mainBinaryName both say so, and must agree, or
    // the bundler and the desktop-shortcut hook would install the framework name.
    let cargo = read(&crate_root().join("Cargo.toml"));
    assert!(
        cargo.contains("name = \"SteganoHero\""),
        "the Cargo [[bin]] target must be named SteganoHero"
    );
    let config = read(&crate_root().join("tauri.conf.json"));
    assert!(
        config.contains("\"mainBinaryName\": \"SteganoHero\""),
        "tauri.conf.json must set mainBinaryName to SteganoHero so the bundle matches"
    );
    assert!(
        !config.contains("stegano-tauri.exe"),
        "no config should hardcode the framework binary name"
    );
}

#[test]
fn the_installer_branding_the_config_references_is_present() {
    // tauri.conf.json points the NSIS installer at a header image, a sidebar
    // image and its own icon, and the WiX (MSI) installer at a banner and a
    // dialog image, so both Windows installers carry the app's own identity. A
    // path that does not resolve ships an installer with no branding or fails
    // the bundler; this pins that the config still references each file and that
    // each file is on disk, so the personalisation cannot silently vanish
    // (invariant 2).
    let config = read(&crate_root().join("tauri.conf.json"));
    for rel in [
        "installer/header.bmp",
        "installer/sidebar.bmp",
        "icons/icon.ico",
        "installer/wix-banner.bmp",
        "installer/wix-dialog.bmp",
    ] {
        assert!(
            config.contains(rel),
            "tauri.conf.json no longer references the installer asset {rel}"
        );
        assert!(
            crate_root().join(rel).is_file(),
            "tauri.conf.json references {rel}, which is missing on disk"
        );
    }
}
