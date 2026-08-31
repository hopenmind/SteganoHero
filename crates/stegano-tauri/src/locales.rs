//! Locale catalogue discovery and loading.
//!
//! Every user-visible string lives in `locales/<code>.json` at the workspace
//! root. The interface never hardcodes the list of languages: it asks this
//! module which files exist. Dropping a new `de.json` into the directory is
//! enough to add German to the picker.
//!
//! Catalogues are flat JSON objects mapping a dotted key to a string. A
//! catalogue containing a non-string value is rejected by name rather than
//! silently ignored.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Language code used when nothing better can be resolved.
pub const BASE_LOCALE: &str = "en";

/// Key holding the name a language calls itself.
const DISPLAY_NAME_KEY: &str = "meta.display_name";

/// Environment variable that overrides directory discovery.
const DIRECTORY_OVERRIDE: &str = "STEGANOHERO_LOCALES_DIR";

/// Directory recorded at compile time, used when the executable sits inside
/// the cargo target tree.
const COMPILE_TIME_DIRECTORY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../locales");

/// One catalogue file that was found on disk.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LocaleDescriptor {
    /// Language code, taken from the file name without its extension.
    pub code: String,
    /// The name this language gives itself, for the picker.
    pub display_name: String,
    /// Number of keys the catalogue holds.
    pub key_count: usize,
}

/// What the interface needs in order to pick a language at startup.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LocaleEnvironment {
    /// Directory the catalogues were read from.
    pub directory: String,
    /// Every catalogue found, sorted by code.
    pub available: Vec<LocaleDescriptor>,
    /// Language suggested by the process environment, when it sets one.
    pub environment_hint: Option<String>,
    /// Code to fall back to when nothing else matches.
    pub base_locale: String,
}

/// Resolve the directory holding the catalogues.
///
/// Candidates are tried in order and the first existing directory wins:
/// the environment override, then paths relative to the executable (which
/// covers both an installed layout and `target/<profile>/`), then the
/// directory recorded at compile time.
pub fn directory() -> Result<PathBuf, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(raw) = std::env::var(DIRECTORY_OVERRIDE) {
        if !raw.trim().is_empty() {
            candidates.push(PathBuf::from(raw));
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        let mut base = exe.parent().map(Path::to_path_buf);
        // target/<profile>/<exe> needs three steps up to reach the workspace.
        for _ in 0..5 {
            let Some(dir) = base else { break };
            candidates.push(dir.join("locales"));
            base = dir.parent().map(Path::to_path_buf);
        }
    }

    candidates.push(PathBuf::from(COMPILE_TIME_DIRECTORY));

    for candidate in &candidates {
        if candidate.is_dir() {
            return Ok(candidate.clone());
        }
    }

    Err(format!(
        "locale directory not found, tried: {}",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// Accept only plain language tags such as `en`, `fr`, `pt-BR`.
fn is_valid_code(code: &str) -> bool {
    if code.is_empty() || code.len() > 12 {
        return false;
    }
    let mut parts = code.split('-');
    let Some(language) = parts.next() else {
        return false;
    };
    if language.len() < 2 || !language.chars().all(|c| c.is_ascii_lowercase()) {
        return false;
    }
    for part in parts {
        if part.is_empty() || !part.chars().all(|c| c.is_ascii_alphanumeric()) {
            return false;
        }
    }
    true
}

/// Read and validate one catalogue file.
pub fn read_catalogue(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read catalogue {}: {e}", path.display()))?;
    let parsed: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| format!("cannot parse catalogue {}: {e}", path.display()))?;
    let object = parsed
        .as_object()
        .ok_or_else(|| format!("catalogue {} is not a JSON object", path.display()))?;

    let mut entries = BTreeMap::new();
    for (key, value) in object {
        let text = value.as_str().ok_or_else(|| {
            format!(
                "catalogue {} holds a non-string value at key '{key}'",
                path.display()
            )
        })?;
        entries.insert(key.clone(), text.to_string());
    }
    Ok(entries)
}

/// List every catalogue present in the locale directory.
pub fn discover(dir: &Path) -> Result<Vec<LocaleDescriptor>, String> {
    let listing = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot list locale directory {}: {e}", dir.display()))?;

    let mut found = Vec::new();
    for entry in listing {
        let entry = entry.map_err(|e| format!("cannot read locale directory entry: {e}"))?;
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(code) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if !is_valid_code(code) {
            continue;
        }
        let catalogue = read_catalogue(&path)?;
        let display_name = catalogue
            .get(DISPLAY_NAME_KEY)
            .cloned()
            .unwrap_or_else(|| code.to_string());
        found.push(LocaleDescriptor {
            code: code.to_string(),
            display_name,
            key_count: catalogue.len(),
        });
    }

    if found.is_empty() {
        return Err(format!("no locale catalogue found in {}", dir.display()));
    }
    found.sort_by(|a, b| a.code.cmp(&b.code));
    Ok(found)
}

/// Language suggested by the process environment.
///
/// This follows the POSIX convention. Windows does not usually set these
/// variables, which is why the interface asks the web view for the system
/// language as well.
fn environment_hint() -> Option<String> {
    for name in ["LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"] {
        let Ok(raw) = std::env::var(name) else {
            continue;
        };
        let candidate = raw
            .split(['.', ':', '@'])
            .next()
            .unwrap_or("")
            .replace('_', "-");
        if candidate.is_empty() || candidate.eq_ignore_ascii_case("C") {
            continue;
        }
        return Some(candidate);
    }
    None
}

/// Everything the interface needs to choose a language at startup.
pub fn environment() -> Result<LocaleEnvironment, String> {
    let dir = directory()?;
    let available = discover(&dir)?;
    Ok(LocaleEnvironment {
        directory: dir.display().to_string(),
        available,
        environment_hint: environment_hint(),
        base_locale: BASE_LOCALE.to_string(),
    })
}

/// Load one catalogue by language code.
pub fn load(code: &str) -> Result<BTreeMap<String, String>, String> {
    if !is_valid_code(code) {
        return Err(format!("invalid language code: {code}"));
    }
    let dir = directory()?;
    let path = dir.join(format!("{code}.json"));
    if !path.is_file() {
        return Err(format!("no catalogue for language '{code}' in {}", dir.display()));
    }
    read_catalogue(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_directory_resolves() {
        let dir = directory().expect("locale directory must resolve during tests");
        assert!(dir.is_dir(), "{} must be a directory", dir.display());
    }

    #[test]
    fn base_catalogue_is_discovered() {
        let dir = directory().expect("locale directory must resolve");
        let found = discover(&dir).expect("discovery must succeed");
        assert!(
            found.iter().any(|d| d.code == BASE_LOCALE),
            "the base catalogue '{BASE_LOCALE}' must exist"
        );
        for descriptor in &found {
            assert!(
                !descriptor.display_name.is_empty(),
                "catalogue '{}' must declare {DISPLAY_NAME_KEY}",
                descriptor.code
            );
        }
    }

    #[test]
    fn invalid_codes_are_refused() {
        assert!(!is_valid_code(""));
        assert!(!is_valid_code("EN"));
        assert!(!is_valid_code("../secrets"));
        assert!(!is_valid_code("e"));
        assert!(is_valid_code("en"));
        assert!(is_valid_code("fr"));
        assert!(is_valid_code("pt-BR"));
    }

    #[test]
    fn loading_an_absent_language_names_it() {
        let error = load("zz").expect_err("an absent language must be an error");
        assert!(error.contains("zz"), "error must name the language: {error}");
    }
}
