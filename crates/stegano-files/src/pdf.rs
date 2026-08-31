//! PDF export by driving a DETECTED LOCAL BROWSER (Phase D1).
//!
//! CONVERSION IS SEPARATE FROM MARKING. This is a conversion output only: it never
//! places a mark. See [`crate::convert`] for the boundary and the losslessness
//! contract.
//!
//! ## Provenance
//!
//! Copied and adapted, not depended upon, from an upstream Markdown converter
//! (`crates/core/src/export.rs`: `find_browser` around line 127 and
//! `export_pdf_via_browser` around line 139). That code writes a self-contained
//! HTML file and drives an installed browser as a subprocess with
//! `--headless=new --print-to-pdf`. Four adaptations, each documented at its site:
//!
//! 1. Detection widened. the upstream converter located Edge only. Here we detect Chrome, Edge
//!    (both Chromium, PDF-capable) and Firefox at their standard Windows install
//!    paths and on `PATH`. Firefox (Gecko) is detected for completeness but is
//!    NEVER driven for PDF: Gecko has no headless print-to-PDF command-line flag
//!    (Mozilla bug 1407238). Pretending otherwise would ship a fictional argument
//!    and risk a silent bad file, so a Firefox-only host is refused BY NAME
//!    (invariant 2), not fed a flag it does not honour.
//! 2. The detection is driven through an injectable existence predicate so it is
//!    unit-testable without a real browser or the real filesystem. No test in this
//!    module launches a browser; the one real end-to-end test is `#[ignore]`d.
//! 3. The result is returned as PDF BYTES in memory (the source wrote to a path).
//!    The temporary HTML, the temporary PDF and the isolated user-data directory
//!    are all removed before returning.
//! 4. Offline hardening flags are added so a self-contained LOCAL render never
//!    phones home, and temporary names are derived from the process id plus an
//!    atomic counter (no date or random-number dependency).
//!
//! This adds NO crate dependency: it uses only `std::process`, `std::env` and
//! `std::fs`, and drives a browser the user already has installed. The pure-Rust
//! Typst fallback for hosts with no browser is a separate later slice (Phase D2)
//! and is deliberately NOT bundled here.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// How long to wait for the detached `--headless=new` child to finish writing the
/// PDF after the browser's parent process has already exited (see [`wait_for_pdf`]).
const PDF_WAIT_TIMEOUT: Duration = Duration::from_secs(20);

/// A browser rendering engine, which decides whether a detected browser can print
/// a PDF from the command line at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Engine {
    /// Chrome / Edge: honour `--headless=new --print-to-pdf`, the PDF path.
    Chromium,
    /// Firefox: DETECTED for completeness, but Gecko has no headless print-to-PDF
    /// command-line flag (Mozilla bug 1407238), so it is never driven for PDF.
    Gecko,
}

/// The outcome of resolving the installed browsers to a PDF engine.
#[derive(Debug, PartialEq, Eq)]
enum BrowserResolution {
    /// A PDF-capable Chromium browser (Chrome or Edge) was found.
    Chromium(PathBuf),
    /// Only Firefox was found: detected, but not PDF-capable (see [`Engine::Gecko`]).
    OnlyGecko,
    /// No supported browser was found at all.
    None,
}

/// An error from the browser-driven PDF path. Every variant names itself and its
/// context; no path returns an empty or corrupt file silently (invariant 2).
#[derive(Debug, thiserror::Error)]
pub(crate) enum PdfError {
    /// No installed browser can render a PDF (none found, or only Firefox, which
    /// has no headless print-to-PDF flag). Refused by name.
    #[error("no usable PDF engine: {detail}")]
    NoUsableEngine { detail: String },

    /// A temporary file or directory could not be written or created.
    #[error("temporary file error during PDF rendering: {detail}")]
    TempIo { detail: String },

    /// The browser subprocess could not be launched.
    #[error("browser launch failed: {detail}")]
    Launch { detail: String },

    /// The browser ran but exited without success.
    #[error("browser exited abnormally: {detail}")]
    NonZeroExit { detail: String },

    /// The browser ran and exited cleanly but produced no PDF, or an empty one. A
    /// named failure, never a silent empty file (invariant 2).
    #[error("browser produced no usable PDF: {detail}")]
    EmptyOutput { detail: String },
}

/// True when a local browser capable of headless PDF rendering (Chrome or Edge) is
/// installed. Firefox does NOT count: Gecko has no headless print-to-PDF flag, so a
/// Firefox-only host reports `false` here and is refused by name at render time.
pub(crate) fn pdf_target_available() -> bool {
    matches!(
        resolve_browser(&standard_candidates(), &|p: &Path| p.exists()),
        BrowserResolution::Chromium(_)
    )
}

/// Render self-contained HTML to PDF bytes by driving a detected local browser.
///
/// Writes the HTML to a temporary file, invokes the browser headless to print it to
/// a temporary PDF, reads the bytes back, and removes every temporary artifact. The
/// browser only ever opens the local `file://` URL; it is passed offline-hardening
/// flags so a local render never phones home. All failure modes are named
/// (invariant 2): no usable browser, a launch error, an abnormal exit, or an
/// empty/absent PDF.
pub(crate) fn html_to_pdf(html: &str) -> Result<Vec<u8>, PdfError> {
    let browser = match resolve_browser(&standard_candidates(), &|p: &Path| p.exists()) {
        BrowserResolution::Chromium(path) => path,
        BrowserResolution::OnlyGecko => {
            return Err(PdfError::NoUsableEngine {
                detail: "the only browser found was Firefox, which has no headless \
                         print-to-PDF command-line flag (Mozilla bug 1407238); install \
                         Chrome or Edge. The pure-Rust Typst fallback is a later slice"
                    .to_string(),
            })
        }
        BrowserResolution::None => {
            return Err(PdfError::NoUsableEngine {
                detail: "no installed browser was found for PDF rendering; the pure-Rust \
                         Typst fallback is a later slice"
                    .to_string(),
            })
        }
    };

    // Unique temp names from the process id plus a counter: no date, no rng.
    let token = unique_token();
    let dir = std::env::temp_dir();
    let html_path = dir.join(format!("steganohero_pdf_{token}.html"));
    let pdf_path = dir.join(format!("steganohero_pdf_{token}.pdf"));
    let user_data_dir = dir.join(format!("steganohero_pdf_udd_{token}"));

    std::fs::write(&html_path, html).map_err(|e| PdfError::TempIo {
        detail: format!("could not write the temporary HTML waypoint: {e}"),
    })?;
    // An isolated user-data directory avoids clashing with an already-open browser.
    let _ = std::fs::create_dir_all(&user_data_dir);

    let file_url = file_url_for(&html_path);
    let args = chromium_print_args(&file_url, &pdf_path, &user_data_dir);
    let run = run_browser(&browser, &args);

    // Resolve the run and read the PDF while the temporary files still exist; clean
    // up afterwards whatever the outcome. `--headless=new` writes the PDF from a
    // detached child that OUTLIVES the parent process, so the parent can exit before
    // the file is on disk. We therefore poll for the finished output rather than
    // reading immediately (reading immediately is a race that yields "file not
    // found"). We must not delete the user-data directory until the child is done,
    // which is exactly what the poll waits for.
    let result = (|| {
        let succeeded = run.map_err(|e| PdfError::Launch {
            detail: format!("could not launch the browser {}: {e}", browser.display()),
        })?;
        if !succeeded {
            return Err(PdfError::NonZeroExit {
                detail: format!("the browser {} exited without success", browser.display()),
            });
        }
        wait_for_pdf(&pdf_path, PDF_WAIT_TIMEOUT).ok_or_else(|| PdfError::EmptyOutput {
            detail: format!(
                "the browser exited but wrote no non-empty PDF within {}s",
                PDF_WAIT_TIMEOUT.as_secs()
            ),
        })
    })();

    let _ = std::fs::remove_file(&html_path);
    let _ = std::fs::remove_file(&pdf_path);
    let _ = std::fs::remove_dir_all(&user_data_dir);

    result
}

/// Wait for the browser's detached child to finish writing the PDF at `path`, up to
/// `timeout`, returning the bytes once the file exists and its size has settled
/// (stable across two polls, so a half-written file is never read). Returns `None`
/// on timeout, which the caller turns into a named [`PdfError::EmptyOutput`].
fn wait_for_pdf(path: &Path, timeout: Duration) -> Option<Vec<u8>> {
    let start = Instant::now();
    let mut last_len: Option<u64> = None;
    loop {
        if let Ok(meta) = std::fs::metadata(path) {
            let len = meta.len();
            // Read only once the size is non-zero and unchanged since the last poll,
            // so the child has finished flushing the file.
            if len > 0 && Some(len) == last_len {
                if let Ok(bytes) = std::fs::read(path) {
                    if !bytes.is_empty() {
                        return Some(bytes);
                    }
                }
            }
            last_len = Some(len);
        }
        if start.elapsed() >= timeout {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Build the argument vector for a Chromium-engine headless print-to-PDF run. The
/// program itself is set separately; this returns only the arguments. The browser
/// opens ONLY the local `file://` URL (the last argument); the offline-hardening
/// flags keep a local render from reaching the network.
fn chromium_print_args(file_url: &str, pdf_path: &Path, user_data_dir: &Path) -> Vec<String> {
    vec![
        // New headless mode (Edge 109+ / Chrome 112+): no visible window.
        "--headless=new".to_string(),
        "--disable-gpu".to_string(),
        "--no-sandbox".to_string(),
        "--disable-extensions".to_string(),
        "--no-pdf-header-footer".to_string(),
        "--run-all-compositor-stages-before-draw".to_string(),
        // Give a self-contained page a moment to lay out before the PDF is drawn.
        "--virtual-time-budget=8000".to_string(),
        // Offline hardening: a local render must never phone home.
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--disable-background-networking".to_string(),
        "--disable-component-update".to_string(),
        "--disable-sync".to_string(),
        "--disable-default-apps".to_string(),
        format!("--user-data-dir={}", user_data_dir.display()),
        format!("--print-to-pdf={}", pdf_path.display()),
        file_url.to_string(),
    ]
}

/// Turn a local filesystem path into a `file:///` URL with forward slashes.
fn file_url_for(path: &Path) -> String {
    format!("file:///{}", path.display().to_string().replace('\\', "/"))
}

/// Spawn the browser and wait for it, returning whether it exited successfully.
/// On Windows the process is created with `CREATE_NO_WINDOW` so no console or
/// browser window ever flashes, even if the browser ignores `--headless`.
fn run_browser(browser: &Path, args: &[String]) -> std::io::Result<bool> {
    let mut cmd = std::process::Command::new(browser);
    cmd.args(args);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    Ok(cmd.status()?.success())
}

/// A process-unique token for temporary file names: the process id plus a
/// monotonically increasing counter. No date, no random-number dependency.
fn unique_token() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{pid}_{n}")
}

/// The standard Windows install paths and `PATH` entries for the browsers we know
/// how to drive, Chromium engines first so a PDF-capable browser always wins over a
/// Firefox that happens to be installed too.
fn standard_candidates() -> Vec<(PathBuf, Engine)> {
    let mut out: Vec<(PathBuf, Engine)> = Vec::new();

    // Chrome (Chromium) — standard install locations.
    for p in [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ] {
        out.push((PathBuf::from(p), Engine::Chromium));
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        let mut p = PathBuf::from(local);
        p.push(r"Google\Chrome\Application\chrome.exe");
        out.push((p, Engine::Chromium));
    }

    // Edge (Chromium) — standard install locations.
    for p in [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ] {
        out.push((PathBuf::from(p), Engine::Chromium));
    }

    // Firefox (Gecko) — detected but not PDF-capable (see Engine::Gecko).
    for p in [
        r"C:\Program Files\Mozilla Firefox\firefox.exe",
        r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
    ] {
        out.push((PathBuf::from(p), Engine::Gecko));
    }

    // PATH lookups for each browser executable, in the same engine priority.
    if let Some(path_var) = std::env::var_os("PATH").and_then(|s| s.into_string().ok()) {
        let exists = |p: &Path| p.exists();
        for (exe, engine) in [
            ("chrome.exe", Engine::Chromium),
            ("msedge.exe", Engine::Chromium),
            ("firefox.exe", Engine::Gecko),
        ] {
            if let Some(found) = find_on_path(exe, &path_var, &exists) {
                out.push((found, engine));
            }
        }
    }

    out
}

/// Resolve the candidate list to a PDF engine, preferring a PDF-capable (Chromium)
/// browser. Returns the first existing Chromium browser; failing that, reports
/// whether a Gecko (Firefox) browser was seen, so the caller can name the honest
/// reason. Pure: existence is decided by the injected predicate, so this is
/// unit-testable without a real browser.
fn resolve_browser(
    candidates: &[(PathBuf, Engine)],
    exists: &dyn Fn(&Path) -> bool,
) -> BrowserResolution {
    let mut gecko_seen = false;
    for (path, engine) in candidates {
        if exists(path) {
            match engine {
                Engine::Chromium => return BrowserResolution::Chromium(path.clone()),
                Engine::Gecko => gecko_seen = true,
            }
        }
    }
    if gecko_seen {
        BrowserResolution::OnlyGecko
    } else {
        BrowserResolution::None
    }
}

/// Find `exe` in a `;`-separated PATH-like string, returning the first directory
/// entry that contains it (per `exists`). Pure and testable.
fn find_on_path(exe: &str, path_var: &str, exists: &dyn Fn(&Path) -> bool) -> Option<PathBuf> {
    for dir in path_var.split(';') {
        let dir = dir.trim();
        if dir.is_empty() {
            continue;
        }
        let candidate = Path::new(dir).join(exe);
        if exists(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // A small helper: an existence predicate that returns true only for the exact
    // paths in the allow list.
    fn only<'a>(present: &'a [&'a str]) -> impl Fn(&Path) -> bool + 'a {
        move |p: &Path| present.iter().any(|s| Path::new(s) == p)
    }

    fn candidates() -> Vec<(PathBuf, Engine)> {
        vec![
            (PathBuf::from(r"C:\chrome\chrome.exe"), Engine::Chromium),
            (PathBuf::from(r"C:\edge\msedge.exe"), Engine::Chromium),
            (PathBuf::from(r"C:\ff\firefox.exe"), Engine::Gecko),
        ]
    }

    #[test]
    fn resolves_chrome_when_only_chrome_present() {
        let r = resolve_browser(&candidates(), &only(&[r"C:\chrome\chrome.exe"]));
        assert_eq!(r, BrowserResolution::Chromium(PathBuf::from(r"C:\chrome\chrome.exe")));
    }

    #[test]
    fn resolves_edge_when_only_edge_present() {
        let r = resolve_browser(&candidates(), &only(&[r"C:\edge\msedge.exe"]));
        assert_eq!(r, BrowserResolution::Chromium(PathBuf::from(r"C:\edge\msedge.exe")));
    }

    #[test]
    fn prefers_chromium_over_firefox_when_both_present() {
        // Firefox present alongside Edge: a PDF-capable engine must win, never Gecko.
        let r = resolve_browser(
            &candidates(),
            &only(&[r"C:\ff\firefox.exe", r"C:\edge\msedge.exe"]),
        );
        assert_eq!(r, BrowserResolution::Chromium(PathBuf::from(r"C:\edge\msedge.exe")));
    }

    #[test]
    fn firefox_only_host_is_reported_as_gecko_only() {
        // Firefox is detected, but Gecko has no headless print-to-PDF flag: report
        // OnlyGecko so the caller refuses by name rather than shipping a bad file.
        let r = resolve_browser(&candidates(), &only(&[r"C:\ff\firefox.exe"]));
        assert_eq!(r, BrowserResolution::OnlyGecko);
    }

    #[test]
    fn no_browser_present_resolves_to_none() {
        let r = resolve_browser(&candidates(), &only(&[]));
        assert_eq!(r, BrowserResolution::None);
    }

    #[test]
    fn find_on_path_locates_executable_in_a_path_entry() {
        let path_var = r"C:\bin;C:\tools\chromium;C:\other";
        let found = find_on_path(
            "chrome.exe",
            path_var,
            &only(&[r"C:\tools\chromium\chrome.exe"]),
        );
        assert_eq!(found, Some(PathBuf::from(r"C:\tools\chromium\chrome.exe")));

        let missing = find_on_path("chrome.exe", path_var, &only(&[]));
        assert_eq!(missing, None);
    }

    #[test]
    fn print_args_are_headless_print_to_pdf_and_local_only() {
        let pdf = PathBuf::from(r"C:\tmp\out.pdf");
        let udd = PathBuf::from(r"C:\tmp\udd");
        let url = file_url_for(Path::new(r"C:\tmp\in.html"));
        let args = chromium_print_args(&url, &pdf, &udd);

        // Headless and print-to-pdf must both be present.
        assert!(
            args.iter().any(|a| a.starts_with("--headless")),
            "no --headless flag: {args:?}"
        );
        assert!(
            args.iter().any(|a| a == "--headless=new"),
            "not the new headless mode: {args:?}"
        );
        assert!(
            args.iter().any(|a| a.starts_with("--print-to-pdf=")),
            "no --print-to-pdf flag: {args:?}"
        );
        // The temp PDF path and the isolated user-data dir are carried through.
        assert!(
            args.iter().any(|a| a.contains("out.pdf")),
            "pdf path missing from args: {args:?}"
        );
        assert!(
            args.iter().any(|a| a.starts_with("--user-data-dir=")),
            "no isolated user-data-dir: {args:?}"
        );
        // The only URL is the LOCAL file, the last argument; nothing reaches the net.
        assert_eq!(args.last().map(String::as_str), Some(url.as_str()));
        assert!(
            !args.iter().any(|a| a.contains("http://") || a.contains("https://")),
            "a network URL leaked into the args: {args:?}"
        );
    }

    #[test]
    fn file_url_uses_forward_slashes() {
        let url = file_url_for(Path::new(r"C:\Users\x\in.html"));
        assert_eq!(url, "file:///C:/Users/x/in.html");
        assert!(!url.contains('\\'), "backslash leaked into file URL: {url}");
    }

    #[test]
    fn unique_token_is_distinct_per_call() {
        assert_ne!(unique_token(), unique_token());
    }

    #[test]
    fn pdf_target_available_is_callable() {
        // Environment-dependent: assert only that detection runs and returns a bool
        // without launching anything. The value is whatever this host happens to be.
        let _ = pdf_target_available();
    }

    // The one real end-to-end test: it drives an actual installed browser to print a
    // PDF. It is `#[ignore]`d because a live browser is flaky, environment-dependent,
    // and can hang or pop a window; it is never a required green test. Run it
    // explicitly with `cargo test -p stegano-files -- --ignored real_browser`.
    #[test]
    #[ignore = "launches a real installed browser; run manually with --ignored"]
    fn real_browser_end_to_end_produces_a_pdf() {
        let html = "<!DOCTYPE html><html><head><meta charset=\"utf-8\">\
                    <title>t</title></head><body><h1>SteganoHero</h1>\
                    <p>Phase D1 end-to-end.</p></body></html>";
        let bytes = html_to_pdf(html).expect("a browser should produce a PDF here");
        assert!(bytes.starts_with(b"%PDF"), "not a PDF: first bytes {:?}", &bytes[..8.min(bytes.len())]);
    }
}
