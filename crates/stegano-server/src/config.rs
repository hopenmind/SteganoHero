//! Start-up configuration for the REST surface.
//!
//! Three rules decide whether this surface starts at all.
//!
//! - It binds loopback. Binding anywhere else needs the flag that says so
//!   deliberately, and says so again in the log at every start.
//! - It runs under a bearer token. The token is generated once, on the first
//!   start, and written to the configuration file. A configuration that exists
//!   but carries no token is a refusal to start, never a start without one.
//! - Settings that do not pass their own validation are a refusal to start.
//!   Starting on repaired values would run the deployment under settings the
//!   operator never chose.

use std::path::Path;

use stegano_mcp::settings::Settings;

/// What a successful start-up resolved to.
#[derive(Debug)]
pub struct Startup {
    pub settings: Settings,
    /// True when this start generated the token, so it can be shown once.
    pub token_generated: bool,
    /// Lines the operator must see at every start.
    pub warnings: Vec<String>,
}

/// Resolve the configuration, or refuse to start and say why.
pub fn prepare(path: &Path) -> Result<Startup, String> {
    let existed = path.exists();

    let mut settings = Settings::load(path).map_err(|reason| {
        format!("refusing to start: the configuration at {} could not be read: {reason}", path.display())
    })?;

    let mut token_generated = false;
    if !existed {
        settings.server.bearer_token = generate_token();
        token_generated = true;
        settings.save(path).map_err(|reason| {
            format!("refusing to start: the configuration could not be written: {reason}")
        })?;
    }

    if settings.server.bearer_token.trim().is_empty() {
        return Err(format!(
            "refusing to start: the configuration at {} carries no bearer token. \
             Add one under server.bearer_token, or delete the file to have one generated. \
             This surface does not run without one.",
            path.display()
        ));
    }

    let rejections = settings.validate();
    if !rejections.is_empty() {
        let detail = rejections
            .iter()
            .map(|r| format!("{} = {}: {}", r.field, r.value, r.reason))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!(
            "refusing to start: the configuration at {} is not usable. {detail}",
            path.display()
        ));
    }

    let mut warnings = Vec::new();
    let loopback = settings
        .bind_target()
        .map_err(|reason| format!("refusing to start: server.bind_address is unusable: {reason}"))?;
    if !loopback {
        warnings.push(format!(
            "WARNING: binding {} reaches beyond this machine. Every command on this surface is available to anything that can reach that address and holds the token.",
            settings.server.bind_address
        ));
    }

    Ok(Startup {
        settings,
        token_generated,
        warnings,
    })
}

/// Generate a bearer token.
fn generate_token() -> String {
    let bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("shb_{hex}")
}

/// Compare a presented token with the configured one without letting the
/// comparison finish early on the first differing byte.
pub fn token_matches(presented: &str, configured: &str) -> bool {
    let presented = presented.as_bytes();
    let configured = configured.as_bytes();
    if configured.is_empty() {
        return false;
    }
    let mut difference = presented.len() ^ configured.len();
    for index in 0..presented.len().max(configured.len()) {
        let left = presented.get(index).copied().unwrap_or(0);
        let right = configured.get(index).copied().unwrap_or(0);
        difference |= (left ^ right) as usize;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch path that removes itself.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "stegano-server-{name}-{}.json",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn the_first_start_generates_a_token_and_writes_it() {
        let scratch = Scratch::new("first-start");
        let started = prepare(scratch.path()).expect("a fresh deployment must start");
        assert!(started.token_generated);
        assert!(started.settings.server.bearer_token.starts_with("shb_"));
        assert!(scratch.path().exists());

        // The second start reuses the same token rather than issuing another.
        let again = prepare(scratch.path()).expect("the second start must succeed");
        assert!(!again.token_generated);
        assert_eq!(
            again.settings.server.bearer_token,
            started.settings.server.bearer_token
        );
    }

    #[test]
    fn a_configuration_without_a_token_refuses_to_start() {
        let scratch = Scratch::new("no-token");
        let mut settings = Settings::default();
        settings.server.bearer_token = String::new();
        settings.save(scratch.path()).expect("must write");

        let refusal = prepare(scratch.path()).expect_err("must refuse to start");
        assert!(refusal.contains("refusing to start"));
        assert!(refusal.contains("bearer token"));
    }

    #[test]
    fn a_configuration_with_a_blank_token_refuses_to_start() {
        let scratch = Scratch::new("blank-token");
        let mut settings = Settings::default();
        settings.server.bearer_token = "   ".into();
        settings.save(scratch.path()).expect("must write");
        assert!(prepare(scratch.path()).is_err());
    }

    #[test]
    fn the_default_bind_is_loopback_and_carries_no_warning() {
        let scratch = Scratch::new("loopback");
        let started = prepare(scratch.path()).expect("must start");
        assert_eq!(started.settings.server.bind_address, "127.0.0.1:3721");
        assert!(started.settings.bind_target().expect("must parse"));
        assert!(started.warnings.is_empty());
    }

    #[test]
    fn a_bind_beyond_this_machine_needs_the_flag_and_still_warns() {
        let scratch = Scratch::new("open-bind");
        let mut settings = Settings::default();
        settings.server.bearer_token = "shb_test".into();
        settings.server.bind_address = "0.0.0.0:3721".into();
        settings.save(scratch.path()).expect("must write");

        // Without the flag, the configuration does not pass its own checks.
        let refusal = prepare(scratch.path()).expect_err("must refuse without the flag");
        assert!(refusal.contains("allow_non_loopback"));

        // With the flag, it starts and says so at every start.
        settings.server.allow_non_loopback = true;
        settings.save(scratch.path()).expect("must write");
        let started = prepare(scratch.path()).expect("must start with the flag");
        assert_eq!(started.warnings.len(), 1);
        assert!(started.warnings[0].starts_with("WARNING:"));
    }

    #[test]
    fn a_configuration_that_fails_its_own_checks_refuses_to_start() {
        let scratch = Scratch::new("bad-values");
        let mut settings = Settings::default();
        settings.server.bearer_token = "shb_test".into();
        settings.density.mark = 5.0;
        settings.save(scratch.path()).expect("must write");

        let refusal = prepare(scratch.path()).expect_err("must refuse to start");
        assert!(refusal.contains("density.mark"));
    }

    #[test]
    fn a_token_comparison_accepts_only_the_exact_token() {
        assert!(token_matches("shb_abc", "shb_abc"));
        assert!(!token_matches("shb_abd", "shb_abc"));
        assert!(!token_matches("shb_ab", "shb_abc"));
        assert!(!token_matches("shb_abcd", "shb_abc"));
        assert!(!token_matches("", "shb_abc"));
        assert!(!token_matches("anything", ""));
    }
}
