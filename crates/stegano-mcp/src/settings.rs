//! Runtime settings shared by both transports.
//!
//! These are the values an operator is allowed to change while the tool is
//! deployed: interface language, where extension bundles are looked for, the
//! per-mission fill ratios, and the key-derivation parameters.
//!
//! Every write is validated field by field. A rejected write changes nothing
//! and returns one entry per offending field, naming the field, the value that
//! was refused and the reason. A partially applied settings update is not a
//! thing this module can produce.
//!
//! The bearer token lives beside these values because a deployment carries one
//! configuration, but it is not part of the editable surface: it is never read
//! back through the configuration zone and never changed through it.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// One rejected field of an attempted write.
#[derive(Debug, Clone, Serialize)]
pub struct FieldRejection {
    /// Dotted path of the offending field, for example `density.conceal`.
    pub field: String,
    /// The value that was refused, rendered for display.
    pub value: String,
    /// Why it was refused, in full.
    pub reason: String,
}

/// Per-mission fill ratios.
///
/// A fill ratio is the share of the available positions a mission is willing
/// to occupy. Concealment wants few, marking wants many. These are configured
/// planning values: the engine measures raw capacity and enforces that, so a
/// ratio narrows what a caller should plan for, it does not narrow what the
/// engine will accept. Every report that uses one says so.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DensitySettings {
    pub conceal: f64,
    pub sign: f64,
    pub mark: f64,
}

impl Default for DensitySettings {
    fn default() -> Self {
        Self {
            conceal: 0.25,
            sign: 0.50,
            mark: 0.85,
        }
    }
}

/// Accepted range for each mission, as a closed interval.
pub const DENSITY_RANGES: [(&str, f64, f64); 3] = [
    ("conceal", 0.05, 0.60),
    ("sign", 0.10, 0.90),
    ("mark", 0.20, 1.00),
];

/// Key-derivation parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoSettings {
    /// Memory cost, in kibibytes.
    pub memory_kib: u32,
    /// Number of passes.
    pub time_cost: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
    /// Confidentiality identifier offered when a caller names none.
    pub default_cipher: String,
}

impl Default for CryptoSettings {
    fn default() -> Self {
        Self {
            memory_kib: 65536,
            time_cost: 3,
            parallelism: 1,
            default_cipher: "chacha20_poly1305".to_string(),
        }
    }
}

/// Where the REST surface listens, and under what token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    /// Address to bind. Loopback unless `allow_non_loopback` is set.
    pub bind_address: String,
    /// Binding outside loopback requires this to be set deliberately.
    pub allow_non_loopback: bool,
    /// Bearer token. Generated once, on first run. Never returned by the
    /// configuration zone and never changed through it.
    #[serde(default)]
    pub bearer_token: String,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1:3721".to_string(),
            allow_non_loopback: false,
            bearer_token: String::new(),
        }
    }
}

/// The complete runtime settings of a deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default = "default_language")]
    pub language: String,
    #[serde(default)]
    pub plugin_paths: Vec<String>,
    #[serde(default)]
    pub density: DensitySettings,
    #[serde(default)]
    pub crypto: CryptoSettings,
    #[serde(default)]
    pub server: ServerSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            language: default_language(),
            plugin_paths: Vec::new(),
            density: DensitySettings::default(),
            crypto: CryptoSettings::default(),
            server: ServerSettings::default(),
        }
    }
}

fn default_language() -> String {
    "en".to_string()
}

/// Languages the interface layer ships.
pub const KNOWN_LANGUAGES: [&str; 2] = ["en", "fr"];

impl Settings {
    /// Fill ratio for a named mission, or `None` if the mission is unknown.
    pub fn fill_ratio(&self, mission: &str) -> Option<f64> {
        match mission {
            "conceal" => Some(self.density.conceal),
            "sign" => Some(self.density.sign),
            "mark" => Some(self.density.mark),
            _ => None,
        }
    }

    /// Every mission and its configured ratio, in a stable order.
    pub fn missions(&self) -> BTreeMap<&'static str, f64> {
        BTreeMap::from([
            ("conceal", self.density.conceal),
            ("mark", self.density.mark),
            ("sign", self.density.sign),
        ])
    }

    /// Check every field. Returns one rejection per offending field.
    ///
    /// Nothing here repairs a bad value: a value out of range is refused, not
    /// clamped, because a clamped value would be applied without the caller
    /// ever learning that the value they asked for was not the value in force.
    pub fn validate(&self) -> Vec<FieldRejection> {
        let mut rejections = Vec::new();

        if !KNOWN_LANGUAGES.contains(&self.language.as_str()) {
            rejections.push(FieldRejection {
                field: "language".into(),
                value: self.language.clone(),
                reason: format!(
                    "unknown language: the interface ships {}",
                    KNOWN_LANGUAGES.join(", ")
                ),
            });
        }

        for (index, path) in self.plugin_paths.iter().enumerate() {
            if path.trim().is_empty() {
                rejections.push(FieldRejection {
                    field: format!("plugin_paths[{index}]"),
                    value: path.clone(),
                    reason: "empty path".into(),
                });
            } else if !Path::new(path).is_dir() {
                rejections.push(FieldRejection {
                    field: format!("plugin_paths[{index}]"),
                    value: path.clone(),
                    reason: "path does not resolve to a directory that exists".into(),
                });
            }
        }

        for (mission, low, high) in DENSITY_RANGES {
            let value = self
                .fill_ratio(mission)
                .expect("DENSITY_RANGES must only name known missions");
            if !value.is_finite() {
                rejections.push(FieldRejection {
                    field: format!("density.{mission}"),
                    value: format!("{value}"),
                    reason: "not a finite number".into(),
                });
            } else if value < low || value > high {
                rejections.push(FieldRejection {
                    field: format!("density.{mission}"),
                    value: format!("{value}"),
                    reason: format!("outside the accepted range for this mission, {low} to {high}"),
                });
            }
        }

        if !(8192..=1_048_576).contains(&self.crypto.memory_kib) {
            rejections.push(FieldRejection {
                field: "crypto.memory_kib".into(),
                value: self.crypto.memory_kib.to_string(),
                reason: "outside the accepted range, 8192 to 1048576".into(),
            });
        }
        if !(1..=10).contains(&self.crypto.time_cost) {
            rejections.push(FieldRejection {
                field: "crypto.time_cost".into(),
                value: self.crypto.time_cost.to_string(),
                reason: "outside the accepted range, 1 to 10".into(),
            });
        }
        if !(1..=16).contains(&self.crypto.parallelism) {
            rejections.push(FieldRejection {
                field: "crypto.parallelism".into(),
                value: self.crypto.parallelism.to_string(),
                reason: "outside the accepted range, 1 to 16".into(),
            });
        }
        if self.crypto.default_cipher != crate::catalogue::CIPHER_NONE {
            if let Err(reason) = crate::catalogue::cipher(&self.crypto.default_cipher) {
                rejections.push(FieldRejection {
                    field: "crypto.default_cipher".into(),
                    value: self.crypto.default_cipher.clone(),
                    reason,
                });
            }
        }

        match self.bind_target() {
            Err(reason) => rejections.push(FieldRejection {
                field: "server.bind_address".into(),
                value: self.server.bind_address.clone(),
                reason,
            }),
            Ok(is_loopback) => {
                if !is_loopback && !self.server.allow_non_loopback {
                    rejections.push(FieldRejection {
                        field: "server.bind_address".into(),
                        value: self.server.bind_address.clone(),
                        reason: "binding outside loopback requires server.allow_non_loopback to be set deliberately".into(),
                    });
                }
            }
        }

        rejections
    }

    /// Parse the bind address and report whether it stays on loopback.
    pub fn bind_target(&self) -> Result<bool, String> {
        let address: std::net::SocketAddr = self
            .server
            .bind_address
            .parse()
            .map_err(|_| "not a host:port address".to_string())?;
        Ok(address.ip().is_loopback())
    }

    /// The editable view, as returned by the configuration zone.
    ///
    /// The bearer token is reported as present or absent, never by value.
    pub fn public_view(&self) -> Value {
        json!({
            "language": self.language,
            "plugin_paths": self.plugin_paths,
            "density": {
                "conceal": self.density.conceal,
                "sign": self.density.sign,
                "mark": self.density.mark,
                "note": "configured planning values. A fill ratio narrows what a caller should plan for; the capacity report states, per carrier, the secret capacity the engine actually accepts.",
            },
            "crypto": {
                "memory_kib": self.crypto.memory_kib,
                "time_cost": self.crypto.time_cost,
                "parallelism": self.crypto.parallelism,
                "default_cipher": self.crypto.default_cipher,
            },
            "server": {
                "bind_address": self.server.bind_address,
                "allow_non_loopback": self.server.allow_non_loopback,
                "bearer_token_present": !self.server.bearer_token.is_empty(),
            },
        })
    }

    /// The accepted range of every editable field, so a caller can check a
    /// value before sending it.
    pub fn constraints() -> Value {
        json!({
            "language": { "one_of": KNOWN_LANGUAGES },
            "plugin_paths": { "each": "path of a directory that exists" },
            "density": {
                "conceal": { "minimum": DENSITY_RANGES[0].1, "maximum": DENSITY_RANGES[0].2 },
                "sign": { "minimum": DENSITY_RANGES[1].1, "maximum": DENSITY_RANGES[1].2 },
                "mark": { "minimum": DENSITY_RANGES[2].1, "maximum": DENSITY_RANGES[2].2 },
            },
            "crypto": {
                "memory_kib": { "minimum": 8192, "maximum": 1_048_576 },
                "time_cost": { "minimum": 1, "maximum": 10 },
                "parallelism": { "minimum": 1, "maximum": 16 },
                "default_cipher": { "one_of": crate::catalogue::CIPHER_ORDER },
            },
            "server": {
                "bind_address": { "format": "host:port" },
                "allow_non_loopback": { "type": "boolean", "note": "required before any bind outside loopback is accepted" },
                "bearer_token": { "editable": false, "note": "generated once, on first run. Not readable and not writable through the configuration zone." },
            },
        })
    }

    /// Apply a partial update, expressed as the same shape as `public_view`.
    ///
    /// The update is applied to a copy, the copy is validated, and only a copy
    /// that passes replaces the original. An unknown field is refused rather
    /// than ignored, so a misspelt key can never look like it took effect.
    pub fn with_update(&self, update: &Value) -> Result<Settings, Vec<FieldRejection>> {
        let object = match update.as_object() {
            Some(object) => object,
            None => {
                return Err(vec![FieldRejection {
                    field: "(root)".into(),
                    value: shorten(update),
                    reason: "the update must be an object".into(),
                }])
            }
        };

        let mut next = self.clone();
        let mut rejections = Vec::new();

        for (key, value) in object {
            match key.as_str() {
                "language" => match value.as_str() {
                    Some(text) => next.language = text.to_string(),
                    None => rejections.push(type_rejection("language", value, "a string")),
                },
                "plugin_paths" => match value.as_array() {
                    Some(items) => {
                        let mut paths = Vec::with_capacity(items.len());
                        for (index, item) in items.iter().enumerate() {
                            match item.as_str() {
                                Some(text) => paths.push(text.to_string()),
                                None => rejections.push(type_rejection(
                                    &format!("plugin_paths[{index}]"),
                                    item,
                                    "a string",
                                )),
                            }
                        }
                        next.plugin_paths = paths;
                    }
                    None => {
                        rejections.push(type_rejection("plugin_paths", value, "an array of strings"))
                    }
                },
                "density" => apply_density(&mut next, value, &mut rejections),
                "crypto" => apply_crypto(&mut next, value, &mut rejections),
                "server" => apply_server(&mut next, value, &mut rejections),
                other => rejections.push(FieldRejection {
                    field: other.to_string(),
                    value: shorten(value),
                    reason: "unknown setting".into(),
                }),
            }
        }

        rejections.extend(next.validate());
        if rejections.is_empty() {
            Ok(next)
        } else {
            Err(rejections)
        }
    }

    /// Read settings from disk. A missing file yields the defaults, so a fresh
    /// deployment starts from a known state rather than from nothing.
    pub fn load(path: &Path) -> Result<Settings, String> {
        if !path.exists() {
            return Ok(Settings::default());
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        serde_json::from_str(&text).map_err(|e| format!("cannot parse {}: {e}", path.display()))
    }

    /// Write settings to disk.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
            }
        }
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| format!("cannot serialise settings: {e}"))?;
        std::fs::write(path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))
    }
}

fn apply_density(next: &mut Settings, value: &Value, rejections: &mut Vec<FieldRejection>) {
    let object = match value.as_object() {
        Some(object) => object,
        None => {
            rejections.push(type_rejection("density", value, "an object"));
            return;
        }
    };
    for (key, item) in object {
        // `note` is the read-only explanation carried by the readable view.
        // Accepting it unchanged is what lets a caller read the view, edit one
        // field and send the whole thing back.
        if key == "note" {
            continue;
        }
        let number = match item.as_f64() {
            Some(number) => number,
            None => {
                rejections.push(type_rejection(&format!("density.{key}"), item, "a number"));
                continue;
            }
        };
        match key.as_str() {
            "conceal" => next.density.conceal = number,
            "sign" => next.density.sign = number,
            "mark" => next.density.mark = number,
            other => rejections.push(FieldRejection {
                field: format!("density.{other}"),
                value: shorten(item),
                reason: "unknown mission".into(),
            }),
        }
    }
}

fn apply_crypto(next: &mut Settings, value: &Value, rejections: &mut Vec<FieldRejection>) {
    let object = match value.as_object() {
        Some(object) => object,
        None => {
            rejections.push(type_rejection("crypto", value, "an object"));
            return;
        }
    };
    for (key, item) in object {
        match key.as_str() {
            "memory_kib" | "time_cost" | "parallelism" => {
                match item.as_u64().and_then(|n| u32::try_from(n).ok()) {
                    Some(number) => match key.as_str() {
                        "memory_kib" => next.crypto.memory_kib = number,
                        "time_cost" => next.crypto.time_cost = number,
                        _ => next.crypto.parallelism = number,
                    },
                    None => rejections.push(type_rejection(
                        &format!("crypto.{key}"),
                        item,
                        "a whole number that fits in 32 bits",
                    )),
                }
            }
            "default_cipher" => match item.as_str() {
                Some(text) => next.crypto.default_cipher = text.to_string(),
                None => {
                    rejections.push(type_rejection("crypto.default_cipher", item, "a string"))
                }
            },
            other => rejections.push(FieldRejection {
                field: format!("crypto.{other}"),
                value: shorten(item),
                reason: "unknown setting".into(),
            }),
        }
    }
}

fn apply_server(next: &mut Settings, value: &Value, rejections: &mut Vec<FieldRejection>) {
    let object = match value.as_object() {
        Some(object) => object,
        None => {
            rejections.push(type_rejection("server", value, "an object"));
            return;
        }
    };
    for (key, item) in object {
        match key.as_str() {
            "bind_address" => match item.as_str() {
                Some(text) => next.server.bind_address = text.to_string(),
                None => rejections.push(type_rejection("server.bind_address", item, "a string")),
            },
            "allow_non_loopback" => match item.as_bool() {
                Some(flag) => next.server.allow_non_loopback = flag,
                None => rejections.push(type_rejection(
                    "server.allow_non_loopback",
                    item,
                    "a boolean",
                )),
            },
            "bearer_token" => rejections.push(FieldRejection {
                field: "server.bearer_token".into(),
                value: "(withheld)".into(),
                reason: "the bearer token is not editable through the configuration zone".into(),
            }),
            // Read-only mirror carried by the readable view. Sending it back
            // unchanged is accepted so a caller can edit one field of the view
            // and return the whole object; sending back a different claim is
            // refused rather than quietly dropped.
            "bearer_token_present" => {
                let present = !next.server.bearer_token.is_empty();
                if item.as_bool() != Some(present) {
                    rejections.push(FieldRejection {
                        field: "server.bearer_token_present".into(),
                        value: shorten(item),
                        reason: "read-only field: it reports whether a token is configured and cannot be set".into(),
                    });
                }
            }
            other => rejections.push(FieldRejection {
                field: format!("server.{other}"),
                value: shorten(item),
                reason: "unknown setting".into(),
            }),
        }
    }
}

fn type_rejection(field: &str, value: &Value, expected: &str) -> FieldRejection {
    FieldRejection {
        field: field.to_string(),
        value: shorten(value),
        reason: format!("expected {expected}"),
    }
}

/// Render a value for a rejection message, bounded so a large payload cannot
/// be echoed back through an error.
fn shorten(value: &Value) -> String {
    let rendered = value.to_string();
    if rendered.chars().count() > 60 {
        let clipped: String = rendered.chars().take(60).collect();
        format!("{clipped}...")
    } else {
        rendered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_valid() {
        assert!(Settings::default().validate().is_empty());
    }

    #[test]
    fn the_default_mission_ratios_match_the_recorded_defaults() {
        let settings = Settings::default();
        assert_eq!(settings.fill_ratio("conceal"), Some(0.25));
        assert_eq!(settings.fill_ratio("sign"), Some(0.50));
        assert_eq!(settings.fill_ratio("mark"), Some(0.85));
        assert_eq!(settings.fill_ratio("unknown_mission"), None);
    }

    #[test]
    fn a_ratio_outside_its_mission_range_is_refused_by_name() {
        let settings = Settings::default();
        let rejections = settings
            .with_update(&json!({ "density": { "conceal": 0.95 } }))
            .expect_err("must be refused");
        assert_eq!(rejections.len(), 1);
        assert_eq!(rejections[0].field, "density.conceal");
        assert!(rejections[0].reason.contains("0.05"));
        assert!(rejections[0].reason.contains("0.6"));
    }

    #[test]
    fn a_refused_write_leaves_the_original_untouched() {
        let settings = Settings::default();
        assert!(settings
            .with_update(&json!({ "density": { "mark": 0.10 } }))
            .is_err());
        assert_eq!(settings.density.mark, 0.85);
    }

    #[test]
    fn an_unknown_setting_is_refused_rather_than_ignored() {
        let rejections = Settings::default()
            .with_update(&json!({ "densty": { "conceal": 0.3 } }))
            .expect_err("must be refused");
        assert_eq!(rejections[0].field, "densty");
        assert_eq!(rejections[0].reason, "unknown setting");
    }

    #[test]
    fn an_unknown_language_is_refused() {
        let rejections = Settings::default()
            .with_update(&json!({ "language": "kl" }))
            .expect_err("must be refused");
        assert_eq!(rejections[0].field, "language");
    }

    #[test]
    fn a_plugin_path_that_does_not_exist_is_refused() {
        let rejections = Settings::default()
            .with_update(&json!({ "plugin_paths": ["./definitely-not-here-8f21"] }))
            .expect_err("must be refused");
        assert_eq!(rejections[0].field, "plugin_paths[0]");
    }

    #[test]
    fn an_unregistered_default_cipher_is_refused() {
        let rejections = Settings::default()
            .with_update(&json!({ "crypto": { "default_cipher": "rot13" } }))
            .expect_err("must be refused");
        assert_eq!(rejections[0].field, "crypto.default_cipher");
        assert!(rejections[0].reason.contains("rot13"));
    }

    #[test]
    fn key_derivation_parameters_outside_range_are_refused() {
        let rejections = Settings::default()
            .with_update(&json!({ "crypto": { "memory_kib": 16, "time_cost": 99 } }))
            .expect_err("must be refused");
        let fields: Vec<&str> = rejections.iter().map(|r| r.field.as_str()).collect();
        assert!(fields.contains(&"crypto.memory_kib"));
        assert!(fields.contains(&"crypto.time_cost"));
    }

    #[test]
    fn a_non_loopback_bind_needs_the_deliberate_flag() {
        let rejections = Settings::default()
            .with_update(&json!({ "server": { "bind_address": "0.0.0.0:3721" } }))
            .expect_err("must be refused");
        assert_eq!(rejections[0].field, "server.bind_address");
        assert!(rejections[0].reason.contains("allow_non_loopback"));

        let accepted = Settings::default()
            .with_update(&json!({
                "server": { "bind_address": "0.0.0.0:3721", "allow_non_loopback": true }
            }))
            .expect("the deliberate flag must make it acceptable");
        assert!(!accepted.bind_target().expect("must parse"));
    }

    #[test]
    fn a_malformed_bind_address_is_refused() {
        let rejections = Settings::default()
            .with_update(&json!({ "server": { "bind_address": "not an address" } }))
            .expect_err("must be refused");
        assert_eq!(rejections[0].field, "server.bind_address");
    }

    #[test]
    fn the_bearer_token_is_neither_readable_nor_writable_through_the_zone() {
        let mut settings = Settings::default();
        settings.server.bearer_token = "sh_secret_value_for_the_test".into();

        let view = settings.public_view().to_string();
        assert!(!view.contains("sh_secret_value_for_the_test"));
        assert!(view.contains("bearer_token_present"));

        let rejections = settings
            .with_update(&json!({ "server": { "bearer_token": "replacement" } }))
            .expect_err("must be refused");
        assert_eq!(rejections[0].field, "server.bearer_token");
        assert_eq!(rejections[0].value, "(withheld)");
    }

    #[test]
    fn an_accepted_write_takes_effect_in_full() {
        let updated = Settings::default()
            .with_update(&json!({
                "language": "fr",
                "density": { "conceal": 0.4, "sign": 0.6 },
                "crypto": { "time_cost": 4 }
            }))
            .expect("must be accepted");
        assert_eq!(updated.language, "fr");
        assert_eq!(updated.density.conceal, 0.4);
        assert_eq!(updated.density.sign, 0.6);
        assert_eq!(updated.density.mark, 0.85);
        assert_eq!(updated.crypto.time_cost, 4);
    }

    /// The view a caller reads back must be a shape it can send back.
    #[test]
    fn the_public_view_round_trips_through_an_update() {
        let settings = Settings::default();
        let restored = settings
            .with_update(&settings.public_view())
            .expect("the readable view must be an acceptable update");
        assert_eq!(restored.language, settings.language);
        assert_eq!(restored.density.mark, settings.density.mark);
    }

    #[test]
    fn a_rejection_never_echoes_a_long_value_in_full() {
        let long = "x".repeat(4000);
        let rejections = Settings::default()
            .with_update(&json!({ "unknown_key": long }))
            .expect_err("must be refused");
        assert!(rejections[0].value.chars().count() <= 63);
    }
}
