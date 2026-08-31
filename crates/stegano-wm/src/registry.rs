//! A registry of PUBLIC watermark configurations and the sweep over it.
//!
//! Replaying a public config is the one tier where detecting a third party's
//! mark is CERTAIN at the level of the test. A hit names the CONFIG, never the
//! author: a stolen watermark can be forged, so presence is not paternity.

use crate::config::{detect_z, WmConfig};

/// A set of public watermark configurations to test a text against.
pub struct Registry {
    entries: Vec<WmConfig>,
}

impl Registry {
    pub fn new(entries: Vec<WmConfig>) -> Self {
        Self { entries }
    }

    pub fn entries(&self) -> &[WmConfig] {
        &self.entries
    }

    /// z-score of the text under every registered config.
    pub fn sweep(&self, tokens: &[u32]) -> Vec<(String, f64)> {
        self.entries
            .iter()
            .map(|c| (c.name.clone(), detect_z(c, tokens)))
            .collect()
    }

    /// The highest-scoring config whose z clears `tau` (a named hit), if any.
    ///
    /// Returns `None` when nothing clears the threshold. That silence is the
    /// honest, correct answer for a secret-key mark the registry cannot reach.
    pub fn best_hit(&self, tokens: &[u32], tau: f64) -> Option<(String, f64)> {
        self.sweep(tokens)
            .into_iter()
            .filter(|(_, z)| *z >= tau)
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
    }
}

/// The public-config registry, seeded with verifiable defaults.
///
/// The transformers `WatermarkingConfig` default hashing key is the millionth
/// prime, 15485863; the remaining entries mirror common public demo and
/// standard configurations across context widths. These are our-PRF analogs:
/// they detect a mark made with this same scheme and are honest about not yet
/// being bit-exact with a specific library's partition layout.
pub fn default_registry() -> Registry {
    Registry::new(vec![
        WmConfig::new("kgw-hash:transformers-default-h1", 15_485_863, 0.25, 1),
        WmConfig::new("kgw-hash:transformers-default-g05", 15_485_863, 0.5, 1),
        WmConfig::new("kgw-hash:transformers-default-h2", 15_485_863, 0.25, 2),
        WmConfig::new("kgw-hash:public-standard-h3", 20_260_827, 0.25, 3),
        WmConfig::new("kgw-hash:vendor-demo-h4", 0x00C0_FFEE, 0.25, 4),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_the_expected_public_entries() {
        let reg = default_registry();
        assert_eq!(reg.entries().len(), 5);
        assert_eq!(reg.entries()[0].name, "kgw-hash:transformers-default-h1");
    }
}
