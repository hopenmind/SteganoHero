//! The live registry seen by an assisting agent.
//!
//! Every list this module produces is built by instantiating the registered
//! identifiers through the core, so the surface cannot advertise something the
//! core does not provide. An identifier that fails to build is a hard error,
//! not a silently shortened list.
//!
//! Each identifier carries a capability label: what it is good for, how well
//! its result survives redistribution, and how visible it is to an analyst.
//! Labels never describe a mechanism. An identifier that reaches the registry
//! without a label is reported with its label missing and a reason, never with
//! a substitute drawn from somewhere else.

use serde_json::{json, Value};

use stegano_core::{
    crypto::{Aes128, Aes256, Caesar, ChaCha20, Xor},
    stego::{Bidi, Homoglyph, WhitespaceVar, ZeroWidth},
    traits::{CryptoMethod, StegoMethod},
};

/// Identifier meaning "no confidentiality layer at all".
pub const CIPHER_NONE: &str = "none";

/// Canonical application order for carriers.
///
/// A selection is always reordered into this order before the core sees it, so
/// the same selection always produces the same layering. The order satisfies
/// the core's own composition rules, which are re-checked at call time by
/// `pipeline::validate_composition` rather than assumed here.
pub const CARRIER_ORDER: [&str; 4] = ["zero_width", "whitespace_var", "bidi", "homoglyph"];

/// Confidentiality identifiers, in the order they are offered.
pub const CIPHER_ORDER: [&str; 5] = [
    "aes256_gcm",
    "chacha20_poly1305",
    "aes128_gcm",
    "caesar",
    "xor",
];

/// Capability label for a carrier identifier.
struct CarrierLabel {
    id: &'static str,
    /// What choosing this identifier buys the caller.
    purpose: &'static str,
    /// How well the result survives being copied, exported and re-imported.
    durability: &'static str,
    /// What an analyst inspecting the result would be able to say about it.
    exposure: &'static str,
}

/// Capability label for a confidentiality identifier.
struct CipherLabel {
    id: &'static str,
    purpose: &'static str,
    /// Whether the layer detects tampering by itself.
    authenticated: bool,
    strength: &'static str,
}

const CARRIER_LABELS: [CarrierLabel; 4] = [
    CarrierLabel {
        id: "zero_width",
        purpose: "Carries a payload alongside the text without altering a single visible character.",
        durability: "low: a routine cleanup pass removes it",
        exposure: "high: a character census locates it immediately",
    },
    CarrierLabel {
        id: "whitespace_var",
        purpose: "Carries a payload alongside the text without altering a single visible character.",
        durability: "low: a routine cleanup pass removes it",
        exposure: "high: a character census locates it immediately",
    },
    CarrierLabel {
        id: "bidi",
        purpose: "Carries a payload alongside the text without altering a single visible character.",
        durability: "low to medium: survives plain copying, removed by sanitisers",
        exposure: "high: a character census locates it immediately",
    },
    CarrierLabel {
        id: "homoglyph",
        purpose: "Carries a payload inside the visible text itself, so the result survives being copied and re-exported.",
        durability: "high: survives copying, export to document formats and normalisation",
        exposure: "high: a character census locates it immediately, at any density. This carrier is not concealed against an analyst who inspects codepoints.",
    },
];

const CIPHER_LABELS: [CipherLabel; 5] = [
    CipherLabel {
        id: "aes256_gcm",
        purpose: "Protects the payload and detects any alteration of it.",
        authenticated: true,
        strength: "strong",
    },
    CipherLabel {
        id: "chacha20_poly1305",
        purpose: "Protects the payload and detects any alteration of it.",
        authenticated: true,
        strength: "strong",
    },
    CipherLabel {
        id: "aes128_gcm",
        purpose: "Protects the payload and detects any alteration of it.",
        authenticated: true,
        strength: "strong",
    },
    CipherLabel {
        id: "caesar",
        purpose: "Retained reference layer. Protects the payload but does not detect alteration of it.",
        authenticated: false,
        strength: "reference only, not for confidential material",
    },
    CipherLabel {
        id: "xor",
        purpose: "Retained reference layer. Protects the payload but does not detect alteration of it.",
        authenticated: false,
        strength: "reference only, not for confidential material",
    },
];

/// Build a carrier from its identifier.
pub fn carrier(id: &str) -> Result<Box<dyn StegoMethod>, String> {
    match id {
        "zero_width" => Ok(Box::new(ZeroWidth::new())),
        "whitespace_var" => Ok(Box::new(WhitespaceVar::new())),
        "bidi" => Ok(Box::new(Bidi::new())),
        "homoglyph" => Ok(Box::new(Homoglyph::new())),
        other => Err(format!(
            "unknown carrier identifier '{other}': known identifiers are {}",
            CARRIER_ORDER.join(", ")
        )),
    }
}

/// Every registered carrier, in canonical order.
pub fn all_carriers() -> Vec<Box<dyn StegoMethod>> {
    CARRIER_ORDER
        .iter()
        .map(|id| carrier(id).expect("CARRIER_ORDER must only hold registered identifiers"))
        .collect()
}

/// Build a confidentiality layer from its identifier.
pub fn cipher(id: &str) -> Result<Box<dyn CryptoMethod>, String> {
    match id {
        "aes256_gcm" => Ok(Box::new(Aes256::new())),
        "aes128_gcm" => Ok(Box::new(Aes128::new())),
        "chacha20_poly1305" => Ok(Box::new(ChaCha20::new())),
        "caesar" => Ok(Box::new(Caesar::new())),
        "xor" => Ok(Box::new(Xor::new())),
        other => Err(format!(
            "unknown cipher identifier '{other}': known identifiers are {}, or '{CIPHER_NONE}'",
            CIPHER_ORDER.join(", ")
        )),
    }
}

/// Every registered confidentiality layer, in canonical order.
pub fn all_ciphers() -> Vec<Box<dyn CryptoMethod>> {
    CIPHER_ORDER
        .iter()
        .map(|id| cipher(id).expect("CIPHER_ORDER must only hold registered identifiers"))
        .collect()
}

/// Reject unknown identifiers, drop repeats, and return the selection in
/// canonical order. An empty selection is refused by name rather than being
/// replaced by a default.
pub fn normalise_carriers(selected: &[String]) -> Result<Vec<String>, String> {
    if selected.is_empty() {
        return Err("no carrier selected: name at least one carrier identifier".to_string());
    }
    for id in selected {
        carrier(id)?;
    }
    Ok(CARRIER_ORDER
        .iter()
        .filter(|id| selected.iter().any(|s| s == *id))
        .map(|id| (*id).to_string())
        .collect())
}

/// Describe every registered carrier, built live from the registry.
pub fn describe_carriers() -> Vec<Value> {
    CARRIER_ORDER
        .iter()
        .map(|id| {
            let built = carrier(id).expect("CARRIER_ORDER must only hold registered identifiers");
            let label = CARRIER_LABELS.iter().find(|l| l.id == *id);
            let alphabet = built.channel();
            let alters_visible_text = alphabet.iter().any(|c| !is_format_control(*c));

            match label {
                Some(label) => json!({
                    "id": built.id(),
                    "purpose": label.purpose,
                    "durability": label.durability,
                    "exposure": label.exposure,
                    "alters_visible_text": alters_visible_text,
                    "must_run_last": alters_visible_text,
                }),
                None => json!({
                    "id": built.id(),
                    "purpose": Value::Null,
                    "durability": Value::Null,
                    "exposure": Value::Null,
                    "alters_visible_text": alters_visible_text,
                    "must_run_last": alters_visible_text,
                    "label_missing": "this identifier is registered but carries no capability label, so no description is offered for it",
                }),
            }
        })
        .collect()
}

/// Describe every registered confidentiality layer, built live from the registry.
pub fn describe_ciphers() -> Vec<Value> {
    let mut described: Vec<Value> = CIPHER_ORDER
        .iter()
        .map(|id| {
            let built = cipher(id).expect("CIPHER_ORDER must only hold registered identifiers");
            let label = CIPHER_LABELS.iter().find(|l| l.id == *id);
            match label {
                Some(label) => json!({
                    "id": built.id(),
                    "purpose": label.purpose,
                    "detects_alteration": label.authenticated,
                    "strength": label.strength,
                }),
                None => json!({
                    "id": built.id(),
                    "purpose": Value::Null,
                    "detects_alteration": Value::Null,
                    "strength": Value::Null,
                    "label_missing": "this identifier is registered but carries no capability label, so no description is offered for it",
                }),
            }
        })
        .collect();

    described.push(json!({
        "id": CIPHER_NONE,
        "purpose": "No confidentiality layer. The payload travels as supplied.",
        "detects_alteration": false,
        "strength": "none",
    }));
    described
}

/// Is this codepoint an invisible format control?
///
/// The core uses the same partition to decide which carriers may be layered in
/// any order and which one has to run last. It is repeated here only to label
/// a carrier for the caller, never to make a decision the core makes.
fn is_format_control(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{206A}'..='\u{206F}'
        | '\u{FEFF}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registered_carrier_reports_its_own_identifier() {
        for id in CARRIER_ORDER {
            assert_eq!(carrier(id).expect("must build").id(), id);
        }
    }

    #[test]
    fn every_registered_cipher_reports_its_own_identifier() {
        for id in CIPHER_ORDER {
            assert_eq!(cipher(id).expect("must build").id(), id);
        }
    }

    #[test]
    fn unknown_identifiers_are_refused_by_name() {
        let carrier_error = carrier("does_not_exist").err().expect("must be refused");
        assert!(carrier_error.contains("does_not_exist"));
        let cipher_error = cipher("does_not_exist").err().expect("must be refused");
        assert!(cipher_error.contains("does_not_exist"));
    }

    /// The catalogue must never advertise an identifier without a label, and
    /// never hold a label for an identifier the registry does not build.
    #[test]
    fn every_registered_identifier_carries_a_capability_label() {
        for entry in describe_carriers() {
            assert!(
                entry.get("label_missing").is_none(),
                "carrier without a label: {entry}"
            );
        }
        for entry in describe_ciphers() {
            assert!(
                entry.get("label_missing").is_none(),
                "cipher without a label: {entry}"
            );
        }
        for label in CARRIER_LABELS {
            assert!(
                CARRIER_ORDER.contains(&label.id),
                "label for an unregistered carrier: {}",
                label.id
            );
        }
        for label in CIPHER_LABELS {
            assert!(
                CIPHER_ORDER.contains(&label.id),
                "label for an unregistered cipher: {}",
                label.id
            );
        }
    }

    /// Exactly one registered carrier alters the visible text, and the
    /// catalogue reads that off the live registry rather than off a list.
    #[test]
    fn the_catalogue_reads_visible_alteration_from_the_registry() {
        let altering: Vec<String> = describe_carriers()
            .iter()
            .filter(|entry| entry["alters_visible_text"] == json!(true))
            .map(|entry| entry["id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(altering, vec!["homoglyph".to_string()]);
    }

    #[test]
    fn a_selection_is_deduplicated_and_reordered() {
        let selection = vec![
            "homoglyph".to_string(),
            "bidi".to_string(),
            "zero_width".to_string(),
            "bidi".to_string(),
        ];
        assert_eq!(
            normalise_carriers(&selection).expect("must normalise"),
            vec!["zero_width", "bidi", "homoglyph"]
        );
    }

    #[test]
    fn an_empty_selection_is_refused() {
        assert!(normalise_carriers(&[]).is_err());
    }

    /// Every selection the surface will accept must pass the core's own
    /// composition rules once put in canonical order.
    #[test]
    fn every_canonical_selection_passes_the_core_composition_rules() {
        for mask in 1u8..(1 << CARRIER_ORDER.len()) {
            let selection: Vec<String> = CARRIER_ORDER
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1 << index) != 0)
                .map(|(_, id)| (*id).to_string())
                .collect();
            let ordered = normalise_carriers(&selection).expect("must normalise");
            let built: Vec<Box<dyn StegoMethod>> = ordered
                .iter()
                .map(|id| carrier(id).expect("must build"))
                .collect();
            let refs: Vec<&dyn StegoMethod> = built.iter().map(|b| b.as_ref()).collect();
            stegano_core::pipeline::validate_composition(&refs)
                .unwrap_or_else(|e| panic!("selection {ordered:?} must be legal: {e}"));
        }
    }
}
