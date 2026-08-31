//! Carrier and cipher registry for the desktop application.
//!
//! The core crate registers its carriers in `stegano_core::stego` and its
//! ciphers in `stegano_core::crypto`. This module is the single place where
//! the desktop application maps identifiers to instances. Adding a carrier to
//! the core means adding exactly one line here plus one catalogue entry per
//! locale; the guardrail tests fail until both are done.

use stegano_core::{
    crypto::{Aes128, Aes256, Caesar, ChaCha20, Xor},
    stego::{Bidi, Homoglyph, WhitespaceVar, ZeroWidth},
    traits::{CryptoMethod, StegoMethod},
};

/// Identifier used by the interface to mean "no encryption at all".
pub const CIPHER_NONE: &str = "none";

/// Canonical application order for carriers.
///
/// Carriers are applied in this order, whatever order the operator selected
/// them in, so that a given selection always produces the same layering.
///
/// The order is fixed by SPEC_CORE_V2 §6.5 and enforced by the core through
/// `pipeline::validate_composition`: a carrier that rewrites visible text must
/// run last, because it changes the substitutable-position set that every
/// other carrier measured. The invisible-channel carriers come first, and they
/// gain capacity as they go since each one sees the longer text produced by
/// its predecessor.
pub const CARRIER_ORDER: [&str; 4] = ["zero_width", "whitespace_var", "bidi", "homoglyph"];

/// Cipher identifiers, in the order shown in the interface.
///
/// The two keystream references are last because they provide no
/// authentication; their catalogue notes say so.
pub const CIPHER_ORDER: [&str; 5] = [
    "aes256_gcm",
    "chacha20_poly1305",
    "aes128_gcm",
    "caesar",
    "xor",
];

/// Build a carrier instance from its identifier.
pub fn carrier(id: &str) -> Result<Box<dyn StegoMethod>, String> {
    match id {
        "homoglyph" => Ok(Box::new(Homoglyph::new())),
        "zero_width" => Ok(Box::new(ZeroWidth::new())),
        "whitespace_var" => Ok(Box::new(WhitespaceVar::new())),
        "bidi" => Ok(Box::new(Bidi::new())),
        other => Err(format!("unknown carrier: {other}")),
    }
}

/// Every registered carrier, in canonical order.
pub fn all_carriers() -> Vec<Box<dyn StegoMethod>> {
    CARRIER_ORDER
        .iter()
        .map(|id| carrier(id).expect("CARRIER_ORDER must only contain registered carriers"))
        .collect()
}

/// Build a cipher instance from its identifier.
pub fn cipher(id: &str) -> Result<Box<dyn CryptoMethod>, String> {
    match id {
        "aes256_gcm" => Ok(Box::new(Aes256::new())),
        "aes128_gcm" => Ok(Box::new(Aes128::new())),
        "chacha20_poly1305" => Ok(Box::new(ChaCha20::new())),
        "caesar" => Ok(Box::new(Caesar::new())),
        "xor" => Ok(Box::new(Xor::new())),
        other => Err(format!("unknown cipher: {other}")),
    }
}

/// Every registered cipher, used when a received text must be tried against
/// all of them.
pub fn all_ciphers() -> Vec<Box<dyn CryptoMethod>> {
    CIPHER_ORDER
        .iter()
        .map(|id| cipher(id).expect("CIPHER_ORDER must only contain registered ciphers"))
        .collect()
}

/// Normalise an operator selection: reject unknown identifiers, drop
/// duplicates, and return the selection in canonical application order.
pub fn normalise_carrier_selection(selected: &[String]) -> Result<Vec<String>, String> {
    if selected.is_empty() {
        return Err("no carrier selected".to_string());
    }
    for id in selected {
        carrier(id)?;
    }
    let ordered: Vec<String> = CARRIER_ORDER
        .iter()
        .filter(|id| selected.iter().any(|s| s == *id))
        .map(|id| (*id).to_string())
        .collect();
    Ok(ordered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_ordered_carrier_reports_its_own_identifier() {
        for id in CARRIER_ORDER {
            let built = carrier(id).expect("carrier must build");
            assert_eq!(built.id(), id, "carrier identifier mismatch for {id}");
        }
    }

    #[test]
    fn every_ordered_cipher_reports_its_own_identifier() {
        for id in CIPHER_ORDER {
            let built = cipher(id).expect("cipher must build");
            assert_eq!(built.id(), id, "cipher identifier mismatch for {id}");
        }
    }

    #[test]
    fn unknown_identifiers_are_rejected_by_name() {
        let carrier_error = carrier("does_not_exist").err().expect("must be rejected");
        assert!(carrier_error.contains("does_not_exist"));
        let cipher_error = cipher("does_not_exist").err().expect("must be rejected");
        assert!(cipher_error.contains("does_not_exist"));
    }

    #[test]
    fn selection_is_deduplicated_and_reordered() {
        let selection = vec![
            "homoglyph".to_string(),
            "bidi".to_string(),
            "zero_width".to_string(),
            "bidi".to_string(),
        ];
        let ordered = normalise_carrier_selection(&selection).expect("selection must normalise");
        assert_eq!(ordered, vec!["zero_width", "bidi", "homoglyph"]);
    }

    #[test]
    fn empty_selection_is_an_error() {
        assert!(normalise_carrier_selection(&[]).is_err());
    }

    /// The canonical order must satisfy the core's composition rules for every
    /// possible selection, not only for the full set.
    #[test]
    fn every_selection_passes_the_core_composition_rules() {
        let ids: Vec<&str> = CARRIER_ORDER.to_vec();
        for mask in 1u8..(1 << ids.len()) {
            let selection: Vec<String> = ids
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1 << index) != 0)
                .map(|(_, id)| (*id).to_string())
                .collect();
            let ordered = normalise_carrier_selection(&selection).expect("selection must normalise");
            let boxed: Vec<Box<dyn StegoMethod>> = ordered
                .iter()
                .map(|id| carrier(id).expect("carrier must build"))
                .collect();
            let refs: Vec<&dyn StegoMethod> = boxed.iter().map(|b| b.as_ref()).collect();
            stegano_core::pipeline::validate_composition(&refs)
                .unwrap_or_else(|e| panic!("selection {ordered:?} must be legal: {e}"));
        }
    }
}
