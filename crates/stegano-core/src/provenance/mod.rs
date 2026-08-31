//! Provenance layer, Phase A.
//!
//! An additive layer over the frozen core (invariant 4, SPEC_PROVENANCE.md).
//! A [`ProvenanceClaim`] is a signed record over a document's hash. It carries
//! one or more [`Assertion`]s (human authorship, AI-generated disclosure,
//! integrity, and the Phase B recipient fingerprint) and attaches to a document
//! through a [`Binding`]. Phase A ships the detached binding, a JSON sidecar;
//! Phase B adds the in-band binding through the carriers; the format-metadata
//! binding is Phase C.
//!
//! Nothing here modifies `license.rs`, `signing.rs`, or `forensic.rs`. The
//! signature reuses [`crate::signing`] (Ed25519), the document hash reuses
//! [`crate::license::document_hash`] (the F12 mechanism), so a claim survives
//! an in-band mark being embedded and fails by name when a visible character
//! changes.

pub mod assertion;
pub mod binding;
pub mod verify;

pub use assertion::{
    assertion_from_record, AiGenerated, Assertion, AssertionRecord, HumanAuthorship, Integrity,
    RecipientFingerprint, KIND_AI_GENERATED, KIND_HUMAN_AUTHORSHIP, KIND_INTEGRITY,
    KIND_RECIPIENT_FINGERPRINT,
};
pub use binding::{
    BindInput, BindOutput, Binding, DetachedBinding, InBandBinding, Robustness, RobustnessClass,
    SIDECAR_VERSION,
};
pub use verify::{
    verify, verify_document, verify_with_policy, KeyRequirement, ProvenanceReport, TrustPolicy,
    UnmetRequirement, VerifiedClaim,
};

use crate::error::{Result, SteganoError};
use crate::signing::{MasterKeyPair, MasterPublicKey};

/// Claim schema version.
pub const CLAIM_VERSION: u8 = 1;

/// A reference to the public key that signed a claim, embedded so any holder
/// can verify. Ed25519 only in Phase A. Key-to-identity binding is a
/// trust-anchor problem outside the tool (SPEC_PROVENANCE.md section 5): the
/// tool proves that a key signed this claim over this document, and no more.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicKeyRef {
    /// Signature algorithm identifier. Phase A: "ed25519".
    pub alg: String,
    /// Public key, hex-encoded (64 hex chars for a 32-byte Ed25519 key).
    pub key: String,
}

impl PublicKeyRef {
    /// Build a reference from an Ed25519 verifying key.
    pub fn ed25519(public: &MasterPublicKey) -> Self {
        Self {
            alg: "ed25519".to_string(),
            key: hex_encode(&public.to_bytes()),
        }
    }

    /// Recover the verifying key. Raises by name on an unsupported algorithm,
    /// bad hex, or a wrong length rather than degrading to a default key.
    pub fn to_public_key(&self) -> Result<MasterPublicKey> {
        if self.alg != "ed25519" {
            return Err(SteganoError::InvalidInput(format!(
                "unsupported signature algorithm '{}': Phase A verifies ed25519 only",
                self.alg
            )));
        }
        let bytes = hex_decode(&self.key)
            .map_err(|_| SteganoError::InvalidInput("signer key is not valid hex".into()))?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            SteganoError::InvalidInput(format!(
                "signer key must be 32 bytes, got {}",
                bytes.len()
            ))
        })?;
        MasterPublicKey::from_bytes(&arr)
    }
}

/// The signed record. Serialises deterministically so its canonical bytes are
/// reproducible at sign time and verify time.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProvenanceClaim {
    /// Claim schema version.
    pub v: u8,
    /// One or more assertions, freely combined. Serialised form.
    pub assertions: Vec<AssertionRecord>,
    /// SHA-256(strip_all(document)), hex. Reuses [`crate::license::document_hash`]
    /// (F12) so the signature covers the document and survives an embedded mark.
    pub document_hash: String,
    /// ISO-8601 creation timestamp. Trusted only as far as the signer is
    /// (SPEC_PROVENANCE.md section 5). Omitted from the wire form when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// The key that signed this claim, embedded for verification.
    pub signer: PublicKeyRef,
}

impl ProvenanceClaim {
    /// Assemble a claim over `document`. The document hash is taken with the
    /// F12 mechanism, so it is reproducible once a mark is embedded. Refuses an
    /// empty assertion set by name: a claim that states nothing is not a claim.
    pub fn new(
        assertions: &[&dyn Assertion],
        document: &str,
        signer_public: &MasterPublicKey,
        created: Option<String>,
    ) -> Result<Self> {
        if assertions.is_empty() {
            return Err(SteganoError::InvalidInput(
                "a provenance claim needs at least one assertion".into(),
            ));
        }
        let document_hash = crate::license::document_hash(document)?;
        let records = assertions
            .iter()
            .map(|a| AssertionRecord::from_assertion(*a))
            .collect();
        Ok(Self {
            v: CLAIM_VERSION,
            assertions: records,
            document_hash,
            created,
            signer: PublicKeyRef::ed25519(signer_public),
        })
    }

    /// Canonical bytes for signing and verifying. Deterministic: the same claim
    /// value always serialises to the same bytes, so a signature made over
    /// these bytes verifies against a claim parsed back from a sidecar.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// True when an assertion of `kind` is present.
    pub fn has_kind(&self, kind: &str) -> bool {
        self.assertions.iter().any(|a| a.kind == kind)
    }

    /// Typed, rehydrated assertions. Raises on an unknown kind rather than
    /// dropping it (invariant 2, no silent degradation).
    pub fn typed_assertions(&self) -> Result<Vec<Box<dyn Assertion>>> {
        self.assertions.iter().map(assertion_from_record).collect()
    }
}

/// A claim plus its detached Ed25519 signature over the claim's canonical bytes.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignedClaim {
    /// The signed claim.
    pub claim: ProvenanceClaim,
    /// Ed25519 signature over `claim.canonical_bytes()`, hex-encoded.
    pub signature: String,
}

impl SignedClaim {
    /// Sign `claim` with `keypair`. The keypair's public half must match the
    /// claim's embedded signer, or the claim would name a key that did not sign
    /// it; this refuses that up front by name rather than producing a record
    /// that fails to verify for a confusing reason.
    pub fn sign(claim: ProvenanceClaim, keypair: &MasterKeyPair) -> Result<Self> {
        let embedded = PublicKeyRef::ed25519(&keypair.public_key());
        if embedded != claim.signer {
            return Err(SteganoError::InvalidInput(
                "signing key does not match the claim's embedded signer".into(),
            ));
        }
        let sig = keypair.sign(&claim.canonical_bytes()?);
        Ok(Self {
            claim,
            signature: hex_encode(&sig),
        })
    }

    /// True when the signature verifies under the claim's embedded signer key.
    /// This is the cryptographic check only; trust in that key is a separate
    /// axis handled by the verify path.
    pub fn signature_valid(&self) -> bool {
        self.verify_under(&self.claim.signer).unwrap_or(false)
    }

    /// True when the signature verifies under `who`'s key. The distinct-key rule
    /// (SPEC_PROVENANCE.md section 5) uses this: a claim only counts for an
    /// assertion when the required signer actually signed it, so a pipeline key
    /// cannot pass as a human key.
    pub fn verify_under(&self, who: &PublicKeyRef) -> Result<bool> {
        let pubkey = who.to_public_key()?;
        let sig = hex_decode(&self.signature)
            .map_err(|_| SteganoError::InvalidInput("signature is not valid hex".into()))?;
        Ok(pubkey.verify(&self.claim.canonical_bytes()?, &sig).is_ok())
    }
}

// ─── Local hex helpers ──────────────────────────────────────
//
// Kept private and local rather than reaching into license.rs (whose copies are
// private) so this module stays additive and touches no existing file.

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(hex: &str) -> std::result::Result<Vec<u8>, ()> {
    if hex.len() % 2 != 0 {
        return Err(());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (MasterKeyPair, MasterPublicKey) {
        let kp = MasterKeyPair::generate();
        let pk = kp.public_key();
        (kp, pk)
    }

    #[test]
    fn empty_assertion_set_is_refused_by_name() {
        let (_, pk) = keypair();
        let err = ProvenanceClaim::new(&[], "some document", &pk, None).unwrap_err();
        assert!(err.to_string().contains("at least one assertion"));
    }

    #[test]
    fn canonical_bytes_are_stable_across_a_round_trip() {
        let (_, pk) = keypair();
        let claim = ProvenanceClaim::new(
            &[&HumanAuthorship {
                author: Some("Ada".into()),
            }],
            "a document",
            &pk,
            Some("2026-08-20T00:00:00Z".into()),
        )
        .unwrap();

        let bytes = claim.canonical_bytes().unwrap();
        let parsed: ProvenanceClaim = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, claim);
        assert_eq!(parsed.canonical_bytes().unwrap(), bytes);
    }

    #[test]
    fn signing_with_a_mismatched_key_is_refused_by_name() {
        let (_kp_a, pk_a) = keypair();
        let (kp_b, _pk_b) = keypair();
        // Claim names key A as signer, but we try to sign with key B.
        let claim =
            ProvenanceClaim::new(&[&HumanAuthorship { author: None }], "doc", &pk_a, None).unwrap();
        let err = SignedClaim::sign(claim, &kp_b).unwrap_err();
        assert!(err.to_string().contains("does not match the claim's embedded signer"));
    }

    #[test]
    fn public_key_ref_round_trips_through_bytes() {
        let (_, pk) = keypair();
        let reference = PublicKeyRef::ed25519(&pk);
        let recovered = reference.to_public_key().unwrap();
        assert_eq!(recovered.to_bytes(), pk.to_bytes());
    }

    #[test]
    fn a_bad_algorithm_in_a_key_ref_is_refused_by_name() {
        let (_, pk) = keypair();
        let mut reference = PublicKeyRef::ed25519(&pk);
        reference.alg = "rsa".into();
        let err = reference.to_public_key().err().expect("expected an error");
        assert!(err.to_string().contains("unsupported signature algorithm"));
    }
}
