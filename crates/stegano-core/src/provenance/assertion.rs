//! Assertions: typed statements inside a [`super::ProvenanceClaim`].
//!
//! Phase A ships three kinds behind the [`Assertion`] trait: human authorship,
//! AI-generated disclosure (EU AI Act Article 50), and integrity. Assertions
//! compose: one claim holds a vec of them. Adding a kind is one type plus a
//! line in [`assertion_from_record`]; the core does not change
//! (SPEC_PROVENANCE.md section 2).

use serde_json::{Map, Value};

use crate::error::{Result, SteganoError};

/// Stable kind identifier for the human-authorship assertion.
pub const KIND_HUMAN_AUTHORSHIP: &str = "human_authorship";
/// Stable kind identifier for the AI-generated disclosure assertion.
pub const KIND_AI_GENERATED: &str = "ai_generated";
/// Stable kind identifier for the integrity assertion.
pub const KIND_INTEGRITY: &str = "integrity";
/// Stable kind identifier for the recipient-fingerprint assertion (Phase B).
pub const KIND_RECIPIENT_FINGERPRINT: &str = "recipient_fingerprint";

/// One typed statement inside a claim.
///
/// Object-safe: `kind` and `to_value` are enough to serialise any assertion.
/// Rehydration is the free function [`assertion_from_record`] because a trait
/// method returning `Self` would not be object-safe.
pub trait Assertion {
    /// Stable identifier, e.g. "human_authorship".
    fn kind(&self) -> &str;
    /// JSON-serialisable payload. Deterministic: object keys serialise sorted.
    fn to_value(&self) -> Value;
}

/// The serialised form carried inside a [`super::ProvenanceClaim`].
///
/// `{ kind, payload }` pairs are what the signature covers, so their
/// serialisation must be deterministic: `payload` is a [`Value`] whose object
/// keys serialise in a fixed order, and the two struct fields serialise in
/// declaration order.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AssertionRecord {
    /// Stable kind identifier.
    pub kind: String,
    /// The assertion's payload.
    pub payload: Value,
}

impl AssertionRecord {
    /// Serialise a typed assertion into its record form.
    pub fn from_assertion(a: &dyn Assertion) -> Self {
        Self {
            kind: a.kind().to_string(),
            payload: a.to_value(),
        }
    }
}

// ─── human_authorship ───────────────────────────────────────

/// The text was authored by the holder of the claim's signer key. The optional
/// `author` label is a human-readable name, not an identity proof.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HumanAuthorship {
    /// Optional author label.
    pub author: Option<String>,
}

impl Assertion for HumanAuthorship {
    fn kind(&self) -> &str {
        KIND_HUMAN_AUTHORSHIP
    }
    fn to_value(&self) -> Value {
        let mut m = Map::new();
        if let Some(author) = &self.author {
            m.insert("author".to_string(), Value::String(author.clone()));
        }
        Value::Object(m)
    }
}

impl HumanAuthorship {
    fn from_value(v: &Value) -> Result<Self> {
        Ok(Self {
            author: optional_string(v, "author", KIND_HUMAN_AUTHORSHIP)?,
        })
    }
}

// ─── ai_generated ───────────────────────────────────────────

/// Article 50 disclosure: the text was produced by an AI system. Optional
/// `model`, `provider`, and `system_version` describe the pipeline. Signable by
/// a pipeline key distinct from a human key (SPEC_PROVENANCE.md section 5).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AiGenerated {
    /// Model name, e.g. "example-model-1".
    pub model: Option<String>,
    /// Provider name.
    pub provider: Option<String>,
    /// System or pipeline version string.
    pub system_version: Option<String>,
}

impl Assertion for AiGenerated {
    fn kind(&self) -> &str {
        KIND_AI_GENERATED
    }
    fn to_value(&self) -> Value {
        let mut m = Map::new();
        if let Some(model) = &self.model {
            m.insert("model".to_string(), Value::String(model.clone()));
        }
        if let Some(provider) = &self.provider {
            m.insert("provider".to_string(), Value::String(provider.clone()));
        }
        if let Some(version) = &self.system_version {
            m.insert("system_version".to_string(), Value::String(version.clone()));
        }
        Value::Object(m)
    }
}

impl AiGenerated {
    fn from_value(v: &Value) -> Result<Self> {
        Ok(Self {
            model: optional_string(v, "model", KIND_AI_GENERATED)?,
            provider: optional_string(v, "provider", KIND_AI_GENERATED)?,
            system_version: optional_string(v, "system_version", KIND_AI_GENERATED)?,
        })
    }
}

// ─── integrity ──────────────────────────────────────────────

/// Carries the document hash so alteration is detectable. Implicit in every
/// claim (the claim itself carries `document_hash`), explicit as an assertion
/// for readers that enumerate assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integrity {
    /// SHA-256(strip_all(document)), hex. Matches the claim's `document_hash`.
    pub document_hash: String,
}

impl Assertion for Integrity {
    fn kind(&self) -> &str {
        KIND_INTEGRITY
    }
    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            "document_hash".to_string(),
            Value::String(self.document_hash.clone()),
        );
        Value::Object(m)
    }
}

impl Integrity {
    fn from_value(v: &Value) -> Result<Self> {
        let document_hash = optional_string(v, "document_hash", KIND_INTEGRITY)?.ok_or_else(|| {
            SteganoError::InvalidInput(
                "integrity assertion is missing its required 'document_hash'".into(),
            )
        })?;
        Ok(Self { document_hash })
    }
}

// ─── recipient_fingerprint (Phase B) ────────────────────────

/// The per-recipient canary identifier from [`crate::watermark::fingerprint`],
/// carried so a claim can state "this copy was issued to recipient R" for leak
/// tracing (SPEC_PROVENANCE.md section 2, Phase B).
///
/// It holds the recipient label and the fingerprint hash the canary module
/// derives (`SHA-256(recipient_id + salt)`, truncated to the document's
/// capacity, then hashed). The raw fingerprint is not carried: the hash is what
/// [`crate::watermark::fingerprint::identify_leak`] matches against, so it is
/// the identifier a leak trace needs and it does not expose the fingerprint bits
/// themselves.
///
/// The derivation is never reimplemented here (invariant 4, frozen core): both
/// constructors read the figure the canary module itself produces.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecipientFingerprint {
    /// The recipient this copy was issued to (name, email, department...).
    pub recipient_id: String,
    /// SHA-256 of the recipient's fingerprint, hex. The canary identifier the
    /// leak-tracing lookup matches on.
    pub fingerprint_hash: String,
}

impl Assertion for RecipientFingerprint {
    fn kind(&self) -> &str {
        KIND_RECIPIENT_FINGERPRINT
    }
    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            "recipient_id".to_string(),
            Value::String(self.recipient_id.clone()),
        );
        m.insert(
            "fingerprint_hash".to_string(),
            Value::String(self.fingerprint_hash.clone()),
        );
        Value::Object(m)
    }
}

impl RecipientFingerprint {
    /// Derive the assertion for `recipient_id` over `cover`, reusing the canary
    /// module's own derivation rather than reimplementing it. The fingerprint
    /// hash matches the one a canary batch over the same cover assigns the same
    /// recipient, which is what ties the claim to a leak trace.
    ///
    /// Raises by name when `cover` has no substitutable positions to fingerprint
    /// (the canary module's own refusal), never returning a degraded identifier.
    pub fn derive(recipient_id: &str, salt: &str, cover: &str) -> Result<Self> {
        let version = crate::watermark::fingerprint::generate_single(cover, recipient_id, salt)?;
        Ok(Self::from_recipient(&version.recipient))
    }

    /// Build the assertion from a [`crate::watermark::fingerprint::Recipient`]
    /// the canary module already produced, for a caller that has a canary batch
    /// in hand and wants the matching provenance assertion.
    pub fn from_recipient(recipient: &crate::watermark::fingerprint::Recipient) -> Self {
        Self {
            recipient_id: recipient.id.clone(),
            fingerprint_hash: recipient.fingerprint_hash.clone(),
        }
    }

    /// True when this assertion identifies `recipient`: the canary identifier it
    /// carries is that recipient's. This is the leak-tracing match, expressed
    /// against the same hash the canary module compares on.
    pub fn identifies(&self, recipient: &crate::watermark::fingerprint::Recipient) -> bool {
        self.fingerprint_hash == recipient.fingerprint_hash
    }

    fn from_value(v: &Value) -> Result<Self> {
        let recipient_id = optional_string(v, "recipient_id", KIND_RECIPIENT_FINGERPRINT)?
            .ok_or_else(|| {
                SteganoError::InvalidInput(
                    "recipient_fingerprint assertion is missing its required 'recipient_id'".into(),
                )
            })?;
        let fingerprint_hash = optional_string(v, "fingerprint_hash", KIND_RECIPIENT_FINGERPRINT)?
            .ok_or_else(|| {
                SteganoError::InvalidInput(
                    "recipient_fingerprint assertion is missing its required 'fingerprint_hash'"
                        .into(),
                )
            })?;
        Ok(Self {
            recipient_id,
            fingerprint_hash,
        })
    }
}

// ─── factory ────────────────────────────────────────────────

/// Rehydrate a typed assertion from its record. Raises by name on an unknown
/// kind rather than silently dropping it: a reader that cannot understand an
/// assertion must say so, not pretend the claim said less (invariant 2).
pub fn assertion_from_record(rec: &AssertionRecord) -> Result<Box<dyn Assertion>> {
    match rec.kind.as_str() {
        KIND_HUMAN_AUTHORSHIP => Ok(Box::new(HumanAuthorship::from_value(&rec.payload)?)),
        KIND_AI_GENERATED => Ok(Box::new(AiGenerated::from_value(&rec.payload)?)),
        KIND_INTEGRITY => Ok(Box::new(Integrity::from_value(&rec.payload)?)),
        KIND_RECIPIENT_FINGERPRINT => {
            Ok(Box::new(RecipientFingerprint::from_value(&rec.payload)?))
        }
        other => Err(SteganoError::InvalidInput(format!(
            "unknown assertion kind '{other}': no registered plugin can read it"
        ))),
    }
}

// ─── helpers ────────────────────────────────────────────────

/// Read an optional string field, refusing a present-but-wrong-typed value by
/// name rather than coercing it.
fn optional_string(v: &Value, field: &str, kind: &str) -> Result<Option<String>> {
    match v.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(SteganoError::InvalidInput(format!(
            "{kind}.{field} must be a string"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_authorship_round_trips_through_a_record() {
        let a = HumanAuthorship {
            author: Some("Grace".into()),
        };
        let rec = AssertionRecord::from_assertion(&a);
        assert_eq!(rec.kind, KIND_HUMAN_AUTHORSHIP);
        let back = assertion_from_record(&rec).unwrap();
        assert_eq!(back.kind(), KIND_HUMAN_AUTHORSHIP);
        assert_eq!(back.to_value(), a.to_value());
    }

    #[test]
    fn ai_generated_omits_absent_fields() {
        let a = AiGenerated {
            model: Some("m".into()),
            provider: None,
            system_version: None,
        };
        let value = a.to_value();
        assert!(value.get("model").is_some());
        assert!(value.get("provider").is_none());
        assert!(value.get("system_version").is_none());
    }

    #[test]
    fn integrity_requires_a_document_hash() {
        let rec = AssertionRecord {
            kind: KIND_INTEGRITY.to_string(),
            payload: serde_json::json!({}),
        };
        let err = assertion_from_record(&rec)
            .err()
            .expect("expected an error");
        assert!(err.to_string().contains("document_hash"));
    }

    #[test]
    fn recipient_fingerprint_round_trips_through_a_record() {
        let a = RecipientFingerprint {
            recipient_id: "alice@company.ch".into(),
            fingerprint_hash: "abcd1234".into(),
        };
        let rec = AssertionRecord::from_assertion(&a);
        assert_eq!(rec.kind, KIND_RECIPIENT_FINGERPRINT);
        let back = assertion_from_record(&rec).unwrap();
        assert_eq!(back.kind(), KIND_RECIPIENT_FINGERPRINT);
        assert_eq!(back.to_value(), a.to_value());
    }

    #[test]
    fn recipient_fingerprint_derive_reuses_the_canary_hash() {
        // The assertion's hash must be exactly the one the canary module assigns
        // the same recipient over the same cover: reuse, not reimplementation.
        let cover = "\
            Access to the open science project expectations are exceptional in scope \
            and practice today across every possible aspect of the ecosystem operations \
            including all cooperative joint exercises previously associated with it";
        let derived = RecipientFingerprint::derive("bob", "doc-salt", cover).unwrap();
        let canary =
            crate::watermark::fingerprint::generate_single(cover, "bob", "doc-salt").unwrap();
        assert_eq!(derived.recipient_id, "bob");
        assert_eq!(derived.fingerprint_hash, canary.recipient.fingerprint_hash);
        assert!(derived.identifies(&canary.recipient));
    }

    #[test]
    fn recipient_fingerprint_derive_refuses_a_cover_with_no_positions_by_name() {
        // A cover the canary module cannot fingerprint raises the module's own
        // refusal rather than yielding a degraded identifier.
        let err = RecipientFingerprint::derive("bob", "salt", "日本語").unwrap_err();
        assert!(err.to_string().contains("no substitutable characters"));
    }

    #[test]
    fn recipient_fingerprint_requires_its_fields() {
        let rec = AssertionRecord {
            kind: KIND_RECIPIENT_FINGERPRINT.to_string(),
            payload: serde_json::json!({ "recipient_id": "bob" }),
        };
        let err = assertion_from_record(&rec).err().expect("expected an error");
        assert!(err.to_string().contains("fingerprint_hash"));
    }

    #[test]
    fn an_unknown_kind_is_refused_by_name() {
        let rec = AssertionRecord {
            kind: "telepathy".to_string(),
            payload: serde_json::json!({}),
        };
        let err = assertion_from_record(&rec)
            .err()
            .expect("expected an error");
        assert!(err.to_string().contains("unknown assertion kind 'telepathy'"));
    }

    #[test]
    fn a_wrong_typed_field_is_refused_by_name() {
        let rec = AssertionRecord {
            kind: KIND_HUMAN_AUTHORSHIP.to_string(),
            payload: serde_json::json!({ "author": 42 }),
        };
        let err = assertion_from_record(&rec)
            .err()
            .expect("expected an error");
        assert!(err.to_string().contains("human_authorship.author must be a string"));
    }
}
