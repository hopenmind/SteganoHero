//! C2PA read and verify: the file side of the AI-regulation tool (backlog AR-2).
//!
//! AR-1 ([`crate::sovereignty`]) answers "what marks are on my text". This module
//! answers the complementary question for files that carry a content credential:
//! read the credential a file already holds, and report, honestly, whether its
//! signature validates. Content credentials live in file containers (images,
//! PDF) as a JUMBF-wrapped, COSE-signed record, not in plain text, so this path
//! takes file bytes, never a `String`.
//!
//! Conformance is delegated to the official `c2pa` reader rather than a
//! hand-rolled parser. That is the point of the AI-Act interoperability
//! language: a credential a third-party C2PA reader validates is worth more than
//! one only this tool can read, and reusing the conformant reader is what makes
//! our verdict match theirs.
//!
//! Two honesty rules, the same discipline the fidelity and forensic modules
//! hold to:
//!
//! - A file with no credential is reported absent, not raised as an error.
//! - The verdict is exactly what the reader's validation returns. A signature
//!   that is cryptographically intact but signed by a certificate outside any
//!   configured trust list is reported as intact with the trust anchor not
//!   established, never as trusted. A failed validation names its failure codes,
//!   never a plausible-but-wrong pass.

use std::io::Cursor;

use c2pa::{Context, Reader, ValidationState};
use serde::Serialize;
use thiserror::Error;

/// IPTC and C2PA digital-source-type suffixes that denote generative-AI output.
///
/// A credential that carries one of these in an action's `digitalSourceType`
/// declares AI-generated (or AI-composited) content. Matched on the suffix so a
/// match holds whether the URI is namespaced under `cv.iptc.org` or `c2pa.org`.
const GENERATIVE_AI_SOURCE_SUFFIXES: [&str; 3] = [
    "trainedAlgorithmicMedia",
    "trainedAlgorithmicData",
    "compositeWithTrainedAlgorithmicMedia",
];

/// An error reading or decoding a file's content credential.
///
/// Absence of a credential is not one of these: it is an ordinary outcome
/// reported through [`C2paReport`]. These name a real failure to read the bytes
/// as an asset, and each names itself rather than collapsing into a generic
/// message (invariant 2).
#[derive(Debug, Error)]
pub enum C2paReadError {
    /// The bytes are not a container format the conformant reader supports.
    #[error("Unsupported file format for content-credential reading: {0}")]
    UnsupportedFormat(String),

    /// The bytes are a recognised format but could not be parsed as one.
    #[error("File could not be parsed as an asset: {0}")]
    UnreadableAsset(String),

    /// The reader failed for a reason other than a missing or malformed asset.
    #[error("Content-credential reader failed: {0}")]
    Backend(String),
}

/// The overall verdict for a file's content credential.
///
/// The three present-and-validated states mirror the conformant reader's own
/// `ValidationState` one to one, so this never invents a verdict the reader did
/// not reach. `Absent` is the fourth, ordinary outcome: no credential attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum C2paVerdict {
    /// No content credential is attached to the file.
    Absent,
    /// A credential is attached but its validation failed. See
    /// [`C2paReport::failures`] for the named reasons.
    Invalid,
    /// The signature is cryptographically intact. The signing certificate is not
    /// established against a configured trust list, so the issuer is not
    /// independently verified. See [`C2paReport::trust_anchor_established`].
    SignatureValid,
    /// The signature is intact and the signing certificate chains to a trusted
    /// issuer in the configured trust list.
    Trusted,
}

/// One failed validation status from the reader, kept verbatim.
///
/// `code` is the reader's own status code (for example `assertion.dataHash.mismatch`
/// or `signingCredential.untrusted`); it is the failure "by name" that honest
/// reporting requires. `explanation` is the reader's human-readable note when it
/// provides one.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationFailure {
    /// The reader's status code, verbatim.
    pub code: String,
    /// The reader's explanation for this status, when present.
    pub explanation: Option<String>,
    /// The JUMBF URI the status points at, when present.
    pub target: Option<String>,
}

/// A summary of the signer, from the active manifest's signature information.
#[derive(Debug, Clone, Serialize)]
pub struct SignerSummary {
    /// Signature algorithm, for example `ps256` or `ed25519`.
    pub algorithm: Option<String>,
    /// Issuing authority, as named in the certificate.
    pub issuer: Option<String>,
    /// Common name on the signing certificate.
    pub common_name: Option<String>,
    /// Certificate serial number.
    pub cert_serial_number: Option<String>,
    /// Time the signature was created, when the credential records one.
    pub signed_time: Option<String>,
}

/// A finding that the credential declares generative-AI content.
#[derive(Debug, Clone, Serialize)]
pub struct AiGenerationFinding {
    /// The generative-AI digital-source-type URIs found in the credential.
    pub source_types: Vec<String>,
    /// A plain-language note stating what was found, capability first.
    pub note: String,
}

/// A structured summary of the active manifest.
#[derive(Debug, Clone, Serialize)]
pub struct ManifestSummary {
    /// The manifest label, when present.
    pub label: Option<String>,
    /// The title the credential gives the asset, when present.
    pub title: Option<String>,
    /// The asset format the credential records, when present.
    pub format: Option<String>,
    /// The tool that generated the claim, when present.
    pub claim_generator: Option<String>,
    /// The labels of every assertion in the manifest, in order.
    pub assertion_labels: Vec<String>,
    /// Number of ingredients (referenced source assets) in the manifest.
    pub ingredient_count: usize,
    /// Every digital-source-type URI found across the manifest's actions,
    /// reported for transparency whether or not it denotes AI.
    pub digital_source_types: Vec<String>,
    /// Present when the credential declares generative-AI content.
    pub ai_generation: Option<AiGenerationFinding>,
    /// The signer summary, when the manifest carries signature information.
    pub signer: Option<SignerSummary>,
}

/// The full read-and-verify report for a file's content credential.
#[derive(Debug, Clone, Serialize)]
pub struct C2paReport {
    /// True when a content credential (a manifest store) was found in the file.
    pub present: bool,
    /// The overall verdict.
    pub verdict: C2paVerdict,
    /// The reader's raw validation-state name (`Valid`, `Invalid`, `Trusted`)
    /// when a credential is present, so a surface can show exactly what the
    /// conformant reader returned. `None` when absent.
    pub validation_state: Option<String>,
    /// True only when the signing certificate is established against a configured
    /// trust list. `SignatureValid` reports `false` here; `Trusted` reports
    /// `true`. Never inferred, taken from the reader's state.
    pub trust_anchor_established: bool,
    /// Every failed validation status, by name. Empty when the credential is
    /// absent or fully valid.
    pub failures: Vec<ValidationFailure>,
    /// The active manifest summary, when a readable manifest is present. A
    /// credential can be present but too malformed to yield a manifest, in which
    /// case this is `None` and the failures name why.
    pub manifest: Option<ManifestSummary>,
    /// Plain-language, honest summary lines.
    pub summary: Vec<String>,
}

impl C2paReport {
    /// True when the signature is cryptographically intact, whether or not the
    /// trust anchor is established. False when absent or invalid.
    pub fn signature_intact(&self) -> bool {
        matches!(self.verdict, C2paVerdict::SignatureValid | C2paVerdict::Trusted)
    }

    /// The report for a file with no content credential.
    fn absent() -> C2paReport {
        C2paReport {
            present: false,
            verdict: C2paVerdict::Absent,
            validation_state: None,
            trust_anchor_established: false,
            failures: Vec::new(),
            manifest: None,
            summary: vec![
                "No content credential is attached to this file.".to_string(),
            ],
        }
    }
}

/// Read and verify the content credential in a file's bytes.
///
/// `format_hint` is an optional MIME type, extension, or filename. When it is
/// `None` the conformant reader detects the container from the bytes; when it is
/// a filename the extension is used. Absence of a credential returns an
/// `Absent` report, not an error. Only a genuine failure to read the bytes as an
/// asset returns [`C2paReadError`].
pub fn inspect_c2pa(
    bytes: &[u8],
    format_hint: Option<&str>,
) -> Result<C2paReport, C2paReadError> {
    let format = normalize_format(format_hint);

    let reader = match Reader::from_context(Context::new())
        .with_stream(&format, Cursor::new(bytes))
    {
        Ok(reader) => reader,
        Err(c2pa::Error::JumbfNotFound) => return Ok(C2paReport::absent()),
        Err(c2pa::Error::UnsupportedType) => {
            return Err(C2paReadError::UnsupportedFormat(if format.is_empty() {
                "format not recognised from bytes".to_string()
            } else {
                format
            }))
        }
        Err(c2pa::Error::InvalidAsset(reason)) => {
            return Err(C2paReadError::UnreadableAsset(reason))
        }
        Err(other) => return Err(C2paReadError::Backend(other.to_string())),
    };

    Ok(build_report(&reader))
}

/// Build the report from a reader that found a credential.
fn build_report(reader: &Reader) -> C2paReport {
    let state = reader.validation_state();
    let trust_anchor_established = matches!(state, ValidationState::Trusted);
    let verdict = match state {
        ValidationState::Invalid => C2paVerdict::Invalid,
        ValidationState::Valid => C2paVerdict::SignatureValid,
        ValidationState::Trusted => C2paVerdict::Trusted,
    };

    let failures: Vec<ValidationFailure> = reader
        .validation_status()
        .unwrap_or(&[])
        .iter()
        .filter(|status| !status.passed())
        .map(|status| ValidationFailure {
            code: status.code().to_string(),
            explanation: status.explanation().map(str::to_string),
            target: status.url().map(str::to_string),
        })
        .collect();

    let manifest = reader.active_manifest().map(build_manifest_summary);
    let summary = build_summary(verdict, &failures, manifest.as_ref());

    C2paReport {
        present: true,
        verdict,
        validation_state: Some(format!("{state:?}")),
        trust_anchor_established,
        failures,
        manifest,
        summary,
    }
}

/// Summarise one manifest.
fn build_manifest_summary(manifest: &c2pa::Manifest) -> ManifestSummary {
    let assertion_labels: Vec<String> = manifest
        .assertions()
        .iter()
        .map(|assertion| assertion.label().to_string())
        .collect();

    let mut digital_source_types = Vec::new();
    for assertion in manifest.assertions() {
        if let Ok(value) = assertion.value() {
            collect_digital_source_types(value, &mut digital_source_types);
        }
    }
    digital_source_types.sort();
    digital_source_types.dedup();

    let ai_generation = ai_generation_finding(&digital_source_types);

    let signer = manifest.signature_info().map(|info| SignerSummary {
        algorithm: info.alg.map(|alg| alg.to_string()),
        issuer: info.issuer.clone(),
        common_name: info.common_name.clone(),
        cert_serial_number: info.cert_serial_number.clone(),
        signed_time: info.time.clone(),
    });

    ManifestSummary {
        label: manifest.label().map(str::to_string),
        title: manifest.title().map(str::to_string),
        format: manifest.format().map(str::to_string),
        claim_generator: manifest.claim_generator().map(str::to_string),
        assertion_labels,
        ingredient_count: manifest.ingredients().len(),
        digital_source_types,
        ai_generation,
        signer,
    }
}

/// Normalise a format hint to what the reader expects: a MIME type or a bare
/// extension. A filename is reduced to its extension; an empty or missing hint
/// becomes the empty string, on which the reader detects the container from the
/// bytes itself.
fn normalize_format(hint: Option<&str>) -> String {
    let hint = match hint {
        Some(hint) => hint.trim(),
        None => return String::new(),
    };
    if hint.is_empty() {
        return String::new();
    }
    // A MIME type is passed through unchanged.
    if hint.contains('/') {
        return hint.to_ascii_lowercase();
    }
    // A filename or dotted name is reduced to its final extension.
    match hint.rsplit_once('.') {
        Some((_, ext)) if !ext.is_empty() => ext.to_ascii_lowercase(),
        _ => hint.to_ascii_lowercase(),
    }
}

/// Walk an assertion value and collect every string found under a
/// `digitalSourceType` key, at any depth.
fn collect_digital_source_types(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if key == "digitalSourceType" {
                    if let serde_json::Value::String(uri) = child {
                        out.push(uri.clone());
                    }
                }
                collect_digital_source_types(child, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_digital_source_types(item, out);
            }
        }
        _ => {}
    }
}

/// True when a digital-source-type URI denotes generative-AI content.
fn is_generative_ai_source(uri: &str) -> bool {
    GENERATIVE_AI_SOURCE_SUFFIXES
        .iter()
        .any(|suffix| uri.ends_with(suffix))
}

/// Build the generative-AI finding from the source types found, if any qualify.
fn ai_generation_finding(source_types: &[String]) -> Option<AiGenerationFinding> {
    let matched: Vec<String> = source_types
        .iter()
        .filter(|uri| is_generative_ai_source(uri))
        .cloned()
        .collect();
    if matched.is_empty() {
        return None;
    }
    Some(AiGenerationFinding {
        note: "This credential declares AI-generated or AI-composited content."
            .to_string(),
        source_types: matched,
    })
}

/// Build the honest, plain-language summary lines.
fn build_summary(
    verdict: C2paVerdict,
    failures: &[ValidationFailure],
    manifest: Option<&ManifestSummary>,
) -> Vec<String> {
    let mut lines = Vec::new();

    match verdict {
        C2paVerdict::Absent => {
            lines.push("No content credential is attached to this file.".to_string());
        }
        C2paVerdict::Trusted => {
            lines.push(
                "A content credential is attached. Its signature is intact and the signing certificate chains to a trusted issuer."
                    .to_string(),
            );
        }
        C2paVerdict::SignatureValid => {
            lines.push(
                "A content credential is attached and its signature is cryptographically intact. The signing certificate is not established against a configured trust list, so the issuer is not independently verified."
                    .to_string(),
            );
        }
        C2paVerdict::Invalid => {
            lines.push(
                "A content credential is attached but its validation failed. The reasons are named below.".to_string(),
            );
            for failure in failures {
                match &failure.explanation {
                    Some(explanation) => {
                        lines.push(format!("  {} ({})", explanation, failure.code))
                    }
                    None => lines.push(format!("  {}", failure.code)),
                }
            }
        }
    }

    if let Some(manifest) = manifest {
        if let Some(generator) = &manifest.claim_generator {
            lines.push(format!("Claimed by: {generator}."));
        }
        match &manifest.ai_generation {
            Some(finding) => lines.push(finding.note.clone()),
            None => {
                if verdict != C2paVerdict::Absent {
                    lines.push(
                        "The credential does not declare AI-generated content.".to_string(),
                    );
                }
            }
        }
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_report_names_no_credential() {
        let report = C2paReport::absent();
        assert!(!report.present);
        assert_eq!(report.verdict, C2paVerdict::Absent);
        assert!(report.validation_state.is_none());
        assert!(!report.trust_anchor_established);
        assert!(report.failures.is_empty());
        assert!(!report.signature_intact());
    }

    #[test]
    fn garbage_bytes_are_an_unsupported_format_error_not_absent() {
        // Bytes of no recognised container: the reader cannot even look for a
        // credential, so this is a named error, not an "absent" report.
        let err = inspect_c2pa(b"not a real asset at all", None).unwrap_err();
        matches!(err, C2paReadError::UnsupportedFormat(_));
    }

    #[test]
    fn format_hint_is_reduced_to_an_extension() {
        assert_eq!(normalize_format(Some("photo.JPG")), "jpg");
        assert_eq!(normalize_format(Some("archive.tar.gz")), "gz");
        assert_eq!(normalize_format(Some("image/png")), "image/png");
        assert_eq!(normalize_format(Some("jpeg")), "jpeg");
        assert_eq!(normalize_format(None), "");
        assert_eq!(normalize_format(Some("   ")), "");
    }

    #[test]
    fn digital_source_types_are_collected_at_any_depth() {
        let value = serde_json::json!({
            "actions": [
                { "action": "c2pa.created",
                  "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia" },
                { "action": "c2pa.edited",
                  "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/humanEdits" }
            ]
        });
        let mut found = Vec::new();
        collect_digital_source_types(&value, &mut found);
        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|u| u.ends_with("trainedAlgorithmicMedia")));
        assert!(found.iter().any(|u| u.ends_with("humanEdits")));
    }

    #[test]
    fn generative_ai_source_types_are_recognised_and_others_are_not() {
        assert!(is_generative_ai_source(
            "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
        ));
        assert!(is_generative_ai_source(
            "http://c2pa.org/digitalsourcetype/trainedAlgorithmicData"
        ));
        assert!(is_generative_ai_source(
            "http://cv.iptc.org/newscodes/digitalsourcetype/compositeWithTrainedAlgorithmicMedia"
        ));
        assert!(!is_generative_ai_source(
            "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
        ));
        assert!(!is_generative_ai_source(
            "http://cv.iptc.org/newscodes/digitalsourcetype/humanEdits"
        ));
    }

    #[test]
    fn ai_finding_is_some_only_when_a_generative_source_is_present() {
        let none = ai_generation_finding(&[
            "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture".to_string(),
        ]);
        assert!(none.is_none());

        let some = ai_generation_finding(&[
            "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture".to_string(),
            "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia".to_string(),
        ]);
        let finding = some.expect("a generative source is present");
        assert_eq!(finding.source_types.len(), 1);
        assert!(finding.source_types[0].ends_with("trainedAlgorithmicMedia"));
    }

    #[test]
    fn verdict_mirrors_the_three_validation_states_plus_absent() {
        // The verdict serialises to stable snake_case identifiers a surface can
        // switch on without a translation table.
        assert_eq!(
            serde_json::to_string(&C2paVerdict::Absent).unwrap(),
            "\"absent\""
        );
        assert_eq!(
            serde_json::to_string(&C2paVerdict::Invalid).unwrap(),
            "\"invalid\""
        );
        assert_eq!(
            serde_json::to_string(&C2paVerdict::SignatureValid).unwrap(),
            "\"signature_valid\""
        );
        assert_eq!(
            serde_json::to_string(&C2paVerdict::Trusted).unwrap(),
            "\"trusted\""
        );
    }
}
