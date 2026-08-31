//! C2PA read and verify over genuine fixtures (backlog AR-2).
//!
//! These exercise the file side of the AI-regulation tool against real bytes:
//!
//! - `genuine_signed.jpg` is a genuinely C2PA-signed JPEG. Its signature is
//!   cryptographically intact, so it must read as present and signature-valid.
//!   The signing certificate is a test certificate outside any configured trust
//!   list, so the trust anchor must be reported as not established, never as
//!   trusted. This is the honesty the verify path exists to hold.
//! - The same bytes with one content byte flipped must fail validation and name
//!   the failure (`assertion.dataHash.mismatch`, the hard-binding hash), never
//!   drop it or report a plausible pass.
//! - `no_manifest.jpg` and `no_manifest.png` carry no credential and must be
//!   reported absent, not raised as an error.
//!
//! The genuine fixture is a small test asset shipped by the `c2pa` crate's own
//! test suite; it is embedded here so the test is self-contained.

use stegano_core::c2pa_read::{inspect_c2pa, C2paReadError, C2paVerdict};

const GENUINE_SIGNED_JPEG: &[u8] = include_bytes!("fixtures/c2pa/genuine_signed.jpg");
const NO_MANIFEST_JPEG: &[u8] = include_bytes!("fixtures/c2pa/no_manifest.jpg");
const NO_MANIFEST_PNG: &[u8] = include_bytes!("fixtures/c2pa/no_manifest.png");

#[test]
fn genuine_credential_reads_present_and_signature_valid() {
    let report = inspect_c2pa(GENUINE_SIGNED_JPEG, Some("image/jpeg"))
        .expect("a genuine signed JPEG reads without error");

    assert!(report.present, "a credential is attached");
    assert_eq!(report.verdict, C2paVerdict::SignatureValid);
    assert!(report.signature_intact());
    assert_eq!(report.validation_state.as_deref(), Some("Valid"));
}

#[test]
fn genuine_credential_reports_trust_anchor_not_established() {
    // The signature is intact, but the test certificate is not in any configured
    // trust list. The report must say so rather than overstate it as trusted.
    let report = inspect_c2pa(GENUINE_SIGNED_JPEG, Some("image/jpeg")).unwrap();

    assert!(!report.trust_anchor_established);
    assert_ne!(report.verdict, C2paVerdict::Trusted);
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.code == "signingCredential.untrusted"),
        "the untrusted-certificate status is surfaced by name, not hidden"
    );
}

#[test]
fn genuine_credential_exposes_manifest_and_signer() {
    let report = inspect_c2pa(GENUINE_SIGNED_JPEG, None).unwrap();
    let manifest = report.manifest.expect("a readable manifest is present");

    assert_eq!(manifest.claim_generator.as_deref(), Some("c2pa_test/1.0.0"));
    assert_eq!(manifest.title.as_deref(), Some("Test_Manifest"));
    assert!(!manifest.assertion_labels.is_empty());

    let signer = manifest.signer.expect("the manifest carries signer info");
    assert_eq!(signer.algorithm.as_deref(), Some("ps256"));
    assert!(signer.issuer.is_some());
}

#[test]
fn genuine_credential_does_not_falsely_flag_ai() {
    // This fixture declares no generative-AI source type. Honest reporting means
    // no AI finding, not a hedge.
    let report = inspect_c2pa(GENUINE_SIGNED_JPEG, None).unwrap();
    let manifest = report.manifest.unwrap();
    assert!(manifest.ai_generation.is_none());
}

#[test]
fn tampered_content_is_reported_invalid_by_name() {
    // Flip one content byte near the end, well past the front-loaded manifest.
    // The hard-binding data hash must then fail, and the failure must be named.
    let mut tampered = GENUINE_SIGNED_JPEG.to_vec();
    let idx = tampered.len() - 500;
    tampered[idx] ^= 0xFF;

    let report = inspect_c2pa(&tampered, Some("image/jpeg"))
        .expect("a tampered but structurally readable asset does not error");

    assert!(report.present, "the credential is still present, just invalid");
    assert_eq!(report.verdict, C2paVerdict::Invalid);
    assert!(!report.signature_intact());
    assert_eq!(report.validation_state.as_deref(), Some("Invalid"));
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.code == "assertion.dataHash.mismatch"),
        "the tamper is named as a data-hash mismatch, not dropped: {:?}",
        report.failures
    );
}

#[test]
fn file_without_a_credential_is_reported_absent() {
    for (bytes, hint) in [
        (NO_MANIFEST_JPEG, "image/jpeg"),
        (NO_MANIFEST_PNG, "image/png"),
    ] {
        let report = inspect_c2pa(bytes, Some(hint)).expect("a plain image reads without error");
        assert!(!report.present, "no credential is attached");
        assert_eq!(report.verdict, C2paVerdict::Absent);
        assert!(report.manifest.is_none());
        assert!(report.failures.is_empty());
        assert!(!report.signature_intact());
    }
}

#[test]
fn absent_is_detected_from_bytes_without_a_format_hint() {
    // With no hint the conformant reader detects the container from the bytes.
    let report = inspect_c2pa(NO_MANIFEST_PNG, None).unwrap();
    assert_eq!(report.verdict, C2paVerdict::Absent);
}

#[test]
fn unreadable_bytes_are_a_named_error_not_a_false_absent() {
    let err = inspect_c2pa(b"this is not an asset", None).unwrap_err();
    assert!(
        matches!(err, C2paReadError::UnsupportedFormat(_)),
        "unrecognised bytes are a format error, not an absent credential: {err:?}"
    );
}
