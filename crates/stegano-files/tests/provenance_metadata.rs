//! The format-metadata provenance route (VISION Phase C, by composition).
//!
//! These tests prove, over a real in-memory DOCX fixture, that signing a
//! provenance claim into a document's metadata channel and verifying it back
//! reports a trusted, unaltered claim; that an edit to the VISIBLE content is
//! reported altered BY NAME (tamper-evidence, the whole point of the document
//! hash); that an untrusted key is present-but-untrusted; that the distinct-key
//! trust policy names an unmet per-kind requirement; that the assertions
//! round-trip and are reported; that a clean file reports absent (not an error);
//! that PNG, SVG and a channel-less format are refused BY NAME; and that the
//! signed file's content is byte-identical to the source except the one added
//! metadata entry (zero-loss).
//!
//! Every fixture is built in memory, so the suite needs no on-disk corpus.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};

use stegano_files::{
    embed_metadata, extract_text, recover_metadata, sign_into_metadata, verify_from_metadata,
    AiGenerated, FileFormat, HumanAuthorship, Integrity, MasterKeyPair, ProvenanceMetadataError,
    PublicKeyRef, RobustnessClass, TrustPolicy, BINDING_KIND, DOCX_METADATA_ENTRY,
    KIND_AI_GENERATED, KIND_HUMAN_AUTHORSHIP, KIND_INTEGRITY,
};

// ── Fixtures ──────────────────────────────────────────────────────────────────

/// A minimal, readable DOCX carrying `body` as its only run of text.
fn docx_with_text(body: &str) -> Vec<u8> {
    let doc = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\n\
  <w:body>\n\
    <w:p><w:r><w:t xml:space=\"preserve\">{body}</w:t></w:r></w:p>\n\
  </w:body>\n\
</w:document>"
    );
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, content) in [
            ("[Content_Types].xml", "<?xml version=\"1.0\"?><Types/>"),
            ("_rels/.rels", "<?xml version=\"1.0\"?><Relationships/>"),
            ("word/document.xml", doc.as_str()),
        ] {
            w.start_file(name, opts).unwrap();
            w.write_all(content.as_bytes()).unwrap();
        }
        w.finish().unwrap();
    }
    buf
}

/// Decompressed content of every ZIP entry, keyed by name.
fn zip_entries(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut map = BTreeMap::new();
    for i in 0..archive.len() {
        let mut f = archive.by_index(i).unwrap();
        let name = f.name().to_string();
        let mut content = Vec::new();
        f.read_to_end(&mut content).unwrap();
        map.insert(name, content);
    }
    map
}

fn keypair_and_ref() -> (MasterKeyPair, PublicKeyRef) {
    let kp = MasterKeyPair::generate();
    let reference = PublicKeyRef::ed25519(&kp.public_key());
    (kp, reference)
}

// ── Round trip: trusted, unaltered ────────────────────────────────────────────

#[test]
fn sign_then_verify_reports_a_trusted_unaltered_claim_on_the_format_metadata_route() {
    let docx = docx_with_text("A document whose provenance rides its own metadata.");
    let (kp, signer) = keypair_and_ref();
    let policy = TrustPolicy::new(vec![signer]);

    let signed = sign_into_metadata(
        &docx,
        FileFormat::Docx,
        &kp,
        &[&HumanAuthorship {
            author: Some("Ada".into()),
        }],
        Some("2026-08-27T00:00:00Z".into()),
    )
    .unwrap();

    let report = verify_from_metadata(&signed, FileFormat::Docx, &policy).unwrap();

    assert_eq!(report.claims.len(), 1, "one claim must be read back");
    let c = &report.claims[0];
    assert!(c.signature_valid, "the signature must verify");
    assert!(c.signer_trusted, "the signer is in the trusted set");
    assert!(c.document_unaltered, "the content is untouched, so unaltered");
    assert!(c.has_kind(KIND_HUMAN_AUTHORSHIP));
    // The route is reported truthfully: format_metadata / FormatBound, never the
    // detached adapter's "detached" / High that the core evaluation ran through.
    assert_eq!(c.binding, BINDING_KIND);
    assert_eq!(c.robustness_realised.class, RobustnessClass::FormatBound);
    assert_eq!(report.strongest, Some(0), "the clean claim is the strongest");
}

// ── Tamper-evidence: an edit to the visible content is named ───────────────────

#[test]
fn editing_the_visible_text_after_signing_reports_altered_by_name() {
    let original = docx_with_text("The original sentence stands here for signing.");
    let (kp, signer) = keypair_and_ref();
    let policy = TrustPolicy::new(vec![signer]);

    let signed = sign_into_metadata(
        &original,
        FileFormat::Docx,
        &kp,
        &[&HumanAuthorship { author: None }],
        None,
    )
    .unwrap();

    // Carry the SAME signed claim onto an edited document: recover the claim
    // bytes and re-embed them into a DOCX whose visible text has changed.
    let claim_bytes = recover_metadata(&signed, FileFormat::Docx).unwrap().unwrap();
    let edited = docx_with_text("The original sentence was quietly changed here.");
    let tampered = embed_metadata(&edited, FileFormat::Docx, &claim_bytes).unwrap();

    let report = verify_from_metadata(&tampered, FileFormat::Docx, &policy).unwrap();
    assert_eq!(report.claims.len(), 1);
    let c = &report.claims[0];
    assert!(
        c.signature_valid,
        "the signature is over the claim, so it still verifies"
    );
    assert!(
        !c.document_unaltered,
        "the visible text changed, so the recomputed hash must differ"
    );
    assert!(
        c.findings.iter().any(|f| f.contains("document altered")),
        "the alteration must be named, not hidden: {:?}",
        c.findings
    );
    assert!(
        report.strongest.is_none(),
        "an altered claim never counts as the strongest"
    );
}

// ── Trust: an untrusted signer is present-but-untrusted ────────────────────────

#[test]
fn a_claim_signed_by_an_untrusted_key_is_present_but_untrusted() {
    let docx = docx_with_text("Signed by a key the verifier does not trust.");
    let (kp, _signer) = keypair_and_ref();
    // A policy that trusts nobody.
    let policy = TrustPolicy::default();

    let signed = sign_into_metadata(
        &docx,
        FileFormat::Docx,
        &kp,
        &[&HumanAuthorship { author: None }],
        None,
    )
    .unwrap();

    let report = verify_from_metadata(&signed, FileFormat::Docx, &policy).unwrap();
    assert_eq!(report.claims.len(), 1, "the claim is present");
    let c = &report.claims[0];
    assert!(c.signature_valid, "the signature is still cryptographically valid");
    assert!(!c.signer_trusted, "the signer is outside the trusted set");
    assert!(
        c.findings.iter().any(|f| f.contains("signer not trusted")),
        "the untrusted signer must be named: {:?}",
        c.findings
    );
    assert!(report.strongest.is_none(), "an untrusted claim is not the strongest");
}

// ── Distinct-key trust policy: a per-kind requirement names its obstacle ────────

#[test]
fn the_distinct_key_policy_names_an_unmet_requirement() {
    let docx = docx_with_text("A pipeline key states human authorship, which is refused.");
    // The claim is signed by a pipeline key.
    let (pipeline_kp, pipeline_ref) = keypair_and_ref();
    // A distinct human key is what the policy demands for human_authorship.
    let (_human_kp, human_ref) = keypair_and_ref();
    let policy = TrustPolicy::new(vec![pipeline_ref]).require(KIND_HUMAN_AUTHORSHIP, &human_ref);

    let signed = sign_into_metadata(
        &docx,
        FileFormat::Docx,
        &pipeline_kp,
        &[&HumanAuthorship { author: None }],
        None,
    )
    .unwrap();

    let report = verify_from_metadata(&signed, FileFormat::Docx, &policy).unwrap();
    // The claim itself is present and its signer is trusted, but the human
    // requirement is unmet because a different key signed it.
    assert_eq!(report.unmet_requirements.len(), 1);
    let unmet = &report.unmet_requirements[0];
    assert_eq!(unmet.assertion_kind, KIND_HUMAN_AUTHORSHIP);
    assert!(
        unmet.reason.contains("different key"),
        "the reason must name the distinct-key obstacle: {}",
        unmet.reason
    );
}

// ── Assertions round-trip and are reported ─────────────────────────────────────

#[test]
fn the_assertions_round_trip_and_are_reported() {
    let docx = docx_with_text("A document carrying three assertions at once.");
    let (kp, signer) = keypair_and_ref();
    let policy = TrustPolicy::new(vec![signer]);

    // The Integrity assertion carries the true document hash (the core's own,
    // over the extracted text), reused rather than invented.
    let text = extract_text(&docx, FileFormat::Docx).unwrap().text;
    let doc_hash = stegano_core::license::document_hash(&text).unwrap();

    let signed = sign_into_metadata(
        &docx,
        FileFormat::Docx,
        &kp,
        &[
            &HumanAuthorship {
                author: Some("Ada".into()),
            },
            &AiGenerated {
                model: Some("example-model-1".into()),
                provider: Some("ExampleAI".into()),
                system_version: None,
            },
            &Integrity {
                document_hash: doc_hash.clone(),
            },
        ],
        None,
    )
    .unwrap();

    let report = verify_from_metadata(&signed, FileFormat::Docx, &policy).unwrap();
    let c = &report.claims[0];
    assert!(c.has_kind(KIND_HUMAN_AUTHORSHIP));
    assert!(c.has_kind(KIND_AI_GENERATED));
    assert!(c.has_kind(KIND_INTEGRITY));

    // The assertion payloads round-trip: the AI model and the integrity hash come
    // back exactly as signed.
    let ai = c
        .assertions
        .iter()
        .find(|r| r.kind == KIND_AI_GENERATED)
        .expect("ai_generated must be reported");
    assert_eq!(
        ai.payload.get("model").and_then(|v| v.as_str()),
        Some("example-model-1")
    );
    let integrity = c
        .assertions
        .iter()
        .find(|r| r.kind == KIND_INTEGRITY)
        .expect("integrity must be reported");
    assert_eq!(
        integrity.payload.get("document_hash").and_then(|v| v.as_str()),
        Some(doc_hash.as_str())
    );
}

// ── Absent on a clean file ─────────────────────────────────────────────────────

#[test]
fn verify_on_a_clean_file_reports_absent() {
    let docx = docx_with_text("A clean document with no claim in its metadata.");
    let report = verify_from_metadata(&docx, FileFormat::Docx, &TrustPolicy::default()).unwrap();
    assert!(report.claims.is_empty(), "no claim means an empty, absent report");
    assert!(report.strongest.is_none());
    assert!(report.unmet_requirements.is_empty());
}

// ── Refusals by name ───────────────────────────────────────────────────────────

#[test]
fn png_and_svg_are_refused_by_name() {
    let kp = MasterKeyPair::generate();
    for (format, name) in [(FileFormat::Png, "png"), (FileFormat::Svg, "svg")] {
        let err = sign_into_metadata(b"image bytes", format, &kp, &[], None).unwrap_err();
        match &err {
            ProvenanceMetadataError::UnsupportedFormat { format: f, .. } => assert_eq!(*f, name),
            other => panic!("expected UnsupportedFormat naming {name}, got {other:?}"),
        }
        assert!(err.to_string().contains(name), "the refusal must name {name}");

        let err =
            verify_from_metadata(b"image bytes", format, &TrustPolicy::default()).unwrap_err();
        assert!(
            matches!(err, ProvenanceMetadataError::UnsupportedFormat { .. }),
            "verify must also refuse {name} by name"
        );
    }
}

#[test]
fn a_channel_less_format_is_refused_by_name() {
    let kp = MasterKeyPair::generate();
    // Markdown is text-bearing but carries no metadata channel in this build, so
    // the metadata channel refuses it by name (through the Metadata variant).
    let err = sign_into_metadata(
        b"# A markdown document\n",
        FileFormat::Markdown,
        &kp,
        &[&HumanAuthorship { author: None }],
        None,
    )
    .unwrap_err();
    assert!(
        matches!(err, ProvenanceMetadataError::Metadata(_)),
        "a channel-less format must be refused through the metadata channel"
    );
    assert!(err.to_string().contains("markdown"), "the refusal must name markdown: {err}");

    let err = verify_from_metadata(
        b"# A markdown document\n",
        FileFormat::Markdown,
        &TrustPolicy::default(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("markdown"), "verify must also name markdown: {err}");
}

#[test]
fn a_present_but_corrupt_claim_is_refused_by_name() {
    // A metadata channel that carries bytes which are not a readable signed claim
    // must be named present-but-invalid, never silently treated as absent.
    let docx = docx_with_text("A document whose metadata holds junk, not a claim.");
    let poisoned = embed_metadata(&docx, FileFormat::Docx, b"this is not a signed claim").unwrap();

    let err =
        verify_from_metadata(&poisoned, FileFormat::Docx, &TrustPolicy::default()).unwrap_err();
    match &err {
        ProvenanceMetadataError::UnreadableClaim { format, .. } => assert_eq!(*format, "docx"),
        other => panic!("expected UnreadableClaim naming docx, got {other:?}"),
    }
}

// ── Zero-loss: content byte-identical except the one added metadata entry ──────

#[test]
fn the_signed_file_is_byte_identical_to_the_source_except_the_added_metadata_entry() {
    let docx = docx_with_text("The content must survive signing byte-for-byte.");
    let (kp, _signer) = keypair_and_ref();

    let signed = sign_into_metadata(
        &docx,
        FileFormat::Docx,
        &kp,
        &[&HumanAuthorship { author: None }],
        None,
    )
    .unwrap();

    let before = zip_entries(&docx);
    let after = zip_entries(&signed);

    // Every original entry survives byte-for-byte.
    for (name, content) in &before {
        assert_eq!(
            after.get(name),
            Some(content),
            "entry {name} was not preserved byte-for-byte"
        );
    }
    // Exactly one entry was added, and it is the metadata entry.
    let added: Vec<&String> = after.keys().filter(|k| !before.contains_key(*k)).collect();
    assert_eq!(added.len(), 1, "exactly one entry may be added");
    assert_eq!(added[0], DOCX_METADATA_ENTRY);

    // The document's extracted text is unchanged.
    assert_eq!(
        extract_text(&signed, FileFormat::Docx).unwrap().text,
        extract_text(&docx, FileFormat::Docx).unwrap().text
    );
}
