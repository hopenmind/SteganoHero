//! Phase A provenance layer, end-to-end tests (SPEC_PROVENANCE.md section 7).
//!
//! Round-trip per assertion, tamper detection by name, the distinct-key rule,
//! robustness never over-reported, and coverage over the nine corpus documents.
//! The frozen-core guarantee is checked here too: the document hash the claim
//! binds to is exactly `license::document_hash`, reused unchanged.

use stegano_core::error::SteganoError;
use stegano_core::license;
use stegano_core::provenance::{
    verify, verify_document, verify_with_policy, AiGenerated, DetachedBinding, HumanAuthorship,
    InBandBinding, Integrity, ProvenanceClaim, PublicKeyRef, RecipientFingerprint, RobustnessClass,
    SignedClaim, TrustPolicy, KIND_AI_GENERATED, KIND_HUMAN_AUTHORSHIP, KIND_INTEGRITY,
    KIND_RECIPIENT_FINGERPRINT,
};
use stegano_core::provenance::binding::{BindInput, Binding};
use stegano_core::signing::{MasterKeyPair, MasterPublicKey};
use stegano_core::stego::{Homoglyph, ZeroWidth};
use stegano_core::traits::StegoMethod;
use stegano_core::watermark::fingerprint;

// The nine corpus documents, the same set the rest of the suite uses.
const CORPUS: &[(&str, &str)] = &[
    ("en_long_article", include_str!("../../../tests/corpus/en_long_article.txt")),
    ("fr_accented", include_str!("../../../tests/corpus/fr_accented.txt")),
    ("en_short", include_str!("../../../tests/corpus/en_short.txt")),
    ("minimal_tiny", include_str!("../../../tests/corpus/minimal_tiny.txt")),
    ("cyrillic_russian", include_str!("../../../tests/corpus/cyrillic_russian.txt")),
    ("cjk_japanese", include_str!("../../../tests/corpus/cjk_japanese.txt")),
    ("mixed_multilingual", include_str!("../../../tests/corpus/mixed_multilingual.txt")),
    ("technical_markdown", include_str!("../../../tests/corpus/technical_markdown.md")),
    ("already_carrying", include_str!("../../../tests/corpus/already_carrying.txt")),
];

fn corpus(name: &str) -> &'static str {
    CORPUS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, t)| *t)
        .expect("corpus document present")
}

fn keypair() -> (MasterKeyPair, MasterPublicKey) {
    let kp = MasterKeyPair::generate();
    let pk = kp.public_key();
    (kp, pk)
}

/// Build a claim, sign it, and bind it detached. Returns the sidecar bytes.
fn sign_and_bind(assertions: &[&dyn stegano_core::provenance::Assertion], document: &str, kp: &MasterKeyPair) -> Vec<u8> {
    let claim = ProvenanceClaim::new(assertions, document, &kp.public_key(), None).unwrap();
    let signed = SignedClaim::sign(claim, kp).unwrap();
    DetachedBinding::new().bind(document, &signed).unwrap().bytes
}

// ─── round-trip per assertion ───────────────────────────────

#[test]
fn human_authorship_round_trip_holds() {
    let (kp, pk) = keypair();
    let doc = corpus("en_short");
    let author = HumanAuthorship {
        author: Some("Hope n Mind".into()),
    };
    let sidecar = sign_and_bind(&[&author], doc, &kp);

    let report = verify(doc, Some(&sidecar), &[PublicKeyRef::ed25519(&pk)]).unwrap();
    assert_eq!(report.claims.len(), 1);
    let c = &report.claims[0];
    assert!(c.signature_valid);
    assert!(c.document_unaltered);
    assert!(c.signer_trusted);
    assert!(c.has_kind(KIND_HUMAN_AUTHORSHIP));
    assert_eq!(c.robustness_realised.class, RobustnessClass::High);
    assert_eq!(report.strongest, Some(0));
}

#[test]
fn ai_generated_round_trip_holds() {
    let (kp, pk) = keypair();
    let doc = corpus("en_long_article");
    let disclosure = AiGenerated {
        model: Some("example-model-1".into()),
        provider: Some("ExampleAI".into()),
        system_version: Some("2026.08".into()),
    };
    let sidecar = sign_and_bind(&[&disclosure], doc, &kp);

    let report = verify(doc, Some(&sidecar), &[PublicKeyRef::ed25519(&pk)]).unwrap();
    let c = &report.claims[0];
    assert!(c.signature_valid && c.document_unaltered);
    assert!(c.has_kind(KIND_AI_GENERATED));

    // The typed assertion round-trips its fields.
    let typed = c.typed_assertions().unwrap();
    assert_eq!(typed[0].kind(), KIND_AI_GENERATED);
    assert_eq!(
        typed[0].to_value(),
        serde_json::json!({
            "model": "example-model-1",
            "provider": "ExampleAI",
            "system_version": "2026.08"
        })
    );
}

#[test]
fn integrity_assertion_carries_the_document_hash() {
    let (kp, pk) = keypair();
    let doc = corpus("fr_accented");
    let hash = license::document_hash(doc).unwrap();
    let integrity = Integrity {
        document_hash: hash.clone(),
    };
    let sidecar = sign_and_bind(&[&integrity], doc, &kp);

    let report = verify(doc, Some(&sidecar), &[PublicKeyRef::ed25519(&pk)]).unwrap();
    let c = &report.claims[0];
    assert!(c.has_kind(KIND_INTEGRITY));
    let typed = c.typed_assertions().unwrap();
    assert_eq!(
        typed[0].to_value(),
        serde_json::json!({ "document_hash": hash })
    );
}

#[test]
fn assertions_compose_in_one_claim() {
    let (kp, pk) = keypair();
    let doc = corpus("en_short");
    let human = HumanAuthorship {
        author: Some("Editor".into()),
    };
    let ai = AiGenerated {
        model: Some("assistant".into()),
        provider: None,
        system_version: None,
    };
    let sidecar = sign_and_bind(&[&human, &ai], doc, &kp);

    let report = verify(doc, Some(&sidecar), &[PublicKeyRef::ed25519(&pk)]).unwrap();
    let c = &report.claims[0];
    assert!(c.has_kind(KIND_HUMAN_AUTHORSHIP));
    assert!(c.has_kind(KIND_AI_GENERATED));
}

// ─── tamper: alter one visible character ────────────────────

#[test]
fn altering_one_visible_character_reports_the_document_altered_by_name() {
    let (kp, pk) = keypair();
    let doc = corpus("en_short");
    let sidecar = sign_and_bind(&[&HumanAuthorship { author: None }], doc, &kp);

    // Recase the first lowercase letter, one visible character, nothing else.
    let mut altered_one = false;
    let altered: String = doc
        .chars()
        .map(|ch| {
            if !altered_one && ch.is_ascii_lowercase() {
                altered_one = true;
                ch.to_ascii_uppercase()
            } else {
                ch
            }
        })
        .collect();
    assert!(altered_one, "the alteration must actually land");

    let report = verify(&altered, Some(&sidecar), &[PublicKeyRef::ed25519(&pk)]).unwrap();
    let c = &report.claims[0];
    // The signature over the claim is intact; only the document binding catches this.
    assert!(c.signature_valid, "the claim itself was not touched");
    assert!(!c.document_unaltered, "the document hash must no longer match");
    assert!(
        c.findings.iter().any(|f| f.contains("document altered")),
        "a finding must name the document as altered, got: {:?}",
        c.findings
    );
    // A tampered document has no surviving trusted-and-valid claim.
    assert_eq!(report.strongest, None);
}

#[test]
fn tamper_detection_reuses_the_f12_document_hash_mechanism() {
    // The claim binds to exactly what license::document_hash returns; nothing
    // in the provenance layer reimplements the hash.
    let (kp, _pk) = keypair();
    let doc = corpus("technical_markdown");
    let claim = ProvenanceClaim::new(
        &[&HumanAuthorship { author: None }],
        doc,
        &kp.public_key(),
        None,
    )
    .unwrap();
    assert_eq!(claim.document_hash, license::document_hash(doc).unwrap());
}

// ─── distinct-key rule (SPEC_PROVENANCE.md section 5) ───────

#[test]
fn a_pipeline_signed_claim_is_not_accepted_as_human_authorship() {
    // Two trust anchors: a human key and a distinct pipeline key. The human key
    // never signs here; the point is that its public half is required and the
    // pipeline's signature must not pass for it.
    let (_human_kp, human_pk) = keypair();
    let (pipeline_kp, pipeline_pk) = keypair();
    let doc = corpus("en_short");

    // The pipeline signs a claim that asserts human authorship. The embedded
    // signer is the pipeline key, the honest record of who actually signed.
    let claim = ProvenanceClaim::new(
        &[
            &HumanAuthorship {
                author: Some("Real Human".into()),
            },
            &AiGenerated {
                model: Some("pipeline".into()),
                provider: None,
                system_version: None,
            },
        ],
        doc,
        &pipeline_kp.public_key(),
        None,
    )
    .unwrap();
    let signed = SignedClaim::sign(claim, &pipeline_kp).unwrap();
    let sidecar = DetachedBinding::new().bind(doc, &signed).unwrap().bytes;

    // The verifier trusts both keys but requires human_authorship to be signed
    // by the human key, and accepts ai_generated from the pipeline key.
    let human_ref = PublicKeyRef::ed25519(&human_pk);
    let pipeline_ref = PublicKeyRef::ed25519(&pipeline_pk);
    let policy = TrustPolicy::new(vec![human_ref.clone(), pipeline_ref.clone()])
        .require(KIND_HUMAN_AUTHORSHIP, &human_ref)
        .require(KIND_AI_GENERATED, &pipeline_ref);

    let report = verify_with_policy(doc, Some(&sidecar), &policy).unwrap();
    let c = &report.claims[0];

    // The signature is cryptographically valid, the document is unaltered.
    assert!(c.signature_valid && c.document_unaltered);

    // But the pipeline-signed claim is NOT accepted for human authorship.
    assert!(
        !c.satisfies(KIND_HUMAN_AUTHORSHIP, &human_ref),
        "a pipeline key must not pass as a human key"
    );
    // It IS accepted for the AI-generated disclosure it legitimately signed.
    assert!(c.satisfies(KIND_AI_GENERATED, &pipeline_ref));

    // The report names the unmet human-authorship requirement, and only that one.
    let kinds: Vec<&str> = report
        .unmet_requirements
        .iter()
        .map(|u| u.assertion_kind.as_str())
        .collect();
    assert_eq!(kinds, vec![KIND_HUMAN_AUTHORSHIP]);
    assert!(report.unmet_requirements[0]
        .reason
        .contains("signed by a different key"));
}

#[test]
fn the_matching_key_satisfies_its_requirement() {
    let (human_kp, human_pk) = keypair();
    let doc = corpus("en_short");
    let human_ref = PublicKeyRef::ed25519(&human_pk);

    let sidecar = sign_and_bind(
        &[&HumanAuthorship {
            author: Some("Author".into()),
        }],
        doc,
        &human_kp,
    );
    let policy =
        TrustPolicy::new(vec![human_ref.clone()]).require(KIND_HUMAN_AUTHORSHIP, &human_ref);

    let report = verify_with_policy(doc, Some(&sidecar), &policy).unwrap();
    assert!(report.unmet_requirements.is_empty());
    assert!(report.claims[0].satisfies(KIND_HUMAN_AUTHORSHIP, &human_ref));
}

// ─── binding behaviour: absent, invalid, robustness ─────────

#[test]
fn an_absent_sidecar_is_absent_not_failed() {
    let (_kp, pk) = keypair();
    let doc = corpus("en_short");
    let report = verify(doc, None, &[PublicKeyRef::ed25519(&pk)]).unwrap();
    assert!(report.claims.is_empty());
    assert_eq!(report.strongest, None);
}

#[test]
fn a_corrupt_sidecar_raises_by_name() {
    let (_kp, pk) = keypair();
    let doc = corpus("en_short");
    let err = verify(doc, Some(b"{ not a sidecar"), &[PublicKeyRef::ed25519(&pk)]).unwrap_err();
    assert!(err.to_string().contains("present but unreadable"));
}

#[test]
fn a_present_but_invalid_signature_is_reported_never_dropped() {
    let (kp, pk) = keypair();
    let doc = corpus("en_short");
    let mut sidecar = sign_and_bind(&[&HumanAuthorship { author: None }], doc, &kp);

    // Corrupt the signature bytes inside the sidecar without breaking its JSON,
    // by swapping the first hex digit of the signature to a different value.
    let text = String::from_utf8(sidecar).unwrap();
    let marker = "\"signature\": \"";
    let idx = text.find(marker).unwrap() + marker.len();
    let original = &text[idx..idx + 1];
    let replacement = if original == "0" { "1" } else { "0" };
    let corrupted = format!("{}{}{}", &text[..idx], replacement, &text[idx + 1..]);
    sidecar = corrupted.into_bytes();

    let report = verify(doc, Some(&sidecar), &[PublicKeyRef::ed25519(&pk)]).unwrap();
    // The claim is present, reported invalid, not silently dropped.
    assert_eq!(report.claims.len(), 1);
    assert!(!report.claims[0].signature_valid);
    assert!(report.claims[0]
        .findings
        .iter()
        .any(|f| f.contains("signature invalid")));
    assert_eq!(report.strongest, None);
}

#[test]
fn an_untrusted_signer_is_reported_present_but_untrusted() {
    let (kp, _pk) = keypair();
    let (_other_kp, other_pk) = keypair();
    let doc = corpus("en_short");
    let sidecar = sign_and_bind(&[&HumanAuthorship { author: None }], doc, &kp);

    // Verify with a different key in the trusted set: the signature is valid
    // under its embedded key, but the signer is not trusted.
    let report = verify(doc, Some(&sidecar), &[PublicKeyRef::ed25519(&other_pk)]).unwrap();
    let c = &report.claims[0];
    assert!(c.signature_valid);
    assert!(!c.signer_trusted);
    assert_eq!(report.strongest, None, "an untrusted claim is not the strongest");
}

#[test]
fn realised_robustness_never_exceeds_the_detached_declaration() {
    let (kp, pk) = keypair();
    let doc = corpus("en_short");
    let sidecar = sign_and_bind(&[&HumanAuthorship { author: None }], doc, &kp);
    let report = verify(doc, Some(&sidecar), &[PublicKeyRef::ed25519(&pk)]).unwrap();

    let declared = DetachedBinding::new().declared_robustness().class;
    let realised = report.claims[0].robustness_realised.class;
    assert_eq!(declared, RobustnessClass::High);
    assert_eq!(realised, declared, "detached realised robustness equals its declaration");
}

// ─── frozen-core guarantee ──────────────────────────────────

#[test]
fn the_provenance_layer_reuses_document_hash_unchanged() {
    // Reuse, not reimplementation: an invisible carrier's artifacts are stripped
    // before hashing, exactly as license::document_hash does, so a claim binds
    // to the same figure whether or not the document already carries a mark.
    let doc = corpus("already_carrying");
    let (kp, _pk) = keypair();
    let claim =
        ProvenanceClaim::new(&[&HumanAuthorship { author: None }], doc, &kp.public_key(), None)
            .unwrap();
    assert_eq!(claim.document_hash, license::document_hash(doc).unwrap());
}

// ─── end to end over the nine corpus documents ──────────────

#[test]
fn round_trip_holds_over_every_corpus_document() {
    for (name, doc) in CORPUS {
        let (kp, pk) = keypair();
        let sidecar = sign_and_bind(
            &[
                &HumanAuthorship {
                    author: Some("Corpus".into()),
                },
                &AiGenerated {
                    model: Some("m".into()),
                    provider: Some("p".into()),
                    system_version: None,
                },
            ],
            doc,
            &kp,
        );

        let report = verify(doc, Some(&sidecar), &[PublicKeyRef::ed25519(&pk)]).unwrap();
        assert_eq!(report.claims.len(), 1, "{name}: exactly one detached claim");
        let c = &report.claims[0];
        assert!(c.signature_valid, "{name}: signature must verify");
        assert!(c.document_unaltered, "{name}: document must read unaltered");
        assert!(c.signer_trusted, "{name}: signer must be trusted");
        assert_eq!(report.strongest, Some(0), "{name}: the claim survives");

        // The detached binding read directly also round-trips the exact claim.
        let signed_back = DetachedBinding::new()
            .read(&BindInput {
                document: doc,
                sidecar: Some(&sidecar),
            })
            .unwrap()
            .expect("a claim is present");
        assert!(
            signed_back.verify_under(&PublicKeyRef::ed25519(&pk)).unwrap(),
            "{name}: the read-back claim verifies under the signer key"
        );
    }
}

// ─── Phase B: in-band binding ───────────────────────────────

/// Sign a claim and bind it in-band through `method`, returning the marked
/// document.
fn sign_and_bind_in_band(
    assertions: &[&dyn stegano_core::provenance::Assertion],
    document: &str,
    method: &dyn StegoMethod,
    kp: &MasterKeyPair,
) -> String {
    let claim = ProvenanceClaim::new(assertions, document, &kp.public_key(), None).unwrap();
    let signed = SignedClaim::sign(claim, kp).unwrap();
    let out = InBandBinding::new(method).bind(document, &signed).unwrap();
    String::from_utf8(out.bytes).unwrap()
}

#[test]
fn in_band_binds_and_verifies_end_to_end() {
    let (kp, pk) = keypair();
    let doc = corpus("en_long_article");
    let zw = ZeroWidth::new();

    let marked = sign_and_bind_in_band(
        &[&HumanAuthorship {
            author: Some("Hope n Mind".into()),
        }],
        doc,
        &zw,
        &kp,
    );

    // Invisible: the marked document reads exactly like its cover.
    assert_eq!(zw.strip(&marked), doc);

    let methods: [&dyn StegoMethod; 1] = [&zw];
    let policy = TrustPolicy::new(vec![PublicKeyRef::ed25519(&pk)]);
    let report = verify_document(&marked, None, &methods, &policy).unwrap();

    assert_eq!(report.claims.len(), 1);
    let c = &report.claims[0];
    assert_eq!(c.binding, "in_band");
    assert!(c.signature_valid, "the in-band signature must verify");
    assert!(c.document_unaltered, "the marked document strips to the signed cover");
    assert!(c.signer_trusted);
    assert!(c.has_kind(KIND_HUMAN_AUTHORSHIP));
    assert_eq!(c.robustness_realised.class, RobustnessClass::BestEffort);
    assert_eq!(report.strongest, Some(0));
}

#[test]
fn in_band_round_trips_through_the_homoglyph_framed_path() {
    // Homoglyph is the carrier the framed pipeline fixed (F0/F2); the in-band
    // binding routes through the same path, so it verifies end to end. Homoglyph
    // is cover-bounded, so a whole signed claim needs a Latin cover wide enough
    // to hold it.
    let (kp, pk) = keypair();
    let doc =
        "The quick brown fox jumps over a lazy dog while a copy escapes precisely today. "
            .repeat(200);
    let hg = Homoglyph::new();

    let marked = sign_and_bind_in_band(&[&HumanAuthorship { author: None }], &doc, &hg, &kp);
    assert_ne!(marked, doc, "the claim must actually be carried by substitutions");
    // The homoglyph mark strips back to the cover (F7/F12b), so the document
    // hash the claim signed over is reproduced.
    assert_eq!(hg.strip(&marked), doc);

    let methods: [&dyn StegoMethod; 1] = [&hg];
    let policy = TrustPolicy::new(vec![PublicKeyRef::ed25519(&pk)]);
    let report = verify_document(&marked, None, &methods, &policy).unwrap();

    let c = &report.claims[0];
    assert_eq!(c.binding, "in_band");
    assert!(c.signature_valid && c.document_unaltered);
    assert_eq!(c.robustness_realised.class, RobustnessClass::BestEffort);
}

#[test]
fn in_band_realised_robustness_is_measured_and_never_exceeds_best_effort() {
    // The verify path measures the realised robustness on the produced document
    // rather than echoing the declaration: the note carries the analyser's own
    // verdict, and the class is never raised above the BestEffort an in-band
    // mark delivers.
    let (kp, pk) = keypair();
    let doc = corpus("en_long_article");
    let zw = ZeroWidth::new();
    let marked = sign_and_bind_in_band(&[&HumanAuthorship { author: None }], doc, &zw, &kp);

    let methods: [&dyn StegoMethod; 1] = [&zw];
    let policy = TrustPolicy::new(vec![PublicKeyRef::ed25519(&pk)]);
    let report = verify_document(&marked, None, &methods, &policy).unwrap();
    let realised = &report.claims[0].robustness_realised;

    assert_eq!(realised.class, RobustnessClass::BestEffort);
    let measured_verdict = stegano_core::forensic::analyze(&marked).verdict.to_string();
    assert!(
        realised.note.contains(&measured_verdict),
        "the realised note must carry the verdict measured on the document, got: {}",
        realised.note
    );
    // In-band never claims the detached binding's High robustness.
    assert_ne!(realised.class, RobustnessClass::High);
}

#[test]
fn in_band_too_small_cover_raises_capacity_exceeded_by_named_arithmetic() {
    // Homoglyph is cover-bounded: a document with too few substitutable
    // positions to hold the framed claim raises CapacityExceeded rather than
    // truncating (invariant 2, SPEC_PROVENANCE.md section 3).
    let (kp, _pk) = keypair();
    let tiny = corpus("minimal_tiny");
    let hg = Homoglyph::new();

    let claim = ProvenanceClaim::new(
        &[&HumanAuthorship {
            author: Some("Hope n Mind".into()),
        }],
        tiny,
        &kp.public_key(),
        None,
    )
    .unwrap();
    let signed = SignedClaim::sign(claim, &kp).unwrap();

    match InBandBinding::new(&hg).bind(tiny, &signed) {
        Err(SteganoError::CapacityExceeded { needed, available }) => {
            assert!(
                needed > available,
                "needed ({needed} bits) must exceed available ({available} bits)"
            );
        }
        other => panic!("expected CapacityExceeded, got {other:?}"),
    }
}

#[test]
fn in_band_altering_one_visible_character_reports_the_document_altered_by_name() {
    // The F12 mechanism through the in-band path: the payload rides untouched,
    // so the signature stays valid, and only the document hash catches a visible
    // edit, naming it.
    let (kp, pk) = keypair();
    let doc = corpus("en_long_article");
    let zw = ZeroWidth::new();
    let marked = sign_and_bind_in_band(&[&HumanAuthorship { author: None }], doc, &zw, &kp);

    let mut altered_one = false;
    let altered: String = marked
        .chars()
        .map(|ch| {
            if !altered_one && ch.is_ascii_lowercase() {
                altered_one = true;
                ch.to_ascii_uppercase()
            } else {
                ch
            }
        })
        .collect();
    assert!(altered_one, "the alteration must actually land");

    let methods: [&dyn StegoMethod; 1] = [&zw];
    let policy = TrustPolicy::new(vec![PublicKeyRef::ed25519(&pk)]);
    let report = verify_document(&altered, None, &methods, &policy).unwrap();
    let c = &report.claims[0];

    assert!(c.signature_valid, "the claim itself was not touched");
    assert!(!c.document_unaltered, "the document hash must no longer match");
    assert!(
        c.findings.iter().any(|f| f.contains("document altered")),
        "a finding must name the document as altered, got: {:?}",
        c.findings
    );
    assert_eq!(report.strongest, None);
}

#[test]
fn detached_and_in_band_read_together_and_detached_is_strongest() {
    // A document can carry both bindings at once; the strongest surviving claim
    // is the detached one, since it is High and the in-band one is BestEffort.
    let (kp, pk) = keypair();
    let doc = corpus("en_long_article");
    let zw = ZeroWidth::new();

    let claim = ProvenanceClaim::new(&[&HumanAuthorship { author: None }], doc, &kp.public_key(), None)
        .unwrap();
    let signed = SignedClaim::sign(claim, &kp).unwrap();
    let sidecar = DetachedBinding::new().bind(doc, &signed).unwrap().bytes;
    let marked = String::from_utf8(InBandBinding::new(&zw).bind(doc, &signed).unwrap().bytes).unwrap();

    let methods: [&dyn StegoMethod; 1] = [&zw];
    let policy = TrustPolicy::new(vec![PublicKeyRef::ed25519(&pk)]);
    let report = verify_document(&marked, Some(&sidecar), &methods, &policy).unwrap();

    assert_eq!(report.claims.len(), 2, "both bindings read a claim");
    let strongest = report.strongest.expect("a surviving strongest claim");
    assert_eq!(report.claims[strongest].binding, "detached");
    assert_eq!(
        report.claims[strongest].robustness_realised.class,
        RobustnessClass::High
    );
}

// ─── Phase B: recipient_fingerprint assertion ───────────────

#[test]
fn recipient_fingerprint_round_trips_composes_and_identifies_on_verify() {
    let (kp, pk) = keypair();
    let doc = corpus("en_long_article");

    // Canary-trap the document for three recipients, then make a provenance
    // claim carrying the fingerprint the canary module assigned one of them.
    let batch = fingerprint::generate_batch(doc, &["alice", "bob", "carol"], "doc-2026-q3").unwrap();
    let bob = batch
        .versions
        .iter()
        .find(|v| v.recipient.id == "bob")
        .unwrap()
        .recipient
        .clone();
    let alice = batch
        .versions
        .iter()
        .find(|v| v.recipient.id == "alice")
        .unwrap()
        .recipient
        .clone();

    let rf = RecipientFingerprint::from_recipient(&bob);
    // It composes with another assertion in the same claim.
    let sidecar = sign_and_bind(
        &[
            &HumanAuthorship {
                author: Some("Editor".into()),
            },
            &rf,
        ],
        doc,
        &kp,
    );

    let report = verify(doc, Some(&sidecar), &[PublicKeyRef::ed25519(&pk)]).unwrap();
    let c = &report.claims[0];
    assert!(c.has_kind(KIND_HUMAN_AUTHORSHIP));
    assert!(c.has_kind(KIND_RECIPIENT_FINGERPRINT));

    // On verify the claim identifies the recipient it was issued to: it matches
    // bob's canary identifier and not alice's.
    let typed = c.typed_assertions().unwrap();
    let carried = typed
        .iter()
        .find(|a| a.kind() == KIND_RECIPIENT_FINGERPRINT)
        .unwrap()
        .to_value();
    assert_eq!(carried["recipient_id"], serde_json::json!("bob"));
    assert_eq!(
        carried["fingerprint_hash"],
        serde_json::json!(bob.fingerprint_hash)
    );
    assert_ne!(
        carried["fingerprint_hash"],
        serde_json::json!(alice.fingerprint_hash),
        "the claim must not match a different recipient"
    );
}

#[test]
fn recipient_fingerprint_composes_with_all_kinds_and_rides_in_band() {
    // All four assertion kinds in one claim, bound in-band, verified end to end.
    let (kp, pk) = keypair();
    let doc = corpus("en_long_article");
    let zw = ZeroWidth::new();

    let hash = license::document_hash(doc).unwrap();
    let rf = RecipientFingerprint::derive("bob", "doc-2026-q3", doc).unwrap();
    let marked = sign_and_bind_in_band(
        &[
            &HumanAuthorship {
                author: Some("Editor".into()),
            },
            &AiGenerated {
                model: Some("assistant".into()),
                provider: None,
                system_version: None,
            },
            &Integrity {
                document_hash: hash,
            },
            &rf,
        ],
        doc,
        &zw,
        &kp,
    );

    let methods: [&dyn StegoMethod; 1] = [&zw];
    let policy = TrustPolicy::new(vec![PublicKeyRef::ed25519(&pk)]);
    let report = verify_document(&marked, None, &methods, &policy).unwrap();
    let c = &report.claims[0];

    assert_eq!(c.binding, "in_band");
    assert!(c.signature_valid && c.document_unaltered);
    assert!(c.has_kind(KIND_HUMAN_AUTHORSHIP));
    assert!(c.has_kind(KIND_AI_GENERATED));
    assert!(c.has_kind(KIND_INTEGRITY));
    assert!(c.has_kind(KIND_RECIPIENT_FINGERPRINT));
    assert_eq!(c.robustness_realised.class, RobustnessClass::BestEffort);
}
