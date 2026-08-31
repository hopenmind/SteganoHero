//! Bindings: how a signed claim attaches to a document.
//!
//! Phase A ships the detached binding, a JSON sidecar kept beside the text. It
//! survives any document transform while it is kept and nothing once dropped,
//! which is why it declares `High` robustness. The in-band binding (through the
//! carriers, Phase B) and the format-metadata binding (Phase C) are not built
//! here; their trait shape is reserved so they drop in additively.
//!
//! Each binding declares a robustness class and the verify path measures the
//! realised one, never reporting more than the binding delivered on the actual
//! document (SPEC_PROVENANCE.md section 3).

use crate::error::{Result, SteganoError};
use crate::traits::StegoMethod;

use super::{ProvenanceClaim, SignedClaim};

/// Sidecar schema version.
pub const SIDECAR_VERSION: u8 = 1;

/// How survivable a mark is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RobustnessClass {
    /// Survives any document transform while the binding is kept (detached).
    High,
    /// Survives copy and paste, not a determined strip or rewrite (in-band).
    BestEffort,
    /// Survives within a format, stripped by conversion (format metadata).
    FormatBound,
}

/// A robustness class with a human-readable note.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Robustness {
    /// The class.
    pub class: RobustnessClass,
    /// A plain-language note on what this class means for this binding.
    pub note: String,
}

impl Robustness {
    /// A `High` robustness with a note.
    pub fn high(note: &str) -> Self {
        Self {
            class: RobustnessClass::High,
            note: note.to_string(),
        }
    }

    /// A `BestEffort` robustness with a note.
    pub fn best_effort(note: &str) -> Self {
        Self {
            class: RobustnessClass::BestEffort,
            note: note.to_string(),
        }
    }
}

/// What a binding produces when it attaches a claim.
#[derive(Debug, Clone)]
pub struct BindOutput {
    /// The binding kind that produced this.
    pub kind: String,
    /// The attachment bytes. For the detached binding, the sidecar JSON.
    pub bytes: Vec<u8>,
}

/// What a binding reads a claim back from.
pub struct BindInput<'a> {
    /// The document as it reads now.
    pub document: &'a str,
    /// The detached sidecar, if one is kept beside the document.
    pub sidecar: Option<&'a [u8]>,
}

/// How a claim attaches to, and reads back from, a document.
pub trait Binding {
    /// Stable kind identifier: "detached" | "in_band" | "format_metadata".
    fn kind(&self) -> &str;
    /// The robustness this binding declares before the document is measured.
    fn declared_robustness(&self) -> Robustness;
    /// Attach an already-signed claim. Signing is a separate, explicit step
    /// (`SignedClaim::sign`) so the caller chooses which key signs, which the
    /// distinct-key model depends on.
    fn bind(&self, cover: &str, signed: &SignedClaim) -> Result<BindOutput>;
    /// Read a signed claim back. `Ok(None)` means the binding carried nothing
    /// (absent, not failed); an `Err` means it carried something unreadable.
    fn read(&self, input: &BindInput) -> Result<Option<SignedClaim>>;
}

// ─── detached ───────────────────────────────────────────────

/// The detached binding: a JSON sidecar kept beside the text. A documented
/// shape (SPEC_PROVENANCE.md section 3), not a private opaque blob, so a
/// non-SteganoHero reader can inspect it. C2PA wire-format is Phase C.
#[derive(Debug, Clone, Copy, Default)]
pub struct DetachedBinding;

impl DetachedBinding {
    /// Construct a detached binding.
    pub fn new() -> Self {
        Self
    }
}

/// The on-disk sidecar shape. Written pretty for inspection; the signature is
/// over the claim's own canonical bytes, recomputed on read, so the sidecar's
/// own formatting does not affect verification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Sidecar {
    sidecar_version: u8,
    binding: String,
    robustness: Robustness,
    claim: ProvenanceClaim,
    signature: String,
}

impl Binding for DetachedBinding {
    fn kind(&self) -> &str {
        "detached"
    }

    fn declared_robustness(&self) -> Robustness {
        Robustness::high(
            "detached sidecar: survives any document transform while it is kept, \
             nothing once it is dropped",
        )
    }

    fn bind(&self, _cover: &str, signed: &SignedClaim) -> Result<BindOutput> {
        let sidecar = Sidecar {
            sidecar_version: SIDECAR_VERSION,
            binding: self.kind().to_string(),
            robustness: self.declared_robustness(),
            claim: signed.claim.clone(),
            signature: signed.signature.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&sidecar)?;
        Ok(BindOutput {
            kind: self.kind().to_string(),
            bytes,
        })
    }

    fn read(&self, input: &BindInput) -> Result<Option<SignedClaim>> {
        let Some(bytes) = input.sidecar else {
            // No sidecar kept: the binding is absent, not failed.
            return Ok(None);
        };
        let sidecar: Sidecar = serde_json::from_slice(bytes).map_err(|e| {
            SteganoError::InvalidInput(format!(
                "detached sidecar is present but unreadable: {e}"
            ))
        })?;
        if sidecar.binding != self.kind() {
            return Err(SteganoError::InvalidInput(format!(
                "detached sidecar declares binding '{}', not 'detached'",
                sidecar.binding
            )));
        }
        Ok(Some(SignedClaim {
            claim: sidecar.claim,
            signature: sidecar.signature,
        }))
    }
}

// ─── in_band ────────────────────────────────────────────────

/// The in-band binding: the signed claim woven into the cover text itself
/// through a chosen [`StegoMethod`] carrier (SPEC_PROVENANCE.md section 3).
///
/// Provenance-owned, not a reuse of `license::sign_and_embed`, which is
/// `License`-specific and cannot carry arbitrary claim bytes without touching
/// the frozen core (P-A carry-over note). It mirrors that path: it serialises
/// the [`SignedClaim`], routes it through [`crate::pipeline::encode`] (the
/// framed path with `payload_bits`, which is what makes the homoglyph carrier
/// round-trip, backlog F0/F2) and reads it back through
/// [`crate::pipeline::decode`]. Signing stays a separate, explicit step so the
/// distinct-key model keeps its choice of key.
///
/// It declares [`RobustnessClass::BestEffort`]: an in-band mark survives copy
/// and paste but not a determined strip or a rewrite. The verify path does not
/// take that on trust; it measures the realised robustness on the document that
/// was produced ([`InBandBinding::realised_robustness`]) and never reports more
/// than the declaration.
pub struct InBandBinding<'a> {
    method: &'a dyn StegoMethod,
}

impl<'a> InBandBinding<'a> {
    /// Bind through `method`. Any single [`StegoMethod`] carrier works; the
    /// carrier is untouched (invariant 4), the framing lives in the pipeline.
    pub fn new(method: &'a dyn StegoMethod) -> Self {
        Self { method }
    }

    /// The carrier this binding routes through.
    pub fn method(&self) -> &dyn StegoMethod {
        self.method
    }

    /// The realised robustness of this binding on `document`, measured rather
    /// than declared (SPEC_PROVENANCE.md section 3). The class is capped at the
    /// declared `BestEffort`: measurement can confirm or lower survivability,
    /// never raise it above what an in-band mark can deliver. The note carries
    /// what the tool's own analysers return on the produced document, so the
    /// figure is one an analyst would measure, not an assumption (invariant 2).
    pub fn realised_robustness(&self, document: &str) -> Robustness {
        let verdict = crate::forensic::analyze(document).verdict;
        let density = crate::metrics::noise_density(document);
        let exposure = crate::fidelity::baseline(document, &crate::fidelity::FidelityOptions::default())
            .overall
            .analyst_exposure;
        Robustness::best_effort(&format!(
            "in-band mark measured on the produced document: forensic verdict {verdict}, \
             channel density {density:.4}, codepoint audit {exposure:?}; survives copy and \
             paste, not a determined strip or a rewrite"
        ))
    }
}

impl Binding for InBandBinding<'_> {
    fn kind(&self) -> &str {
        "in_band"
    }

    fn declared_robustness(&self) -> Robustness {
        Robustness::best_effort(
            "in-band mark through a carrier: survives copy and paste, not a determined \
             strip or a rewrite; the realised figure is measured on the document",
        )
    }

    fn bind(&self, cover: &str, signed: &SignedClaim) -> Result<BindOutput> {
        // The whole signed claim, claim plus signature, is what rides in-band;
        // `read` parses it straight back and the verify path checks it.
        let claim_bytes = serde_json::to_vec(signed)?;

        // A cover the carrier bounds has a hard ceiling: name the arithmetic and
        // refuse rather than truncate (invariant 2, SPEC_PROVENANCE.md section 3).
        // A carrier that creates the positions it writes is not cover-bounded,
        // so it extends the document instead, and `pipeline::encode` is the
        // authority on its refusals.
        if crate::format::cover_bounds_writes(self.method, cover) {
            let available = crate::pipeline::secret_capacity_bytes(cover, &[self.method], None)
                .unwrap_or(0);
            if claim_bytes.len() > available {
                return Err(SteganoError::CapacityExceeded {
                    needed: claim_bytes.len() * 8,
                    available: available * 8,
                });
            }
        }

        let encoded = crate::pipeline::encode(cover, &claim_bytes, &[self.method], None)?;
        Ok(BindOutput {
            kind: self.kind().to_string(),
            bytes: encoded.stego_text.into_bytes(),
        })
    }

    fn read(&self, input: &BindInput) -> Result<Option<SignedClaim>> {
        // No cipher: the claim is signed for attribution, not kept secret.
        // A carrier that holds no framed layer of its own reads nothing, which
        // is "absent", not a failure (SPEC_PROVENANCE.md section 4).
        let decoded = match crate::pipeline::decode(input.document, &[self.method], &[], None) {
            Ok(decoded) => decoded,
            Err(SteganoError::NothingDetected) => return Ok(None),
            Err(e) => return Err(e),
        };
        let signed: SignedClaim = serde_json::from_slice(&decoded.hidden_data).map_err(|e| {
            SteganoError::InvalidInput(format!(
                "in-band binding is present but its bytes are not a readable signed claim: {e}"
            ))
        })?;
        Ok(Some(signed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::{HumanAuthorship, ProvenanceClaim};
    use crate::signing::MasterKeyPair;

    fn signed_over(document: &str) -> SignedClaim {
        let kp = MasterKeyPair::generate();
        let claim = ProvenanceClaim::new(
            &[&HumanAuthorship { author: None }],
            document,
            &kp.public_key(),
            None,
        )
        .unwrap();
        SignedClaim::sign(claim, &kp).unwrap()
    }

    #[test]
    fn detached_declares_high_robustness() {
        assert_eq!(
            DetachedBinding::new().declared_robustness().class,
            RobustnessClass::High
        );
    }

    #[test]
    fn bind_then_read_round_trips_the_signed_claim() {
        let doc = "a document to bind";
        let signed = signed_over(doc);
        let out = DetachedBinding::new().bind(doc, &signed).unwrap();

        let back = DetachedBinding::new()
            .read(&BindInput {
                document: doc,
                sidecar: Some(&out.bytes),
            })
            .unwrap()
            .expect("the sidecar carries a claim");
        assert_eq!(back, signed);
    }

    #[test]
    fn an_absent_sidecar_reads_as_absent_not_failed() {
        let read = DetachedBinding::new()
            .read(&BindInput {
                document: "doc",
                sidecar: None,
            })
            .unwrap();
        assert!(read.is_none());
    }

    #[test]
    fn a_corrupt_sidecar_is_refused_by_name() {
        let err = DetachedBinding::new()
            .read(&BindInput {
                document: "doc",
                sidecar: Some(b"{ this is not a sidecar"),
            })
            .unwrap_err();
        assert!(err.to_string().contains("present but unreadable"));
    }

    // ─── in_band ────────────────────────────────────────────

    const IN_BAND_COVER: &str =
        "Access to the open science project expectations are exceptional in scope and \
         practice today across every possible aspect of the ecosystem operations including \
         all cooperative joint exercises previously associated with the core operations \
         executive committee since its inception a full year ago today across the divisions";

    #[test]
    fn in_band_declares_best_effort_robustness() {
        let zw = crate::stego::ZeroWidth::new();
        assert_eq!(
            InBandBinding::new(&zw).declared_robustness().class,
            RobustnessClass::BestEffort
        );
    }

    #[test]
    fn in_band_bind_then_read_round_trips_the_signed_claim() {
        let zw = crate::stego::ZeroWidth::new();
        let signed = signed_over(IN_BAND_COVER);
        let binding = InBandBinding::new(&zw);

        let out = binding.bind(IN_BAND_COVER, &signed).unwrap();
        assert_eq!(out.kind, "in_band");
        let document = String::from_utf8(out.bytes).unwrap();
        // The mark is invisible: the document strips back to the cover.
        assert_eq!(zw.strip(&document), IN_BAND_COVER);

        let back = binding
            .read(&BindInput {
                document: &document,
                sidecar: None,
            })
            .unwrap()
            .expect("the document carries a claim");
        assert_eq!(back, signed);
    }

    #[test]
    fn in_band_reads_absent_when_the_carrier_holds_nothing() {
        let zw = crate::stego::ZeroWidth::new();
        let read = InBandBinding::new(&zw)
            .read(&BindInput {
                document: IN_BAND_COVER,
                sidecar: None,
            })
            .unwrap();
        assert!(read.is_none());
    }

    #[test]
    fn in_band_round_trips_through_the_homoglyph_framed_path() {
        // Homoglyph is the carrier F0/F2 fixed by framing; the in-band binding
        // routes through the same pipeline, so it round-trips here too. Homoglyph
        // is cover-bounded, so a whole signed claim needs a Latin cover with the
        // positions to hold it.
        let hg = crate::stego::Homoglyph::new();
        let cover =
            "The quick brown fox jumps over a lazy dog while a copy escapes precisely today. "
                .repeat(200);
        let signed = signed_over(&cover);
        let binding = InBandBinding::new(&hg);

        let out = binding.bind(&cover, &signed).unwrap();
        let document = String::from_utf8(out.bytes).unwrap();
        assert_ne!(document, cover, "the claim must actually be carried");

        let back = binding
            .read(&BindInput {
                document: &document,
                sidecar: None,
            })
            .unwrap()
            .expect("the homoglyph document carries a claim");
        assert_eq!(back, signed);
    }

    #[test]
    fn in_band_refuses_a_cover_too_small_by_named_arithmetic() {
        // Homoglyph is cover-bounded, so a cover with too few positions to hold
        // the framed claim raises CapacityExceeded rather than truncating.
        let hg = crate::stego::Homoglyph::new();
        let signed = signed_over(IN_BAND_COVER);
        let binding = InBandBinding::new(&hg);

        match binding.bind("ok thanks", &signed) {
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
    fn in_band_realised_robustness_is_best_effort_and_measured() {
        let zw = crate::stego::ZeroWidth::new();
        let signed = signed_over(IN_BAND_COVER);
        let binding = InBandBinding::new(&zw);
        let document = String::from_utf8(binding.bind(IN_BAND_COVER, &signed).unwrap().bytes).unwrap();

        let realised = binding.realised_robustness(&document);
        assert_eq!(realised.class, RobustnessClass::BestEffort);
        // The note carries the analyser's own verdict on the produced document,
        // so it is measured rather than assumed.
        let expected_verdict = crate::forensic::analyze(&document).verdict.to_string();
        assert!(
            realised.note.contains(&expected_verdict),
            "the note must carry the measured forensic verdict, got: {}",
            realised.note
        );
    }
}
