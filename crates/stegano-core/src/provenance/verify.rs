//! The verify path (SPEC_PROVENANCE.md section 4).
//!
//! Given a document, an optional detached sidecar, and a trust policy, verify
//! reports for each binding that carried a readable claim: whether the
//! signature is valid, whether the recomputed document hash matches (document
//! unaltered), the assertions, and the binding's realised robustness.
//!
//! The rules are strict, per invariant 2 and the spec: a claim whose signature
//! fails is present-but-invalid, never dropped; a document whose hash differs is
//! reported altered by name; a binding that carries nothing is absent, not
//! failed; undetermined is undetermined.

use crate::error::Result;
use crate::traits::StegoMethod;

use super::binding::{
    BindInput, Binding, DetachedBinding, InBandBinding, Robustness, RobustnessClass,
};
use super::{AssertionRecord, Assertion, PublicKeyRef, SignedClaim};

/// A requirement that a given assertion kind be signed by a specific key. This
/// is the distinct-key rule (SPEC_PROVENANCE.md section 5): an `ai_generated`
/// claim signed by a pipeline key is not accepted as human authorship when a
/// human key is required for `human_authorship`.
#[derive(Debug, Clone)]
pub struct KeyRequirement {
    /// The assertion kind this requirement governs.
    pub assertion_kind: String,
    /// The key that must have signed a claim for that kind to be accepted.
    pub required_signer: PublicKeyRef,
}

/// Which keys a verifier trusts, and which assertion kinds must be signed by a
/// specific key.
#[derive(Debug, Clone, Default)]
pub struct TrustPolicy {
    /// Keys the verifier trusts. A claim signed by a key outside this set is
    /// reported present, with `signer_trusted` false.
    pub trusted_keys: Vec<PublicKeyRef>,
    /// Per-kind signer requirements.
    pub requirements: Vec<KeyRequirement>,
}

impl TrustPolicy {
    /// A policy that trusts `trusted_keys` and imposes no per-kind requirement.
    pub fn new(trusted_keys: Vec<PublicKeyRef>) -> Self {
        Self {
            trusted_keys,
            requirements: Vec::new(),
        }
    }

    /// Require that `kind` be signed by `signer`. Builder-style.
    pub fn require(mut self, kind: &str, signer: &PublicKeyRef) -> Self {
        self.requirements.push(KeyRequirement {
            assertion_kind: kind.to_string(),
            required_signer: signer.clone(),
        });
        self
    }
}

/// One binding's readable claim, evaluated.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifiedClaim {
    /// The binding this claim arrived through ("detached").
    pub binding: String,
    /// The signature verifies under the claim's embedded signer key.
    pub signature_valid: bool,
    /// The embedded signer is among the policy's trusted keys.
    pub signer_trusted: bool,
    /// The recomputed document hash matches the signed one (document unaltered).
    pub document_unaltered: bool,
    /// The realised robustness, never higher than the binding delivered.
    pub robustness_realised: Robustness,
    /// The embedded signer key.
    pub signer: PublicKeyRef,
    /// The stable kinds of the assertions carried.
    pub assertion_kinds: Vec<String>,
    /// The assertions carried, in serialised form.
    pub assertions: Vec<AssertionRecord>,
    /// Named findings for a human reader, e.g. "document altered".
    pub findings: Vec<String>,
}

impl VerifiedClaim {
    /// True when an assertion of `kind` is present.
    pub fn has_kind(&self, kind: &str) -> bool {
        self.assertion_kinds.iter().any(|k| k == kind)
    }

    /// Whether this claim can be accepted as evidence for `kind` attributed to
    /// `required_signer`: the assertion is present, the document is unaltered,
    /// and `required_signer` actually signed the claim. This is the distinct-key
    /// gate: a pipeline-signed claim is not accepted for a human requirement.
    pub fn satisfies(&self, kind: &str, required_signer: &PublicKeyRef) -> bool {
        self.has_kind(kind)
            && self.document_unaltered
            && self.signature_valid
            && &self.signer == required_signer
    }

    /// Typed, rehydrated assertions. Raises on an unknown kind (invariant 2).
    pub fn typed_assertions(&self) -> Result<Vec<Box<dyn Assertion>>> {
        self.assertions
            .iter()
            .map(super::assertion_from_record)
            .collect()
    }
}

/// A policy requirement that no readable claim met, with the reason named.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UnmetRequirement {
    /// The assertion kind the requirement governs.
    pub assertion_kind: String,
    /// The signer the requirement demanded.
    pub required_signer: PublicKeyRef,
    /// Why no claim satisfied it, named.
    pub reason: String,
}

/// The verify report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProvenanceReport {
    /// One entry per binding that carried a readable claim.
    pub claims: Vec<VerifiedClaim>,
    /// Index into `claims` of the highest-robustness surviving, trusted, valid
    /// claim, if any.
    pub strongest: Option<usize>,
    /// Policy requirements no readable claim met.
    pub unmet_requirements: Vec<UnmetRequirement>,
}

/// Verify a document against an optional detached sidecar and a set of trusted
/// keys. Convenience over [`verify_with_policy`] with no per-kind requirements.
pub fn verify(
    document: &str,
    sidecar: Option<&[u8]>,
    keys: &[PublicKeyRef],
) -> Result<ProvenanceReport> {
    verify_with_policy(document, sidecar, &TrustPolicy::new(keys.to_vec()))
}

/// Verify a document against an optional detached sidecar and a trust policy.
///
/// Reads the detached binding only. In-band bindings need the carriers they
/// were placed through, so a caller that wants them read uses
/// [`verify_document`]; this convenience keeps the Phase A shape unchanged.
///
/// Raises only when a binding carries something unreadable (invariant 2). An
/// absent binding is absent; a present-but-invalid claim is reported.
pub fn verify_with_policy(
    document: &str,
    sidecar: Option<&[u8]>,
    policy: &TrustPolicy,
) -> Result<ProvenanceReport> {
    verify_bindings(document, sidecar, &[], policy)
}

/// Verify a document against a detached sidecar and any in-band bindings.
///
/// This is the Phase B reader (SPEC_PROVENANCE.md section 4). It reads the
/// detached sidecar exactly as [`verify_with_policy`] does, then reads each
/// carrier in `in_band_methods` for an in-band claim of its own. An in-band
/// claim's realised robustness is measured on the document by `forensic` and
/// `fidelity` ([`InBandBinding::realised_robustness`]), never taken from the
/// declaration, and never reported higher than the `BestEffort` an in-band mark
/// can deliver.
///
/// Passing no carriers reads only the detached binding, which is exactly
/// [`verify_with_policy`]. A carrier that holds no framed layer is absent, not
/// failed; a carrier that holds bytes which are not a readable signed claim
/// raises by name (invariant 2).
pub fn verify_document(
    document: &str,
    sidecar: Option<&[u8]>,
    in_band_methods: &[&dyn StegoMethod],
    policy: &TrustPolicy,
) -> Result<ProvenanceReport> {
    verify_bindings(document, sidecar, in_band_methods, policy)
}

/// The shared verify engine over every binding in play.
fn verify_bindings(
    document: &str,
    sidecar: Option<&[u8]>,
    in_band_methods: &[&dyn StegoMethod],
    policy: &TrustPolicy,
) -> Result<ProvenanceReport> {
    let mut claims = Vec::new();

    // Detached binding, the Phase A binding.
    let detached = DetachedBinding::new();
    let input = BindInput { document, sidecar };
    if let Some(signed) = detached.read(&input)? {
        claims.push(evaluate(
            &signed,
            document,
            detached.kind(),
            detached.declared_robustness(),
            policy,
        )?);
    }

    // In-band bindings, one per carrier offered. The realised robustness is
    // measured on the actual document, never the declaration (section 3).
    for method in in_band_methods {
        let binding = InBandBinding::new(*method);
        if let Some(signed) = binding.read(&input)? {
            let realised = binding.realised_robustness(document);
            claims.push(evaluate(
                &signed,
                document,
                binding.kind(),
                realised,
                policy,
            )?);
        }
    }

    let unmet = unmet_requirements(&claims, policy);
    let strongest = pick_strongest(&claims);

    Ok(ProvenanceReport {
        claims,
        strongest,
        unmet_requirements: unmet,
    })
}

/// Evaluate one readable claim. The realised robustness for a detached binding
/// that read back is what it declared: the claim survived and is in hand.
/// Robustness is about survival, not authenticity, so a tampered claim still
/// reports its true robustness alongside `signature_valid` false.
fn evaluate(
    signed: &SignedClaim,
    document: &str,
    binding: &str,
    declared: Robustness,
    policy: &TrustPolicy,
) -> Result<VerifiedClaim> {
    let signer = signed.claim.signer.clone();
    let signature_valid = signed.signature_valid();
    let signer_trusted = policy.trusted_keys.iter().any(|k| k == &signer);

    // Document binding, reusing the F12 mechanism unchanged.
    let recomputed = crate::license::document_hash(document)?;
    let document_unaltered = recomputed == signed.claim.document_hash;

    let assertion_kinds: Vec<String> = signed
        .claim
        .assertions
        .iter()
        .map(|a| a.kind.clone())
        .collect();

    let mut findings = Vec::new();
    if !signature_valid {
        findings.push(
            "signature invalid: this claim did not verify under the key it names".to_string(),
        );
    }
    if !document_unaltered {
        findings.push(format!(
            "document altered: it strips to {recomputed} but the claim was signed over {}",
            signed.claim.document_hash
        ));
    }
    if !signer_trusted {
        findings.push(
            "signer not trusted: the key that signed this claim is not in the trusted set"
                .to_string(),
        );
    }
    if findings.is_empty() {
        findings.push("claim verified: signature valid, document unaltered, signer trusted".to_string());
    }

    Ok(VerifiedClaim {
        binding: binding.to_string(),
        signature_valid,
        signer_trusted,
        document_unaltered,
        robustness_realised: declared,
        signer,
        assertion_kinds,
        assertions: signed.claim.assertions.clone(),
        findings,
    })
}

/// For each policy requirement, find whether any readable claim satisfies it.
/// When none does, name why: no such assertion, wrong signer, invalid signature,
/// or an altered document.
fn unmet_requirements(claims: &[VerifiedClaim], policy: &TrustPolicy) -> Vec<UnmetRequirement> {
    let mut unmet = Vec::new();
    for req in &policy.requirements {
        let satisfied = claims
            .iter()
            .any(|c| c.satisfies(&req.assertion_kind, &req.required_signer));
        if !satisfied {
            unmet.push(UnmetRequirement {
                assertion_kind: req.assertion_kind.clone(),
                required_signer: req.required_signer.clone(),
                reason: reason_unmet(claims, req),
            });
        }
    }
    unmet
}

/// Name why a requirement was not met.
fn reason_unmet(claims: &[VerifiedClaim], req: &KeyRequirement) -> String {
    let with_kind: Vec<&VerifiedClaim> = claims
        .iter()
        .filter(|c| c.has_kind(&req.assertion_kind))
        .collect();

    if with_kind.is_empty() {
        return format!(
            "no readable claim carries a '{}' assertion",
            req.assertion_kind
        );
    }
    // Report the first carrying claim's specific obstacle.
    let c = with_kind[0];
    if c.signer != req.required_signer {
        format!(
            "the '{}' assertion was signed by a different key than the required signer; \
             it is not accepted as that key's statement",
            req.assertion_kind
        )
    } else if !c.signature_valid {
        format!(
            "the '{}' assertion's signature does not verify",
            req.assertion_kind
        )
    } else if !c.document_unaltered {
        format!(
            "the document carrying the '{}' assertion has been altered since it was signed",
            req.assertion_kind
        )
    } else {
        format!("the '{}' requirement is unmet", req.assertion_kind)
    }
}

/// The highest-robustness surviving claim: present, signature valid, document
/// unaltered, signer trusted. `None` when no claim clears that bar.
fn pick_strongest(claims: &[VerifiedClaim]) -> Option<usize> {
    claims
        .iter()
        .enumerate()
        .filter(|(_, c)| c.signature_valid && c.document_unaltered && c.signer_trusted)
        .max_by_key(|(_, c)| robustness_rank(c.robustness_realised.class))
        .map(|(i, _)| i)
}

fn robustness_rank(class: RobustnessClass) -> u8 {
    match class {
        RobustnessClass::High => 3,
        RobustnessClass::BestEffort => 2,
        RobustnessClass::FormatBound => 1,
    }
}
