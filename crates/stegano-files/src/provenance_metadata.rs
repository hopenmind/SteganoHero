//! # Format-metadata provenance route (the third binding, by composition)
//!
//! This module binds a signed provenance claim into a document's OWN metadata
//! channel and verifies it back. Functionally it is the third binding from
//! VISION Phase C, the `format_metadata` binding named in `SPEC_PROVENANCE.md`
//! (declared robustness `FormatBound`). It is implemented HERE as a COMPOSITION
//! of two existing, proven pieces, NOT as a `provenance::Binding` trait impl,
//! and it does not pretend to be one.
//!
//! ## Why composition, not a `Binding` impl
//!
//! The core `provenance::Binding` trait is text-oriented: it attaches a claim to
//! a `cover: &str` and reads it back from a `BindInput { document, sidecar }`.
//! The format-metadata route is byte-oriented: it writes into a file's binary
//! metadata surface (a DOCX ZIP entry) and leaves the document content
//! byte-for-byte unchanged. Forcing that shape into `bind(cover: &str)` would
//! break the trait's contract, since the product is a modified byte container,
//! not a marked string. So this route composes the pieces rather than lying
//! about the trait. A future bytes-capable binding trait could unify the two;
//! until then this is a documented composition, deliberately not a `Binding`.
//!
//! ## What it composes, verbatim (no new crypto, no new hashing)
//!
//! - [`stegano_core::provenance`] for the claim, the signature and the verify
//!   evaluation ([`ProvenanceClaim`], [`SignedClaim`], [`verify_with_policy`],
//!   [`TrustPolicy`]). The document hash is the core's
//!   `license::document_hash` over the document's extracted-and-stripped TEXT,
//!   taken by [`ProvenanceClaim::new`] at sign time and recomputed by the verify
//!   path at verify time, so an edit to the VISIBLE content is detected and
//!   named.
//! - [`crate::embed_metadata`] / [`crate::recover_metadata`] for the zero-loss
//!   metadata write and read (content byte-identical, already proven).
//!
//! The persisted payload is the neutral [`SignedClaim`] itself, so a third party
//! reading the metadata blob sees only a signed claim, not a false statement
//! about which binding produced it. The core's verify evaluation is reached
//! through the detached-binding sidecar as an in-memory adapter (never
//! persisted); the report is then relabelled to this route's true kind and true
//! `FormatBound` robustness, so it never overclaims survivability (invariant 2,
//! `SPEC_PROVENANCE.md` section 3).
//!
//! ## Served and refused formats (invariant 2: every refusal names the format)
//!
//! Served: the text-bearing formats whose [`crate::extract_text`] faithfully
//! yields the document to hash AND which carry a metadata channel. In this build
//! that is DOCX. A text-bearing format the metadata channel does not carry is
//! refused by name by the channel itself.
//!
//! Refused by name here: PNG and SVG. They DO carry a metadata channel, but
//! their "document" is image content, not text, so a text `document_hash` would
//! sign the wrong thing. Image-content provenance is a separate later slice.
//! Refusing is honest; faking a text hash for an image is not.

use stegano_core::provenance::{
    verify_with_policy, Assertion, Binding, DetachedBinding, ProvenanceClaim, ProvenanceReport,
    Robustness, RobustnessClass, SignedClaim, TrustPolicy,
};
use stegano_core::signing::MasterKeyPair;

use crate::{embed_metadata, extract_text, recover_metadata, FileFormat};

/// The stable binding kind this route reports, matching the `format_metadata`
/// binding named in `SPEC_PROVENANCE.md`.
pub const BINDING_KIND: &str = "format_metadata";

/// An error from the format-metadata provenance route. Every variant names the
/// format and the reason; no path silently succeeds, returns empty, or treats a
/// present-but-corrupt claim as absent (invariant 2).
#[derive(Debug, thiserror::Error)]
pub enum ProvenanceMetadataError {
    /// The format is not served by this text-provenance route. PNG and SVG land
    /// here BY NAME: they carry a metadata channel but no document TEXT, so a
    /// text document hash would sign the wrong thing.
    #[error("the {format} format is not served by the format-metadata provenance route: {reason}")]
    UnsupportedFormat {
        format: &'static str,
        reason: &'static str,
    },

    /// Text extraction for the document to hash failed, or the format carries no
    /// extractable text. Names the format through the file layer's own error.
    #[error(transparent)]
    Extraction(#[from] crate::FilesError),

    /// The metadata channel refused the format, or could not read or write it.
    /// Names the format through the channel's own error. A format with no
    /// metadata channel is refused here BY NAME.
    #[error(transparent)]
    Metadata(#[from] crate::MetadataError),

    /// A metadata channel was present but the bytes it held are not a readable
    /// signed provenance claim (corrupt or foreign payload). Present-but-invalid
    /// is named, never silently treated as absent (invariant 2). An ABSENT
    /// channel is NOT this error: it is reported absent in the report.
    #[error("the {format} metadata channel holds a payload that is not a readable signed provenance claim: {detail}")]
    UnreadableClaim { format: &'static str, detail: String },

    /// Serialising the signed claim to its metadata payload failed.
    #[error("could not serialise the signed provenance claim: {0}")]
    Serialization(String),

    /// The core signing or verify path raised. Names the stage and defers to the
    /// core error for the detail.
    #[error("provenance {stage} failed: {source}")]
    Core {
        stage: &'static str,
        #[source]
        source: stegano_core::SteganoError,
    },
}

/// Sign a provenance claim over `bytes` (a document of `format`) and write the
/// signed claim into the document's metadata channel, returning the new file
/// bytes with the document CONTENT byte-for-byte unchanged (additive, zero-loss).
///
/// The claim is built over the document's extracted-and-stripped TEXT via the
/// core's [`ProvenanceClaim::new`] (which hashes with `license::document_hash`)
/// and signed with the core's [`SignedClaim::sign`]. No crypto or hashing is
/// reimplemented here.
///
/// Served: DOCX (and any other text-bearing format the metadata channel carries).
/// PNG and SVG are refused by name (image content, not text). A format with no
/// metadata channel is refused by name.
pub fn sign_into_metadata(
    bytes: &[u8],
    format: FileFormat,
    keypair: &MasterKeyPair,
    assertions: &[&dyn Assertion],
    created: Option<String>,
) -> Result<Vec<u8>, ProvenanceMetadataError> {
    ensure_text_route(format)?;

    // The document to hash is the format's extracted visible text. Extraction
    // refuses a non-text format by name (invariant 2).
    let extracted = extract_text(bytes, format)?;

    // Build and sign the claim over that text. The document hash and the
    // signature are the core's, reused verbatim.
    let claim = ProvenanceClaim::new(assertions, &extracted.text, &keypair.public_key(), created)
        .map_err(|source| ProvenanceMetadataError::Core {
            stage: "claim assembly",
            source,
        })?;
    let signed = SignedClaim::sign(claim, keypair).map_err(|source| {
        ProvenanceMetadataError::Core {
            stage: "signing",
            source,
        }
    })?;

    // Serialise the SIGNED CLAIM itself: a neutral, self-contained record that
    // makes no false statement about which binding produced it. Write it into
    // the metadata channel, leaving the document content untouched.
    let payload = serde_json::to_vec(&signed)
        .map_err(|e| ProvenanceMetadataError::Serialization(e.to_string()))?;
    let out = embed_metadata(bytes, format, &payload)?;
    Ok(out)
}

/// Verify the provenance claim carried in `bytes`'s metadata channel under
/// `policy`, returning the core's [`ProvenanceReport`] relabelled to this route.
///
/// Recovers the signed claim from the metadata channel, deserialises it, and
/// runs the core's [`verify_with_policy`]: the signature check, the distinct-key
/// trust policy, and the document hash re-computed over the CURRENT extracted
/// text (so an edit to the visible content is reported altered, by name). An
/// ABSENT channel is reported absent (an empty report), never an error. A
/// present-but-corrupt payload is refused by name.
///
/// Served and refused formats are exactly as in [`sign_into_metadata`].
pub fn verify_from_metadata(
    bytes: &[u8],
    format: FileFormat,
    policy: &TrustPolicy,
) -> Result<ProvenanceReport, ProvenanceMetadataError> {
    ensure_text_route(format)?;

    // Recover the signed claim from the metadata channel. Absent is NOT an
    // error: it is an empty report, exactly how the core reports a binding that
    // carried nothing.
    let payload = match recover_metadata(bytes, format)? {
        None => return Ok(absent_report()),
        Some(payload) => payload,
    };

    // Deserialise the signed claim. A present-but-corrupt payload is named,
    // never silently treated as absent (invariant 2).
    let signed: SignedClaim = serde_json::from_slice(&payload).map_err(|e| {
        ProvenanceMetadataError::UnreadableClaim {
            format: format.name(),
            detail: e.to_string(),
        }
    })?;

    // Recompute the document hash over the CURRENT extracted text so an edit to
    // the visible content is detected. Extraction refuses a non-text format by
    // name.
    let extracted = extract_text(bytes, format)?;

    // Reuse the core verify evaluation verbatim: the signature, the distinct-key
    // trust policy and the document-hash re-computation all live in
    // `verify_with_policy`. The detached-binding sidecar is used purely as the
    // in-memory adapter that carries the recovered signed claim into that
    // evaluation; it is never persisted.
    let sidecar = DetachedBinding::new()
        .bind(&extracted.text, &signed)
        .map_err(|source| ProvenanceMetadataError::Core {
            stage: "verify adapter",
            source,
        })?
        .bytes;
    let mut report = verify_with_policy(&extracted.text, Some(&sidecar), policy).map_err(
        |source| ProvenanceMetadataError::Core {
            stage: "verify",
            source,
        },
    )?;

    // Relabel each evaluated claim to the TRUE route and its TRUE robustness.
    // The core ran the evaluation through the detached adapter, so it labelled
    // the claim "detached"/High; this route is `format_metadata`/FormatBound.
    // The crypto verdict (signature, hash, trust) is the core's, unchanged; only
    // the route metadata is corrected, so the report never overclaims
    // survivability (invariant 2, SPEC_PROVENANCE.md section 3).
    for claim in &mut report.claims {
        claim.binding = BINDING_KIND.to_string();
        claim.robustness_realised = format_metadata_robustness();
    }
    Ok(report)
}

/// Gate the route to text-bearing formats. PNG and SVG are refused BY NAME: they
/// carry a metadata channel but no document text, so a text document hash is
/// wrong for them. A channel-less text format passes here and is refused by name
/// downstream by the metadata channel itself.
fn ensure_text_route(format: FileFormat) -> Result<(), ProvenanceMetadataError> {
    match format {
        FileFormat::Png => Err(ProvenanceMetadataError::UnsupportedFormat {
            format: format.name(),
            reason: "a raster image carries image content, not document text; a text document \
                     hash would sign the wrong thing. Image-content provenance is a separate \
                     later slice",
        }),
        FileFormat::Svg => Err(ProvenanceMetadataError::UnsupportedFormat {
            format: format.name(),
            reason: "a vector image carries image content, not document text; a text document \
                     hash would sign the wrong thing. Image-content provenance is a separate \
                     later slice",
        }),
        _ => Ok(()),
    }
}

/// This route's true robustness: `FormatBound`, with an honest note on what it
/// survives and what strips it.
fn format_metadata_robustness() -> Robustness {
    Robustness {
        class: RobustnessClass::FormatBound,
        note: "format-metadata channel: the claim rides the file's own metadata surface; it \
               survives a copy or a re-save that preserves metadata, and is stripped by a \
               conversion that drops metadata"
            .to_string(),
    }
}

/// The report for a document whose metadata channel carried no claim: absent, not
/// failed. Mirrors the core's shape for a binding that read back nothing.
fn absent_report() -> ProvenanceReport {
    ProvenanceReport {
        claims: Vec::new(),
        strongest: None,
        unmet_requirements: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal, readable DOCX built in memory: a real word/document.xml the text
    // pipeline can extract. Mirrors the fixture builder in the metadata tests.
    fn docx_with_text(body: &str) -> Vec<u8> {
        use std::io::{Cursor, Write};
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

    #[test]
    fn absent_channel_reports_absent_not_an_error() {
        let docx = docx_with_text("a clean document with no claim");
        let report =
            verify_from_metadata(&docx, FileFormat::Docx, &TrustPolicy::default()).unwrap();
        assert!(report.claims.is_empty(), "a clean file must report absent");
        assert!(report.strongest.is_none());
    }

    #[test]
    fn png_and_svg_are_refused_by_name_on_sign_and_verify() {
        let kp = MasterKeyPair::generate();
        for (format, name) in [(FileFormat::Png, "png"), (FileFormat::Svg, "svg")] {
            let err = sign_into_metadata(b"whatever", format, &kp, &[], None).unwrap_err();
            match &err {
                ProvenanceMetadataError::UnsupportedFormat { format: f, .. } => assert_eq!(*f, name),
                other => panic!("expected UnsupportedFormat naming {name}, got {other:?}"),
            }
            assert!(err.to_string().contains(name));

            let err =
                verify_from_metadata(b"whatever", format, &TrustPolicy::default()).unwrap_err();
            assert!(matches!(
                err,
                ProvenanceMetadataError::UnsupportedFormat { .. }
            ));
        }
    }
}
