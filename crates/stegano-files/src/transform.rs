//! Transform: tie document extraction to the frozen core's operations and write
//! the result back in the document's own format.
//!
//! This module wires three operations to real files:
//!
//! - **Inspect** (read-only): run [`stegano_core::sovereignty::inspect`] on a
//!   document's extracted text. Supported for every readable format.
//! - **Clean** (removal): run the chosen mark-class removals and write the
//!   cleaned document back in the SAME format, losslessly.
//! - **Conceal** (embedding): place a secret into a document's extracted text
//!   through the frozen core's compose path (the same path the desktop `compose`
//!   command and the CLI `encode` drive), then write the marked document back.
//!   Text-native formats conceal; containers and HTML are refused by name (see
//!   [`conceal_file`]). No placement, carrier or cipher logic is reimplemented
//!   here: this layer only wraps [`stegano_core::pipeline::encode_for_mission`].
//!
//! Losslessness is the bar, and where it cannot be proven the combination is
//! refused BY NAME (invariant 2, no silent degradation):
//!
//! - **Text-native (Markdown, plain text):** the extracted text is the document,
//!   so the cleaned text re-encoded in the original encoding is the new file. The
//!   write is proven by re-extracting the written bytes and requiring the cleaned
//!   text back; an encoding whose re-encoding would not round-trip is refused.
//! - **Office containers (DOCX, ODT):** a surgical in-place rewrite strips the
//!   chosen invisible channel characters from each XML text node and repackages
//!   the ZIP with every other entry byte-identical. The invisible classes are
//!   position-independent deletions, so a per-node strip equals a whole-document
//!   strip exactly. The homoglyph class reverts context-dependent look-alike
//!   substitutions whose per-node reversal is not proven equal across run
//!   boundaries, so cleaning it in a container is refused by name.
//! - **HTML:** a surgical, provably lossless text-node rewrite of arbitrary HTML
//!   is out of reach this slice (HTML is not well-formed XML), so HTML clean is
//!   refused by name. Inspect (read-only) is supported.

use std::path::Path;

use stegano_core::format::Mission;
use stegano_core::pipeline;
use stegano_core::sovereignty::{self, ClassRemoval, InspectionReport, MarkClass};
use stegano_core::traits::{CryptoMethod, StegoMethod};

use crate::writeback;
use crate::{extract_text, extract_text_from_path, Container, FileFormat, FilesError};

/// An error from a transform (inspect or clean) over a real document.
#[derive(Debug, thiserror::Error)]
pub enum TransformError {
    /// The underlying file layer could not read the document. Names itself.
    #[error(transparent)]
    Files(#[from] FilesError),

    /// The frozen core refused the operation and named itself: an empty secret,
    /// a capacity shortfall past the Conceal density ceiling, or an unsound
    /// carrier composition all surface here unchanged (invariant 2).
    #[error(transparent)]
    Core(#[from] stegano_core::SteganoError),

    /// Concealing into this format is not solved in this build. Refused by name
    /// rather than approximated with a silent partial (invariant 2): a container
    /// or HTML conceal needs the globally placed marked text redistributed back
    /// across the document's individual runs or nodes, which is not the per-node
    /// strip that clean performs.
    #[error("concealing a secret into a {format} document is not supported in this build: {reason}")]
    UnsupportedConceal { format: &'static str, reason: String },

    /// A confidentiality layer was selected but no passphrase was given. The core
    /// treats an empty passphrase as "no cipher", so applying it silently would
    /// let a secret the operator asked to encrypt travel in the clear. Refused by
    /// name rather than degraded silently (invariant 2).
    #[error("the '{cipher}' cipher was selected but no passphrase was given; a conceal that was asked to encrypt is refused rather than left in the clear")]
    MissingPassphrase { cipher: String },

    /// A (format, operation, class) combination whose lossless write-back this
    /// slice cannot prove. Refused by name rather than approximated (invariant 2).
    #[error("{operation} of {class} in a {format} document is not supported losslessly in this build: {reason}")]
    UnsupportedCombination {
        operation: &'static str,
        class: String,
        format: &'static str,
        reason: String,
    },

    /// The source text encoding cannot be re-encoded losslessly for write-back.
    #[error("cannot write back a {encoding} text document losslessly: {reason}")]
    UnsupportedEncoding { encoding: String, reason: String },

    /// Write-back produced bytes that do not round-trip back to the cleaned
    /// text. Raised rather than ship a document that would not re-extract cleanly.
    #[error("{format} write-back did not round-trip losslessly: {reason}")]
    WriteBackNotLossless { format: &'static str, reason: String },

    /// The surgical container rewrite or the ZIP repackage failed.
    #[error("{format} write-back failed: {reason}")]
    WriteBack { format: &'static str, reason: String },

    /// A file-level metadata strip refused itself and named the format: a format
    /// with no strippable metadata container, or a carrier the strip could not
    /// parse. Surfaced unchanged (invariant 2).
    #[error(transparent)]
    Strip(#[from] crate::strip::StripError),
}

/// The outcome of a clean over a real document.
#[derive(Debug, Clone)]
pub struct CleanOutcome {
    /// The source format, unchanged by the clean.
    pub format: FileFormat,
    /// The written-back document bytes, in the same format as the input.
    pub bytes: Vec<u8>,
    /// The document's text after the clean, obtained by RE-EXTRACTING `bytes`
    /// rather than by predicting it, so it reflects exactly what a reader gets
    /// back from the written file.
    pub cleaned_text: String,
    /// Per requested class: how many marks were removed from the extracted text.
    pub removed: Vec<ClassRemoval>,
    /// True when the write-back changed the document bytes.
    pub altered: bool,
    /// The honest limits of a native clean, surfaced from the core unchanged.
    pub residual: Vec<String>,
}

/// The outcome of a file-level metadata strip: native metadata AND our own
/// channel removed, with the document's readable CONTENT left byte-identical.
#[derive(Debug, Clone)]
pub struct StripOutcome {
    /// The source format, unchanged by the strip.
    pub format: FileFormat,
    /// The stripped document bytes, in the same format as the input.
    pub bytes: Vec<u8>,
    /// True when the strip changed the document bytes (metadata was present).
    pub altered: bool,
    /// True by construction: a strip removes only metadata surfaces and our
    /// channel, never the readable content, so the content is byte-identical.
    pub content_identical: bool,
}

/// The outcome of a file-level pristine clean: every mark class removed AND every
/// remaining invisible or format-control character removed, so the document text
/// re-analyses fully clean. Meaning-bearing invisibles (an emoji joiner, an RTL
/// run, an Indic or Arabic joiner) are removed too, so this is a DECLARED opt-in
/// and the trade-off is named in [`PristineOutcome::notes`] (invariant 2).
#[derive(Debug, Clone)]
pub struct PristineOutcome {
    /// The source format, unchanged by the clean.
    pub format: FileFormat,
    /// The written-back document bytes, in the same format as the input.
    pub bytes: Vec<u8>,
    /// The document's text after the pristine clean, obtained by RE-EXTRACTING
    /// `bytes` rather than by predicting it.
    pub cleaned_text: String,
    /// True when the pristine clean changed the document bytes.
    pub altered: bool,
    /// Per mark class: what the conservative clean removed first.
    pub class_removed: Vec<ClassRemoval>,
    /// Invisible or format-control characters removed BEYOND the mark classes,
    /// including any that are meaning-bearing.
    pub invisibles_removed: usize,
    /// The honest caveat and what was removed, surfaced from the core unchanged.
    pub notes: Vec<String>,
}

/// The outcome of a conceal over a real document.
#[derive(Debug, Clone)]
pub struct ConcealOutcome {
    /// The source format, unchanged by the conceal.
    pub format: FileFormat,
    /// The marked document bytes, in the same format as the input. These are the
    /// core's actual compose output, re-encoded in the document's own encoding;
    /// nothing is predicted or truncated (invariant 2).
    pub bytes: Vec<u8>,
    /// The document's text after the conceal, obtained by RE-EXTRACTING `bytes`
    /// rather than by predicting it, so it reflects exactly what a reader gets
    /// back from the written file.
    pub marked_text: String,
    /// The carriers the core applied, in application order, taken from the core's
    /// own [`stegano_core::EncodeResult::methods_used`], never a predicted list.
    pub carriers: Vec<String>,
    /// The confidentiality layer applied, or `None` when the secret travelled in
    /// the clear. Named from the selection that was actually used.
    pub cipher: Option<String>,
    /// Bytes of the secret concealed, measured from the input.
    pub secret_len: usize,
    /// Bytes of the source document, measured from the input.
    pub source_len: usize,
    /// Bytes of the marked document, measured from `bytes`.
    pub marked_len: usize,
}

/// Inspect a document's extracted text. Read-only, every readable format.
pub fn inspect_file(bytes: &[u8], format: FileFormat) -> Result<InspectionReport, TransformError> {
    let extracted = extract_text(bytes, format)?;
    Ok(sovereignty::inspect(&extracted.text))
}

/// Inspect a document on disk, inferring its format from the path extension.
pub fn inspect_path(path: &Path) -> Result<InspectionReport, TransformError> {
    let extracted = extract_text_from_path(path)?;
    Ok(sovereignty::inspect(&extracted.text))
}

/// Clean the chosen mark classes from a document and return the written-back
/// bytes, in the same format as the input.
///
/// An unsupported (format, class) combination is refused by name; a plain
/// document with nothing to remove is returned byte-for-byte unchanged.
pub fn clean_file(
    bytes: &[u8],
    format: FileFormat,
    classes: &[MarkClass],
) -> Result<CleanOutcome, TransformError> {
    let extracted = extract_text(bytes, format)?;
    match &extracted.container {
        Container::Source => clean_text_native(bytes, format, &extracted.text, classes),
        Container::OfficeZip { archive, entry, xml } => {
            clean_office(format, archive, entry, xml, &extracted.text, classes)
        }
        Container::Markup { .. } => Err(TransformError::UnsupportedCombination {
            operation: "clean",
            class: "any mark class".to_string(),
            format: format_display(format),
            reason: "arbitrary HTML is not well-formed XML, so a surgical text-node \
                     rewrite cannot be proven lossless in this build; inspect \
                     (read-only) is supported"
                .to_string(),
        }),
        Container::Lowered => Err(TransformError::UnsupportedCombination {
            operation: "clean",
            class: "any mark class".to_string(),
            format: format_display(format),
            reason: "extraction lowers this format to a best-effort Markdown rendering, not \
                     the source, so a lossless write-back in the original format is not solved \
                     in this build; inspect (read-only) is supported"
                .to_string(),
        }),
    }
}

/// Clean a document on disk in place, writing the cleaned bytes back to the same
/// path when the clean changed anything.
pub fn clean_path(path: &Path, classes: &[MarkClass]) -> Result<CleanOutcome, TransformError> {
    let format = FileFormat::from_path(path)?;
    let bytes = std::fs::read(path).map_err(|source| FilesError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let outcome = clean_file(&bytes, format, classes)?;
    if outcome.altered {
        std::fs::write(path, &outcome.bytes).map_err(|source| FilesError::Io {
            path: path.display().to_string(),
            source,
        })?;
    }
    Ok(outcome)
}

// ── Strip (metadata removal, content byte-identical) ─────────────────────────

/// Strip a document's metadata (native metadata and our own channel) at the file
/// level, leaving the readable CONTENT byte-identical, and return the stripped
/// bytes in the same format.
///
/// Delegates to [`crate::strip_metadata`], which supports the container and image
/// formats that carry a separate metadata surface (DOCX, ODT, PNG, SVG, JPEG). A
/// text-native format carries no strippable metadata container and is refused BY
/// NAME rather than returned unchanged (invariant 2).
pub fn strip_file(bytes: &[u8], format: FileFormat) -> Result<StripOutcome, TransformError> {
    let stripped = crate::strip_metadata(bytes, format)?;
    let altered = stripped.as_slice() != bytes;
    Ok(StripOutcome {
        format,
        altered,
        content_identical: true,
        bytes: stripped,
    })
}

/// Strip a document's metadata on disk in place, writing the stripped bytes back
/// to the same path when the strip changed anything.
pub fn strip_path(path: &Path) -> Result<StripOutcome, TransformError> {
    let format = FileFormat::from_path(path)?;
    let bytes = std::fs::read(path).map_err(|source| FilesError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let outcome = strip_file(&bytes, format)?;
    if outcome.altered {
        std::fs::write(path, &outcome.bytes).map_err(|source| FilesError::Io {
            path: path.display().to_string(),
            source,
        })?;
    }
    Ok(outcome)
}

// ── Pristine (clean every mark class AND every remaining invisible) ───────────

/// Pristine-clean a document and return the written-back bytes in the same format.
///
/// Text-native formats (Markdown, plain text) are pristine-cleaned in full: the
/// extracted text IS the document, so the core's pristine clean runs on it and the
/// cleaned text, re-encoded in the document's own encoding, is the new file. The
/// write is proven by re-extracting the written bytes and requiring the cleaned
/// text back.
///
/// A container (DOCX, ODT), markup (HTML) or lowered format is refused BY NAME. A
/// guaranteed-pristine write-back of those (the text re-analyses fully clean) needs
/// a surgical strip of every orphan invisible from each text node, which is not the
/// per-node mark-class strip that [`clean_file`] performs and is not solved in this
/// build; strip the metadata ([`strip_file`]) and clean every mark class
/// ([`clean_file`] with all classes) as the best-effort pair instead (invariant 2:
/// named, never a silent partial).
pub fn pristine_file(bytes: &[u8], format: FileFormat) -> Result<PristineOutcome, TransformError> {
    let extracted = extract_text(bytes, format)?;
    match &extracted.container {
        Container::Source => pristine_text_native(bytes, format, &extracted.text),
        Container::OfficeZip { .. } | Container::Markup { .. } | Container::Lowered => {
            Err(TransformError::UnsupportedCombination {
                operation: "pristine clean",
                class: "orphan invisibles".to_string(),
                format: format_display(format),
                reason: "a guaranteed-pristine write-back (the text re-analyses fully clean) \
                         needs a surgical strip of every orphan invisible from each text node, \
                         which is not the per-node mark-class strip that clean performs and is \
                         not solved in this build; strip the metadata and clean every mark class \
                         as the best-effort pair instead"
                    .to_string(),
            })
        }
    }
}

/// Pristine-clean a document on disk in place, writing the cleaned bytes back to
/// the same path when the clean changed anything.
pub fn pristine_path(path: &Path) -> Result<PristineOutcome, TransformError> {
    let format = FileFormat::from_path(path)?;
    let bytes = std::fs::read(path).map_err(|source| FilesError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let outcome = pristine_file(&bytes, format)?;
    if outcome.altered {
        std::fs::write(path, &outcome.bytes).map_err(|source| FilesError::Io {
            path: path.display().to_string(),
            source,
        })?;
    }
    Ok(outcome)
}

/// Pristine-clean a text-native document: run the core's pristine clean on the
/// extracted text (which IS the document), re-encode in the source encoding, and
/// prove the round-trip.
fn pristine_text_native(
    original: &[u8],
    format: FileFormat,
    text: &str,
) -> Result<PristineOutcome, TransformError> {
    let report = sovereignty::pristine_clean(text);

    if !report.altered {
        // Nothing to remove: return the input untouched, byte-for-byte.
        return Ok(PristineOutcome {
            format,
            bytes: original.to_vec(),
            cleaned_text: text.to_string(),
            altered: false,
            class_removed: report.class_removed,
            invisibles_removed: report.invisibles_removed,
            notes: report.notes,
        });
    }

    let encoding = writeback::detect_text_encoding(original);
    let out_bytes = writeback::encode_text(&report.cleaned_text, encoding).ok_or_else(|| {
        TransformError::UnsupportedEncoding {
            encoding: writeback::encoding_label(encoding).to_string(),
            reason: "re-encoding pristine-cleaned Unicode text to this legacy encoding cannot \
                     be guaranteed lossless; the file is refused rather than degraded"
                .to_string(),
        }
    })?;

    // Prove the round-trip: re-extract the written bytes and require the pristine
    // text back, so the clean survived the document's own encoding.
    let roundtrip = extract_text(&out_bytes, format)?;
    if roundtrip.text != report.cleaned_text {
        return Err(TransformError::WriteBackNotLossless {
            format: format_display(format),
            reason: "re-extraction of the written file did not reproduce the pristine text"
                .to_string(),
        });
    }

    Ok(PristineOutcome {
        format,
        altered: out_bytes.as_slice() != original,
        cleaned_text: roundtrip.text,
        class_removed: report.class_removed,
        invisibles_removed: report.invisibles_removed,
        notes: report.notes,
        bytes: out_bytes,
    })
}

// ── Conceal (embedding) ──────────────────────────────────────────────────────

/// Conceal a secret inside a document's extracted text and return the marked
/// document bytes, in the same format as the input.
///
/// Text-native formats (Markdown, plain text) conceal: the extracted text IS the
/// document, so the secret is placed into it through the frozen core's compose
/// path and the marked text, re-encoded in the document's own encoding, is the
/// new file. Placement protects code and math regions in the core, so a marked
/// Markdown file keeps its fenced blocks and equations byte-identical (invariant
/// 4b), proven by test.
///
/// Concealing into a container (DOCX, ODT) or HTML is refused BY NAME. It needs
/// the globally placed marked text redistributed back across the document's
/// individual runs or nodes, which is not the per-node strip that [`clean_file`]
/// performs and is not solved in this build; a silent partial is worse than a
/// named refusal (invariant 2).
///
/// The carrier and cipher selection are the core's own trait objects, so no
/// registry is duplicated here. The named refusals are: a cipher selected with an
/// empty passphrase ([`TransformError::MissingPassphrase`]); and, surfaced
/// straight from the core, an empty secret, a secret too large for the cover
/// under the Conceal density ceiling, and an unsound carrier composition
/// ([`TransformError::Core`]).
///
/// The conceal runs under [`Mission::Conceal`], so the core refuses to write past
/// the concealment density ceiling with named arithmetic rather than overflowing
/// the cover (invariant 4b is the product for this operation).
pub fn conceal_file(
    bytes: &[u8],
    format: FileFormat,
    secret: &str,
    carriers: &[&dyn StegoMethod],
    cipher: Option<(&dyn CryptoMethod, &str)>,
    saturate: bool,
) -> Result<ConcealOutcome, TransformError> {
    // A cipher chosen with no passphrase would silently travel in the clear
    // through the core (there an empty password means "no cipher"). For a conceal
    // the operator explicitly asked to encrypt, so refuse by name rather than
    // degrade silently (invariant 2).
    if let Some((method, passphrase)) = cipher {
        if passphrase.is_empty() {
            return Err(TransformError::MissingPassphrase {
                cipher: method.id().to_string(),
            });
        }
    }

    let extracted = extract_text(bytes, format)?;
    match &extracted.container {
        Container::Source => {
            conceal_text_native(bytes, format, &extracted.text, secret, carriers, cipher, saturate)
        }
        Container::OfficeZip { .. } => Err(TransformError::UnsupportedConceal {
            format: format_display(format),
            reason: "concealing into a container needs the globally placed marked text \
                     redistributed back across the document's individual text runs, which is not \
                     the per-node strip that clean performs and is not solved in this build"
                .to_string(),
        }),
        Container::Markup { .. } => Err(TransformError::UnsupportedConceal {
            format: format_display(format),
            reason: "concealing into HTML needs the globally placed marked text redistributed \
                     back across the document's individual nodes, and arbitrary HTML is not \
                     well-formed XML, so it is not solved in this build"
                .to_string(),
        }),
        Container::Lowered => Err(TransformError::UnsupportedConceal {
            format: format_display(format),
            reason: "extraction lowers this format to a best-effort Markdown rendering, not the \
                     source, so there is no faithful way to write a marked document back in the \
                     original format in this build"
                .to_string(),
        }),
    }
}

/// Conceal a secret into a document on disk in place, writing the marked bytes
/// back to the same path.
///
/// A conceal always alters the document (it adds a hidden secret), so on success
/// the write always happens; there is no unchanged-input branch as [`clean_path`]
/// has.
pub fn conceal_path(
    path: &Path,
    secret: &str,
    carriers: &[&dyn StegoMethod],
    cipher: Option<(&dyn CryptoMethod, &str)>,
    saturate: bool,
) -> Result<ConcealOutcome, TransformError> {
    let format = FileFormat::from_path(path)?;
    let bytes = std::fs::read(path).map_err(|source| FilesError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let outcome = conceal_file(&bytes, format, secret, carriers, cipher, saturate)?;
    std::fs::write(path, &outcome.bytes).map_err(|source| FilesError::Io {
        path: path.display().to_string(),
        source,
    })?;
    Ok(outcome)
}

/// Conceal into a text-native document: place the secret into the extracted text
/// through the core, re-encode in the source encoding, and prove the round-trip.
fn conceal_text_native(
    original: &[u8],
    format: FileFormat,
    cover_text: &str,
    secret: &str,
    carriers: &[&dyn StegoMethod],
    cipher: Option<(&dyn CryptoMethod, &str)>,
    saturate: bool,
) -> Result<ConcealOutcome, TransformError> {
    // Wrap the frozen core's compose path. No placement, carrier or cipher logic
    // is reimplemented. In the normal path the secret is placed under the Conceal
    // mission, gated against the density ceiling (invariant 4b), and a secret too
    // large surfaces the core's named CapacityExceeded. In the saturation path the
    // channel is filled with the secret repeated (SATURATE), the aggressive
    // declared variant, which does not apply the density gate.
    let encoded = if saturate {
        pipeline::encode_saturated(cover_text, secret.as_bytes(), carriers, cipher)?
    } else {
        pipeline::encode_for_mission(
            cover_text,
            secret.as_bytes(),
            carriers,
            cipher,
            Some(Mission::Conceal),
        )?
    };
    let marked_text = encoded.stego_text;

    // Re-encode in the document's own encoding, preserving its BOM, exactly as
    // clean does. A legacy target whose re-encoding is not lossless is refused by
    // name rather than degraded.
    let encoding = writeback::detect_text_encoding(original);
    let out_bytes = writeback::encode_text(&marked_text, encoding).ok_or_else(|| {
        TransformError::UnsupportedEncoding {
            encoding: writeback::encoding_label(encoding).to_string(),
            reason: "re-encoding the marked Unicode text to this legacy encoding cannot be \
                     guaranteed lossless; the file is refused rather than degraded"
                .to_string(),
        }
    })?;

    // Prove the round-trip: re-extract the written bytes and require the marked
    // text back, so the concealed channel survived the document's own encoding.
    let roundtrip = extract_text(&out_bytes, format)?;
    if roundtrip.text != marked_text {
        return Err(TransformError::WriteBackNotLossless {
            format: format_display(format),
            reason: "re-extraction of the written file did not reproduce the marked text"
                .to_string(),
        });
    }

    let cipher = cipher.map(|(method, _)| method.id().to_string());
    Ok(ConcealOutcome {
        format,
        marked_len: out_bytes.len(),
        source_len: original.len(),
        secret_len: secret.len(),
        bytes: out_bytes,
        marked_text: roundtrip.text,
        carriers: encoded.methods_used,
        cipher,
    })
}

// ── Text-native (Markdown, plain text) ───────────────────────────────────────

fn clean_text_native(
    original: &[u8],
    format: FileFormat,
    text: &str,
    classes: &[MarkClass],
) -> Result<CleanOutcome, TransformError> {
    // The extracted text IS the document for these formats, so the whole-text
    // clean is the removal, and re-encoding it is the new file.
    let report = sovereignty::clean(text, classes);

    if !report.altered {
        // Nothing to remove: return the input untouched, byte-for-byte.
        return Ok(CleanOutcome {
            format,
            bytes: original.to_vec(),
            cleaned_text: text.to_string(),
            removed: report.removed,
            altered: false,
            residual: report.residual,
        });
    }

    let encoding = writeback::detect_text_encoding(original);
    let out_bytes = writeback::encode_text(&report.cleaned_text, encoding).ok_or_else(|| {
        TransformError::UnsupportedEncoding {
            encoding: writeback::encoding_label(encoding).to_string(),
            reason: "re-encoding cleaned Unicode text to this legacy encoding cannot be \
                     guaranteed lossless; the file is refused rather than degraded"
                .to_string(),
        }
    })?;

    // Prove the round-trip: re-extract the written bytes and require the cleaned
    // text back. This catches any case where encoding normalisation (BOM
    // handling, mojibake repair) would alter the cleaned text on re-read.
    let roundtrip = extract_text(&out_bytes, format)?;
    if roundtrip.text != report.cleaned_text {
        return Err(TransformError::WriteBackNotLossless {
            format: format_display(format),
            reason: "re-extraction of the written file did not reproduce the cleaned text"
                .to_string(),
        });
    }

    Ok(CleanOutcome {
        format,
        bytes: out_bytes,
        cleaned_text: roundtrip.text,
        removed: report.removed,
        altered: true,
        residual: report.residual,
    })
}

// ── Office containers (DOCX, ODT) ────────────────────────────────────────────

fn clean_office(
    format: FileFormat,
    archive: &[u8],
    entry: &str,
    xml: &str,
    extracted_text: &str,
    classes: &[MarkClass],
) -> Result<CleanOutcome, TransformError> {
    // The homoglyph class reverts context-dependent substitutions; a per-node
    // reversal across run boundaries is not proven equal to a whole-document
    // reversal, so it is refused by name for containers this slice.
    if classes.contains(&MarkClass::Homoglyph) {
        return Err(TransformError::UnsupportedCombination {
            operation: "clean",
            class: MarkClass::Homoglyph.label().to_string(),
            format: format_display(format),
            reason: "reverting look-alike substitutions needs surrounding context, so a \
                     per-text-node reversal across run boundaries is not proven equal to a \
                     whole-document reversal"
                .to_string(),
        });
    }

    // Only the invisible classes reach the surgical strip. They are the classes
    // whose per-node deletion equals a whole-document deletion exactly.
    let invisible: Vec<MarkClass> = classes
        .iter()
        .copied()
        .filter(|class| *class != MarkClass::Homoglyph)
        .collect();

    // Report counts come from the extracted text, so they match what inspect
    // reported for the same document.
    let report = sovereignty::clean(extracted_text, &invisible);

    // Surgical strip: reuse the core's own removal on each text node's raw
    // slice. Because the invisible carriers delete their channel characters
    // independent of neighbours, stripping node by node equals stripping the
    // whole document. Entity references pass through untouched (they are ASCII).
    let new_xml = writeback::rewrite_text_nodes(xml, |raw| {
        sovereignty::clean(raw, &invisible).cleaned_text
    })
    .map_err(|reason| TransformError::WriteBack {
        format: format_display(format),
        reason,
    })?;

    if new_xml == *xml {
        // Nothing changed in the content part: return the archive untouched.
        return Ok(CleanOutcome {
            format,
            bytes: archive.to_vec(),
            cleaned_text: extracted_text.to_string(),
            removed: report.removed,
            altered: false,
            residual: report.residual,
        });
    }

    let out_bytes = writeback::repackage_zip(archive, entry, &new_xml).map_err(|reason| {
        TransformError::WriteBack {
            format: format_display(format),
            reason,
        }
    })?;

    // Prove removal: re-extract and require no residual marks of the cleaned
    // classes. If a channel character of a cleaned class survived, refuse rather
    // than report a clean that did not hold.
    let roundtrip = extract_text(&out_bytes, format)?;
    if sovereignty::clean(&roundtrip.text, &invisible).altered {
        return Err(TransformError::WriteBackNotLossless {
            format: format_display(format),
            reason: "the surgical rewrite left channel characters of a cleaned class in the \
                     document"
                .to_string(),
        });
    }

    Ok(CleanOutcome {
        format,
        bytes: out_bytes,
        cleaned_text: roundtrip.text,
        removed: report.removed,
        altered: true,
        residual: report.residual,
    })
}

/// A stable, capitalised display name for a format, for error messages.
fn format_display(format: FileFormat) -> &'static str {
    match format {
        FileFormat::Docx => "DOCX",
        FileFormat::Odt => "ODT",
        FileFormat::Pptx => "PPTX",
        FileFormat::Epub => "EPUB",
        FileFormat::Html => "HTML",
        FileFormat::Markdown => "Markdown",
        FileFormat::Rtf => "RTF",
        FileFormat::Latex => "LaTeX",
        FileFormat::Org => "Org",
        FileFormat::Rst => "reStructuredText",
        FileFormat::Wiki => "MediaWiki",
        FileFormat::AsciiDoc => "AsciiDoc",
        FileFormat::Typst => "Typst",
        FileFormat::Ipynb => "Jupyter",
        FileFormat::Bibtex => "BibTeX",
        FileFormat::Fb2 => "FictionBook",
        FileFormat::Eml => "email",
        FileFormat::Csv => "CSV",
        FileFormat::Code(_) => "source code",
        FileFormat::PlainText => "plain-text",
        FileFormat::Png => "PNG",
        FileFormat::Svg => "SVG",
        FileFormat::Jpeg => "JPEG",
        FileFormat::Tiff => "TIFF",
        FileFormat::Webp => "WebP",
        FileFormat::Pdf => "PDF",
    }
}
