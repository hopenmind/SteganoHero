//! The command surface, and the one dispatcher both transports call.
//!
//! Every command here follows the same shape: read the arguments, refuse them
//! by name if they are not usable, call the core, and report what came back.
//! When a command can check its own result, it does, and it refuses rather
//! than hand back an output it could not confirm.
//!
//! No description in this file explains a mechanism. Identifiers accepted as
//! parameters come from [`crate::catalogue`] and are passed through untouched.
//!
//! Secrets, passcodes and private key material appear only in the arguments a
//! caller supplies and in the results a caller explicitly asked for. They are
//! never written into a reason, a warning or a log line.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use stegano_core::{
    c2pa_read,
    crypto,
    error::SteganoError,
    forensic,
    format::{self, frame, Envelope, Mission, PreambleSource},
    license, metrics, pipeline,
    sovereignty::{self, MarkClass},
    provenance::{
        verify_document, AiGenerated, Assertion, Binding, DetachedBinding, HumanAuthorship,
        InBandBinding, Integrity, ProvenanceClaim, PublicKeyRef, RecipientFingerprint, SignedClaim,
        TrustPolicy, KIND_AI_GENERATED, KIND_HUMAN_AUTHORSHIP, KIND_INTEGRITY,
        KIND_RECIPIENT_FINGERPRINT,
    },
    signing,
    traits::{CryptoMethod, StegoMethod},
    utils::{compression::Compression, file_embed::FileEmbed, text_clean::CleanOptions, text_clean::TextClean},
    watermark::fingerprint as canary,
};

// The file layer sits above the core: it reads a real document and ties its
// extracted text to the same frozen sovereignty operations the text tools use.
// This surface only wraps it; it reimplements no extraction, clean, conceal,
// convert or metadata-read logic.
use stegano_files::{
    clean_file, conceal_file, convert_file, export_text, extract_text, inspect_file, pristine_file,
    read_image_metadata, read_native_metadata, recover_metadata, strip_file, supported_targets,
    target_from_extension, FileFormat,
};

use crate::catalogue::{self, CIPHER_NONE};
use crate::settings::{FieldRejection, Settings};

// ─────────────────────────────────────────────────────────────
// Dispatcher types
// ─────────────────────────────────────────────────────────────

/// The result of running one command.
pub enum Outcome {
    /// The command ran and produced this payload.
    Done(Value),
    /// The command ran and refused, naming why.
    Refused { code: &'static str, reason: String },
    /// The arguments were not usable, naming why.
    BadArguments(String),
    /// No command by that name.
    Unknown(String),
}

impl Outcome {
    fn refused(code: &'static str, reason: impl Into<String>) -> Self {
        Outcome::Refused {
            code,
            reason: reason.into(),
        }
    }
}

/// The settings in force, and where they are kept.
///
/// A store without a path keeps its settings in memory only, which is what a
/// test uses. A store with a path writes an accepted update through before
/// reporting it, so a caller is never told a setting took effect that would
/// be gone at the next start.
pub struct SettingsStore {
    path: Option<std::path::PathBuf>,
    settings: Settings,
}

impl SettingsStore {
    /// A store held in memory only.
    pub fn in_memory(settings: Settings) -> Self {
        Self {
            path: None,
            settings,
        }
    }

    /// A store backed by a file. A missing file starts from the defaults.
    pub fn at(path: impl Into<std::path::PathBuf>) -> Result<Self, String> {
        let path = path.into();
        let settings = Settings::load(&path)?;
        Ok(Self {
            path: Some(path),
            settings,
        })
    }

    /// The settings in force.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Replace the settings in force, without validation. Used at start-up to
    /// install a generated token, never from the configuration zone.
    pub fn replace(&mut self, settings: Settings) -> Result<(), String> {
        if let Some(path) = &self.path {
            settings.save(path)?;
        }
        self.settings = settings;
        Ok(())
    }

    /// Apply a partial update. Nothing changes unless every field is accepted.
    pub fn apply(&mut self, update: &Value) -> Result<(), Vec<FieldRejection>> {
        let next = self.settings.with_update(update)?;
        if let Some(path) = &self.path {
            next.save(path).map_err(|reason| {
                vec![FieldRejection {
                    field: "(storage)".into(),
                    value: path.display().to_string(),
                    reason,
                }]
            })?;
        }
        self.settings = next;
        Ok(())
    }
}

/// One command, as advertised to a caller.
pub struct ToolSpec {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub schema: fn() -> Value,
}

// ─────────────────────────────────────────────────────────────
// The catalogue of commands
// ─────────────────────────────────────────────────────────────

/// Every command, in the order they are offered.
pub fn tool_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "capabilities_list",
            title: "List capabilities",
            description: "List everything this surface can do right now: the available carriers and confidentiality layers with their durability and exposure labels, the configured missions, and the full command list. Read from the live registry, so it never names something that is not there.",
            schema: schema_capabilities_list,
        },
        ToolSpec {
            name: "chain_validate",
            title: "Check a carrier selection",
            description: "Check that a selection of carriers can be combined, before any text is touched. Returns the selection in the order it would be applied, or refuses and says which pair is the problem.",
            schema: schema_chain_validate,
        },
        ToolSpec {
            name: "capacity_report",
            title: "Report capacity for a cover text",
            description: "Report how many bytes each carrier can actually place in a given cover text, before any attempt is made. The figure is the one the engine will accept: ask for that many bytes and it takes them, one more is refused. Capacity depends on the script and shape of the cover, so it is reported per carrier and every zero is explained.",
            schema: schema_capacity_report,
        },
        ToolSpec {
            name: "recommend_settings",
            title: "Recommend the best settings for a hide",
            description: "For a specific secret and cover, recommend the carrier, mission and density that hold the secret with the most margin and no overflow, preferring the most discreet setting that still fits. When nothing fits, it names the shortfall in bytes rather than a false figure. Every number is the one the engine enforces, so the recommendation can be applied as is or ignored.",
            schema: schema_recommend_settings,
        },
        ToolSpec {
            name: "conceal",
            title: "Place a secret in a cover text",
            description: "Place a secret inside a cover text using the named carriers, optionally under a confidentiality layer. The result is checked by recovering it again before it is handed back, and the command refuses rather than return a document whose content could not be recovered.",
            schema: schema_conceal,
        },
        ToolSpec {
            name: "reveal",
            title: "Recover a secret from a text",
            description: "Recover a secret placed in a text. Reports which carriers answered, which confidentiality layer was declared, and whether the recovered content matched its own integrity check. Refuses when the check fails, rather than returning content it cannot vouch for.",
            schema: schema_reveal,
        },
        ToolSpec {
            name: "roundtrip_check",
            title: "Test a plan against a cover text",
            description: "Run a full place-and-recover cycle for a given cover text and plan, and report every stage separately: selection, placement, recovery, and whether the recovered content matched. Use it to find out whether a plan works on a specific document before committing to it.",
            schema: schema_roundtrip_check,
        },
        ToolSpec {
            name: "inspect",
            title: "Inspect a text without opening it",
            description: "Report what a text appears to be carrying: a score per carrier, the format version of anything found, its declared confidentiality layer and its size. Nothing is decrypted and no passcode is asked for or used.",
            schema: schema_inspect,
        },
        ToolSpec {
            name: "analyze",
            title: "Full analysis report",
            description: "Produce the full analysis of a text: overall verdict, per-carrier findings, character-level anomalies, script mixing and statistics. This is the complete report, not a summary of it.",
            schema: schema_analyze,
        },
        ToolSpec {
            name: "sanitize",
            title: "Remove carried content from a text",
            description: "Remove carried content from a text and return the cleaned result. Removal that would rewrite visible characters is refused unless it is asked for explicitly and the text actually shows signs of having been marked, because on a text that was never marked the same operation would corrupt legitimate writing.",
            schema: schema_sanitize,
        },
        ToolSpec {
            name: "normalize_text",
            title: "Normalise a text",
            description: "Normalise a text: accents, capitalisation, spacing, punctuation and composition form, each switched on individually. Refuses when the text is carrying something, unless the loss is accepted explicitly.",
            schema: schema_normalize_text,
        },
        ToolSpec {
            name: "mark_batch",
            title: "Produce one marked copy per recipient",
            description: "Produce one visually identical copy of a document per named recipient, each carrying its own mark, together with the registry needed to identify a copy later. Reports how many recipients the document can support.",
            schema: schema_mark_batch,
        },
        ToolSpec {
            name: "trace_origin",
            title: "Identify which copy a text came from",
            description: "Given a text and the registry produced when copies were made, identify which recipient's copy it came from, with a confidence figure. Needs no passcode. Reports honestly when no mark is located.",
            schema: schema_trace_origin,
        },
        ToolSpec {
            name: "verify_mark",
            title: "Check a text against one recipient",
            description: "Check whether a text is the copy that was made for one specific recipient. Answers yes or no for that recipient alone.",
            schema: schema_verify_mark,
        },
        ToolSpec {
            name: "authorship_keypair",
            title: "Create an authorship key pair",
            description: "Create a new authorship key pair. The private half is returned once and is not retained anywhere by this surface; the caller is responsible for keeping it. The public half is what others use to check a document.",
            schema: schema_authorship_keypair,
        },
        ToolSpec {
            name: "authorship_sign",
            title: "Attach an authorship claim to a text",
            description: "Attach a signed authorship claim to a text, so that anyone holding the matching public half can confirm the claim was made by the holder of the private half and that the writing has not been altered since. The claim is bound to the visible text: editing one character makes verification fail and name the reason. The result is checked before it is handed back.",
            schema: schema_authorship_sign,
        },
        ToolSpec {
            name: "authorship_verify",
            title: "Check an authorship claim",
            description: "Check the authorship claim attached to a text against a public key, and return the claim it carries. Refuses, naming why, when the claim is absent, altered, made with a different key, or when the visible writing has changed since the claim was attached.",
            schema: schema_authorship_verify,
        },
        ToolSpec {
            name: "provenance_sign",
            title: "Attach a provenance record to a document",
            description: "Attach a signed provenance record to a document, stating one or more claims about it: that a named person authored it, that an AI system generated it (the Article 50 disclosure use), that it is unaltered, or that it was issued to a named recipient. The record is bound to the document and signed with the supplied private key. Choose a detached record kept beside the document, or an in-band record carried within the document itself; a document too small for an in-band record is refused with the exact shortfall, never truncated. The result is checked by reading it back before it is returned. This enables Article 50 aligned marking and verification, it is not itself the legal obligation.",
            schema: schema_provenance_sign,
        },
        ToolSpec {
            name: "provenance_verify",
            title: "Verify a document's provenance",
            description: "Read the provenance record attached to a document and report what holds: which claims it carries, whether each signature is valid, whether the document is unaltered since it was signed, whether the signer is trusted, and each binding's measured robustness. A claim whose signature fails, or whose document was altered, is reported rather than dropped. With trusted public keys and an optional per-claim signer requirement, it names any requirement no claim met, so an AI-generated disclosure signed by a pipeline key is not accepted as human authorship. This enables Article 50 aligned verification, it is not itself the legal obligation.",
            schema: schema_provenance_verify,
        },
        ToolSpec {
            name: "document_inspect",
            title: "Inspect your own document",
            description: "Inspect a document you hold and report the marks it carries: the class and count of each mark this tool can recognise, the carrier signatures present, any readable metadata, and an honest summary. This shows you what is in your own content. It also names invisible characters that fall outside the removable classes rather than passing over them, and it decrypts nothing.",
            schema: schema_document_inspect,
        },
        ToolSpec {
            name: "document_clean",
            title: "Clean your own document",
            description: "Remove the mark classes you choose from your own document and return the cleaned text, leaving everything outside those classes byte-identical. Reports how many marks were removed per class and an honest residual note stating what a native clean does not address: statistical or token-sampling watermarks are out of scope and are not removed here, and marks carried in pixels, audio or a container format are not part of the text path. This is control over your own content, not a claim to defeat another party's detection.",
            schema: schema_document_clean,
        },
        ToolSpec {
            name: "file_inspect",
            title: "Inspect your own document file",
            description: "Inspect a document file you hold, supplied as base64 bytes with a format hint (Word .docx, OpenDocument .odt, HTML, Markdown or plain text), and report the marks it carries: the class and count of each mark this tool can recognise, the carrier signatures present, any readable metadata, and an honest summary. It reads the file's own text and shows what is in your own content, names invisible characters outside the removable classes rather than passing over them, and decrypts nothing. A format it cannot read is refused by name, never returned empty.",
            schema: schema_file_inspect,
        },
        ToolSpec {
            name: "file_clean",
            title: "Clean your own document file",
            description: "Remove the mark classes you choose from your own document file (Word .docx, OpenDocument .odt, Markdown or plain text) and return the cleaned file rewritten in its original format, so every character outside those classes stays byte-identical. Reports how many marks were removed per class, the cleaned bytes as base64 (and the cleaned text when the format is text), and an honest residual note: statistical or token-sampling watermarks are out of scope and are not removed here, and marks carried in pixels, audio or elsewhere are not part of the text path. A format or class combination whose lossless rewrite cannot be proven is refused by name, never approximated. This is control over your own content, not a claim to defeat another party's detection.",
            schema: schema_file_clean,
        },
        ToolSpec {
            name: "file_analyze",
            title: "Analyse your own document file",
            description: "Produce the full analysis of a document file you hold, supplied as base64 bytes with a format hint. It reads the file's own text and returns the complete report: overall verdict, per-carrier findings, character-level anomalies, script mixing and statistics. This is the whole report, not a summary of it. A format whose text cannot be read is refused by name, never returned empty.",
            schema: schema_file_analyze,
        },
        ToolSpec {
            name: "file_conceal",
            title: "Place a secret in your own document file",
            description: "Place a secret inside a document file and return the marked file in its ORIGINAL format, supplied as base64 bytes with a format hint, the secret, the carriers to use and an optional confidentiality layer. Text-native formats are served; a container or markup format is refused by name, because a marked document in those formats would need the placement redistributed across the document's own structure, which this build does not do. The mark is read back before the file is handed over, and the marked file is returned as base64 with the carriers and any confidentiality layer that were applied. This is the surgical route that keeps the original format; it is not a conversion and it does not alter the visible document.",
            schema: schema_file_conceal,
        },
        ToolSpec {
            name: "file_convert",
            title: "Convert a document file to another format",
            description: "Convert a document file to another format, supplied as base64 bytes with the source format and a target format. Conversion is DECLARED LOSSY and never places a mark: it renders the source into the target and returns the converted file as base64. The set of targets this build can write is honoured, and an unsupported target is refused by name; a target that needs a local component not present on the host is refused by name too, never handed back an empty file.",
            schema: schema_file_convert,
        },
        ToolSpec {
            name: "file_metadata",
            title: "Read a file's metadata",
            description: "Read the standard metadata a file carries, supplied as base64 bytes with a format hint. For an Office document it returns the document's own properties (title, author, dates, application, custom properties); for an image it returns the EXIF and XMP the image declares, reporting the presence of location tags without interpreting them. Where the file can also carry this tool's own added metadata, that presence is reported too. A format that carries no metadata this tool reads is refused by name, never returned empty.",
            schema: schema_file_metadata,
        },
        ToolSpec {
            name: "file_strip",
            title: "Strip your own file's metadata",
            description: "Remove the metadata a file carries (its native document or image properties, and this tool's own added channel) and return the file with its readable CONTENT byte-identical, supplied as base64 bytes with a format hint. It removes only the metadata surfaces, never a value is edited and never the content is touched, so the stripped file is the same document without the metadata around it. Reports whether metadata was present and removed, and the stripped bytes as base64. A format with no strippable metadata surface is refused by name, never returned unchanged. This is a clean removal on your own file, the kind an established metadata cleaner performs.",
            schema: schema_file_strip,
        },
        ToolSpec {
            name: "file_pristine",
            title: "Pristine-clean your own text file",
            description: "Return a text file (Markdown or plain text) to a pristine state: remove every mark class AND every remaining invisible or format-control character, so the text re-analyses fully clean, supplied as base64 bytes with a format hint. This is a DECLARED opt-in that goes further than the safe clean: it also removes meaning-bearing invisibles (an emoji joiner, a right-to-left run, an Arabic or Indic joiner), which changes how such text renders, so it NAMES that trade-off and REPORTS exactly what it removed, never silently. Returns the cleaned bytes as base64 and the cleaned text, the count of invisibles removed, and the honest notes. A container or markup format is refused by name, pointing to strip plus a full clean as the best-effort pair.",
            schema: schema_file_pristine,
        },
        ToolSpec {
            name: "pqc_keypair",
            title: "Create a post-quantum recipient keypair",
            description: "Create a post-quantum recipient keypair (ML-KEM-768). The public half is what a sender uses to seal a secret to you; the secret half opens what was sealed to you. The secret half is returned once and kept nowhere by this surface; keep it yourself. This is the recipient identity for the direct encryption channel: it needs no shared password, and it resists a quantum adversary.",
            schema: schema_pqc_keypair,
        },
        ToolSpec {
            name: "pqc_seal",
            title: "Seal a secret to a recipient (post-quantum)",
            description: "Seal a secret message to a recipient's public key so only that recipient can open it. The message is encrypted with ML-KEM-768 (post-quantum key protection) and AES-256-GCM (authenticated, so any tampering is detected). The result is ordinary base64: it can be sent as is, or hidden inside a cover text with conceal so an encrypted secret travels inside a plain message. No shared password is needed, only the recipient's public key. A malformed key is refused by name.",
            schema: schema_pqc_seal,
        },
        ToolSpec {
            name: "pqc_open",
            title: "Open a sealed secret with your secret key",
            description: "Open a payload that was sealed to your public key, using your ML-KEM-768 secret key. Returns the recovered message. A wrong key, a truncated payload, or any tampering is refused by name, never a partial result: the authentication tag must verify.",
            schema: schema_pqc_open,
        },
        ToolSpec {
            name: "wordmark_analyze",
            title: "Analyze a text for word-choice marks",
            description: "Analyze a text you hold for marks that live in the choice of words, and report each finding with how sure it is. It names, with certainty, a mark made with a known public configuration, a mark you placed yourself under your own key, and a suspected acrostic you name; it flags, as a weaker indication, a word-substitution channel that is merely present; and on every report it states plainly the one limit it cannot pass, a mark keyed by a secret it does not hold. Text in, an honest report out.",
            schema: schema_wordmark_analyze,
        },
        ToolSpec {
            name: "wordmark_scrub",
            title: "Perturb a word-choice channel in a text",
            description: "Reduce a word-choice channel in a text you hold by changing synonym choices, best-effort and entirely local. It perturbs the wording to disrupt a statistical mark without a model; it is NOT a removal and makes no guarantee, because a word-choice mark can only be reduced by rewriting. It reports how many positions it changed. The chosen words change; every other byte is preserved. Nothing is sent anywhere.",
            schema: schema_wordmark_scrub,
        },
        ToolSpec {
            name: "wordmark_online_disclaimer",
            title: "Get the disclaimer to show before an online rewrite",
            description: "Before sending a user's text to an ONLINE model for rewriting, the driving agent must show the usage disclaimer in the user's language. This returns the interface keys for that disclaimer (title, body, acknowledge), so the agent resolves them in the user's language and displays them as a frame or an artifact, and proceeds only after the user acknowledges. A local model (Ollama, LM Studio, or the embedded model) sends nothing out and does not need this.",
            schema: schema_wordmark_online_disclaimer,
        },
        ToolSpec {
            name: "c2pa_inspect",
            title: "Read a file's content credential",
            description: "Read the C2PA content credential a file carries and report exactly what its validation returned: whether a credential is present, the verdict, whether the signing certificate is established against a trust list, any named validation failures, and a summary of the manifest. A file with no credential is reported absent, not an error. The verdict is only ever what the conformant reader returned, never overstated. The file is supplied as base64 bytes with an optional format hint.",
            schema: schema_c2pa_inspect,
        },
        ToolSpec {
            name: "measure_text",
            title: "Score a text",
            description: "Score a text: information density, the share of characters that are not part of the visible writing, and the share that are lookalike substitutions. With a reference text supplied, also reports the change from it.",
            schema: schema_measure_text,
        },
        ToolSpec {
            name: "compare_texts",
            title: "Compare two texts",
            description: "Compare two texts and report what one holds that the other does not, character class by character class, together with the verdict each one draws on its own. Use it to see exactly what an operation changed.",
            schema: schema_compare_texts,
        },
        ToolSpec {
            name: "protect_payload",
            title: "Protect a payload",
            description: "Protect a payload with a chosen confidentiality layer and passcode, without placing it in any text. Returns the protected bytes.",
            schema: schema_protect_payload,
        },
        ToolSpec {
            name: "unprotect_payload",
            title: "Open a protected payload",
            description: "Open a payload that was protected with a chosen layer and passcode. Refuses, naming why, when the passcode is wrong or the payload has been altered.",
            schema: schema_unprotect_payload,
        },
        ToolSpec {
            name: "compress_payload",
            title: "Compress a payload",
            description: "Compress a payload so that more of it fits in a given cover text. Reports the size before and after.",
            schema: schema_compress_payload,
        },
        ToolSpec {
            name: "expand_payload",
            title: "Expand a compressed payload",
            description: "Expand a payload that was compressed. Refuses, naming why, when the input is not something this surface produced.",
            schema: schema_expand_payload,
        },
        ToolSpec {
            name: "attach_payload",
            title: "Attach a file to a text",
            description: "Attach a small file to a text so the two travel as one. Reports the resulting size.",
            schema: schema_attach_payload,
        },
        ToolSpec {
            name: "list_attachments",
            title: "List files attached to a text",
            description: "List the files attached to a text and return their contents.",
            schema: schema_list_attachments,
        },
        ToolSpec {
            name: "detach_payload",
            title: "Remove attached files from a text",
            description: "Remove attached files from a text and return the text without them.",
            schema: schema_detach_payload,
        },
        ToolSpec {
            name: "render",
            title: "Render output ready to redistribute",
            description: "Render a text in a chosen output format, ready to hand back to a person or publish. Every rendering carries its own size, fingerprint and verdict, so what is being handed over is stated rather than assumed.",
            schema: schema_render,
        },
        ToolSpec {
            name: "export",
            title: "Export any result to a document format",
            description: "Export a text result (a revealed secret, a marked cover, a report) to a chosen document format, returned as bytes to save as a file. Formats: md, html, txt, tex, rtf, org, rst, asciidoc, ipynb, typ, pdf. Plain text and Markdown are byte-faithful, so a marked cover's hidden layer survives; the richer formats, including the self-contained native pdf, are a declared-lossy rendering. Pass a document via file_base64 to export a file's text instead. A binary container target is refused by name.",
            schema: schema_export,
        },
        ToolSpec {
            name: "settings_read",
            title: "Read runtime settings",
            description: "Read the runtime settings in force and the accepted range of every one of them. Values held for authentication are reported as present or absent, never by value.",
            schema: schema_settings_read,
        },
        ToolSpec {
            name: "settings_update",
            title: "Update runtime settings",
            description: "Update runtime settings. Every field is checked first, and a change is applied only if all of them pass; otherwise nothing changes and each offending field is returned with its reason.",
            schema: schema_settings_update,
        },
    ]
}

/// Every command name, in catalogue order. Both transports build from this.
pub fn tool_names() -> Vec<&'static str> {
    tool_specs().into_iter().map(|spec| spec.name).collect()
}

/// The catalogue as a protocol payload.
pub fn tool_list_payload() -> Value {
    Value::Array(
        tool_specs()
            .into_iter()
            .map(|spec| {
                json!({
                    "name": spec.name,
                    "title": spec.title,
                    "description": spec.description,
                    "inputSchema": served_schema(spec.name, (spec.schema)()),
                })
            })
            .collect(),
    )
}

// ─────────────────────────────────────────────────────────────
// Dispatch
// ─────────────────────────────────────────────────────────────

/// Run one command.
pub fn call(name: &str, args: &Value, store: &mut SettingsStore) -> Outcome {
    let args = match args {
        Value::Null => Map::new(),
        Value::Object(map) => map.clone(),
        other => {
            return Outcome::BadArguments(format!(
                "arguments must be an object, received {}",
                type_name(other)
            ))
        }
    };
    let args = Value::Object(args);

    // Uniform file input: any single-text operation can be handed a document file
    // instead of its text, and the text is extracted before dispatch. One path for
    // every eligible tool, so a file works the same everywhere (invariant: uniform
    // methods across functions).
    let args = match resolve_file_input(name, args) {
        Ok(resolved) => resolved,
        Err(outcome) => return outcome,
    };

    match name {
        "capabilities_list" => run_capabilities_list(&args, store),
        "chain_validate" => run_chain_validate(&args),
        "capacity_report" => run_capacity_report(&args, store),
        "recommend_settings" => run_recommend_settings(&args),
        "conceal" => run_conceal(&args),
        "reveal" => run_reveal(&args),
        "roundtrip_check" => run_roundtrip_check(&args),
        "inspect" => run_inspect(&args),
        "analyze" => run_analyze(&args),
        "sanitize" => run_sanitize(&args),
        "normalize_text" => run_normalize_text(&args),
        "mark_batch" => run_mark_batch(&args),
        "trace_origin" => run_trace_origin(&args),
        "verify_mark" => run_verify_mark(&args),
        "authorship_keypair" => run_authorship_keypair(&args),
        "authorship_sign" => run_authorship_sign(&args),
        "authorship_verify" => run_authorship_verify(&args),
        "provenance_sign" => run_provenance_sign(&args),
        "provenance_verify" => run_provenance_verify(&args),
        "document_inspect" => run_document_inspect(&args),
        "document_clean" => run_document_clean(&args),
        "file_inspect" => run_file_inspect(&args),
        "file_clean" => run_file_clean(&args),
        "file_analyze" => run_file_analyze(&args),
        "file_conceal" => run_file_conceal(&args),
        "file_convert" => run_file_convert(&args),
        "file_metadata" => run_file_metadata(&args),
        "file_strip" => run_file_strip(&args),
        "file_pristine" => run_file_pristine(&args),
        "pqc_keypair" => run_pqc_keypair(&args),
        "pqc_seal" => run_pqc_seal(&args),
        "pqc_open" => run_pqc_open(&args),
        "wordmark_analyze" => run_wordmark_analyze(&args),
        "wordmark_scrub" => run_wordmark_scrub(&args),
        "wordmark_online_disclaimer" => run_wordmark_online_disclaimer(&args),
        "c2pa_inspect" => run_c2pa_inspect(&args),
        "measure_text" => run_measure_text(&args),
        "compare_texts" => run_compare_texts(&args),
        "protect_payload" => run_protect_payload(&args),
        "unprotect_payload" => run_unprotect_payload(&args),
        "compress_payload" => run_compress_payload(&args),
        "expand_payload" => run_expand_payload(&args),
        "attach_payload" => run_attach_payload(&args),
        "list_attachments" => run_list_attachments(&args),
        "detach_payload" => run_detach_payload(&args),
        "render" => run_render(&args),
        "export" => run_export(&args),
        "settings_read" => run_settings_read(store),
        "settings_update" => run_settings_update(&args, store),
        other => Outcome::Unknown(format!(
            "unknown command '{other}': the available commands are {}",
            tool_names().join(", ")
        )),
    }
}

// ─────────────────────────────────────────────────────────────
// Uniform file input: a document file for any single-text operation
// ─────────────────────────────────────────────────────────────

/// The single text field a tool reads its primary subject from, for the tools
/// that can take a document file in its place. A tool absent here does not accept
/// a file through the shared resolver: either it is inherently file-native already
/// (the `file_*` family, `c2pa_inspect`), it produces a file rather than reading
/// one (`conceal` has `file_conceal`), it reads more than one text (`compare_texts`),
/// or it takes no document subject (keypairs, payload blobs, settings).
fn primary_text_field(name: &str) -> Option<&'static str> {
    Some(match name {
        "reveal" | "inspect" | "analyze" | "sanitize" | "normalize_text" | "mark_batch"
        | "trace_origin" | "verify_mark" | "authorship_verify" | "measure_text"
        | "wordmark_analyze" | "wordmark_scrub" | "export" => "text",
        "capacity_report" | "recommend_settings" | "roundtrip_check" | "authorship_sign"
        | "provenance_sign" => "cover",
        "provenance_verify" | "document_inspect" | "document_clean" => "document",
        _ => return None,
    })
}

/// The tools that already read `file_base64` themselves (the file layer and the
/// content-credential reader). The shared resolver leaves their file input alone.
fn is_file_native(name: &str) -> bool {
    matches!(
        name,
        "file_inspect"
            | "file_clean"
            | "file_analyze"
            | "file_conceal"
            | "file_convert"
            | "file_metadata"
            | "file_strip"
            | "file_pristine"
            | "c2pa_inspect"
    )
}

/// When a call carries `file_base64`, extract the document's text and inject it
/// into the tool's primary text field before dispatch. A tool that does not accept
/// a file, or a call that supplies both the text and a file, is refused by name
/// (invariant 2). Without `file_base64` the arguments pass through untouched.
fn resolve_file_input(name: &str, mut args: Value) -> Result<Value, Outcome> {
    if args.get("file_base64").is_none() {
        return Ok(args);
    }
    let Some(field) = primary_text_field(name) else {
        // The file-native family consumes file_base64 itself: leave it untouched.
        // Any other tool has no use for a document, so a file is refused by name.
        if is_file_native(name) {
            return Ok(args);
        }
        return Err(Outcome::BadArguments(format!(
            "'{name}' does not take a document file; supply its text directly"
        )));
    };
    if args.get(field).and_then(Value::as_str).is_some() {
        return Err(Outcome::BadArguments(format!(
            "supply either '{field}' or a document via 'file_base64', not both"
        )));
    }
    let bytes = required_base64(&args, "file_base64")?;
    let format = file_format_from(&args)?;
    let extracted = extract_text(&bytes, format)
        .map_err(|e| Outcome::refused("file_unreadable", e.to_string()))?;
    if let Value::Object(map) = &mut args {
        map.insert(field.to_string(), json!(extracted.text));
    }
    Ok(args)
}

/// The file-input properties advertised on every tool that accepts a document file
/// through [`resolve_file_input`], so the schema matches the dispatch.
fn file_input_properties() -> Value {
    json!({
        "file_base64": { "type": "string", "description": "A document file as base64. When given, its text is extracted and used in place of the text field, so this operation runs on a real file (docx, odt, html, md, txt and the other readable formats). Supply this or the text field, not both." },
        "format": { "type": "string", "description": "The document's format, as an extension or a filename (for example \"docx\" or \"notes.odt\"). Required alongside file_base64." }
    })
}

/// A tool's schema as served to clients: the base schema, plus the uniform
/// file-input fields when the tool accepts a file, with its text field relaxed
/// from required (text OR file). Applied where the schema is served on MCP and
/// REST, so the advertised contract matches the dispatch without editing each
/// `schema_*`.
fn served_schema(name: &str, mut schema: Value) -> Value {
    let Some(field) = primary_text_field(name) else {
        return schema;
    };
    if let Some(props) = schema.get_mut("properties").and_then(Value::as_object_mut) {
        if let Value::Object(extra) = file_input_properties() {
            for (key, value) in extra {
                props.entry(key).or_insert(value);
            }
        }
    }
    // The text field is no longer strictly required: a file may stand in for it.
    if let Some(required) = schema.get_mut("required").and_then(Value::as_array_mut) {
        required.retain(|value| value.as_str() != Some(field));
    }
    schema
}

// ─────────────────────────────────────────────────────────────
// Argument helpers
// ─────────────────────────────────────────────────────────────

macro_rules! bail {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(outcome) => return outcome,
        }
    };
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

fn required_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, Outcome> {
    match args.get(key) {
        Some(Value::String(text)) => Ok(text.as_str()),
        Some(other) => Err(Outcome::BadArguments(format!(
            "'{key}' must be a string, received {}",
            type_name(other)
        ))),
        None => Err(Outcome::BadArguments(format!("'{key}' is required"))),
    }
}

fn optional_str<'a>(args: &'a Value, key: &str) -> Result<Option<&'a str>, Outcome> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.as_str())),
        Some(other) => Err(Outcome::BadArguments(format!(
            "'{key}' must be a string, received {}",
            type_name(other)
        ))),
    }
}

fn optional_bool(args: &Value, key: &str, fallback: bool) -> Result<bool, Outcome> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(fallback),
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(other) => Err(Outcome::BadArguments(format!(
            "'{key}' must be a boolean, received {}",
            type_name(other)
        ))),
    }
}

fn optional_u64(args: &Value, key: &str, fallback: u64) -> Result<u64, Outcome> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(fallback),
        Some(Value::Number(number)) => number.as_u64().ok_or_else(|| {
            Outcome::BadArguments(format!("'{key}' must be a whole number that is not negative"))
        }),
        Some(other) => Err(Outcome::BadArguments(format!(
            "'{key}' must be a number, received {}",
            type_name(other)
        ))),
    }
}

fn string_array(args: &Value, key: &str) -> Result<Option<Vec<String>>, Outcome> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => {
            let mut collected = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                match item {
                    Value::String(text) => collected.push(text.clone()),
                    other => {
                        return Err(Outcome::BadArguments(format!(
                            "'{key}[{index}]' must be a string, received {}",
                            type_name(other)
                        )))
                    }
                }
            }
            Ok(Some(collected))
        }
        Some(other) => Err(Outcome::BadArguments(format!(
            "'{key}' must be an array of strings, received {}",
            type_name(other)
        ))),
    }
}

fn required_base64(args: &Value, key: &str) -> Result<Vec<u8>, Outcome> {
    let text = required_str(args, key)?;
    B64.decode(text)
        .map_err(|_| Outcome::BadArguments(format!("'{key}' is not valid base64")))
}

/// Read an optional base64 field: absent yields None, present must decode.
fn optional_base64(args: &Value, key: &str) -> Result<Option<Vec<u8>>, Outcome> {
    match optional_str(args, key)? {
        None => Ok(None),
        Some(text) => B64
            .decode(text)
            .map(Some)
            .map_err(|_| Outcome::BadArguments(format!("'{key}' is not valid base64"))),
    }
}

/// Read a payload supplied either as text or as base64. Exactly one of the two
/// must be present: supplying both would leave the surface choosing on the
/// caller's behalf.
fn payload_from(args: &Value, text_key: &str, base64_key: &str) -> Result<Vec<u8>, Outcome> {
    let as_text = optional_str(args, text_key)?;
    let as_base64 = optional_str(args, base64_key)?;
    match (as_text, as_base64) {
        (Some(_), Some(_)) => Err(Outcome::BadArguments(format!(
            "supply either '{text_key}' or '{base64_key}', not both"
        ))),
        (Some(text), None) => Ok(text.as_bytes().to_vec()),
        (None, Some(encoded)) => B64
            .decode(encoded)
            .map_err(|_| Outcome::BadArguments(format!("'{base64_key}' is not valid base64"))),
        (None, None) => Err(Outcome::BadArguments(format!(
            "one of '{text_key}' or '{base64_key}' is required"
        ))),
    }
}

/// Resolve a carrier selection, falling back to the supplied default.
fn carriers_from(args: &Value, fallback: &[&str]) -> Result<Vec<String>, Outcome> {
    let selected = string_array(args, "carriers")?
        .unwrap_or_else(|| fallback.iter().map(|id| (*id).to_string()).collect());
    catalogue::normalise_carriers(&selected).map_err(Outcome::BadArguments)
}

fn build_carriers(ids: &[String]) -> Result<Vec<Box<dyn StegoMethod>>, Outcome> {
    ids.iter()
        .map(|id| catalogue::carrier(id).map_err(Outcome::BadArguments))
        .collect()
}

/// Resolve a confidentiality layer and its passcode together, since neither is
/// usable without the other.
fn cipher_from(
    args: &Value,
) -> Result<Option<(Box<dyn CryptoMethod>, String)>, Outcome> {
    let id = optional_str(args, "cipher")?.unwrap_or(CIPHER_NONE);
    if id == CIPHER_NONE {
        return Ok(None);
    }
    let built = catalogue::cipher(id).map_err(Outcome::BadArguments)?;
    let passcode = optional_str(args, "passcode")?.unwrap_or("");
    if passcode.is_empty() {
        return Err(Outcome::BadArguments(format!(
            "'passcode' is required and must not be empty when 'cipher' is '{id}'"
        )));
    }
    Ok(Some((built, passcode.to_string())))
}

fn as_refs(built: &[Box<dyn StegoMethod>]) -> Vec<&dyn StegoMethod> {
    built.iter().map(|b| b.as_ref()).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Render a byte payload for a caller: always base64, and as text when the
/// bytes are text.
fn payload_view(bytes: &[u8]) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(text) => json!({
            "text": text,
            "base64": B64.encode(bytes),
            "byte_count": bytes.len(),
        }),
        Err(_) => json!({
            "text": Value::Null,
            "base64": B64.encode(bytes),
            "byte_count": bytes.len(),
            "note": "the payload is not text, so only its bytes are reported",
        }),
    }
}

// ─────────────────────────────────────────────────────────────
// Commands
// ─────────────────────────────────────────────────────────────

fn run_capabilities_list(_args: &Value, store: &SettingsStore) -> Outcome {
    let commands: Vec<Value> = tool_specs()
        .into_iter()
        .map(|spec| {
            json!({
                "name": spec.name,
                "title": spec.title,
                "description": spec.description,
                "parameters": served_schema(spec.name, (spec.schema)()),
            })
        })
        .collect();

    let missions: Vec<Value> = store
        .settings()
        .missions()
        .into_iter()
        .map(|(mission, ratio)| {
            json!({
                "mission": mission,
                "fill_ratio": ratio,
                "note": "a configured planning value. It applies a fill ratio to the secret capacity the capacity report states per carrier, not to a raw figure the engine would not accept.",
            })
        })
        .collect();

    Outcome::Done(json!({
        "protocol_version": crate::PROTOCOL_VERSION,
        "surface_version": crate::SERVER_VERSION,
        "carriers": catalogue::describe_carriers(),
        "ciphers": catalogue::describe_ciphers(),
        "missions": missions,
        "output_formats": RENDER_FORMATS,
        "commands": commands,
    }))
}

fn run_chain_validate(args: &Value) -> Outcome {
    let given = match bail!(string_array(args, "carriers")) {
        Some(list) if !list.is_empty() => list,
        _ => {
            return Outcome::BadArguments(
                "'carriers' is required and must name at least one carrier".into(),
            )
        }
    };
    let preserve_order = bail!(optional_bool(args, "preserve_order", false));

    // With the order preserved, the selection is checked exactly as it was
    // given, so an order that would be refused is reported as refused. By
    // default the selection is put into application order first, which is what
    // every other command does with it.
    let ids = if preserve_order {
        for id in &given {
            bail!(catalogue::carrier(id).map_err(Outcome::BadArguments));
        }
        given.clone()
    } else {
        bail!(catalogue::normalise_carriers(&given).map_err(Outcome::BadArguments))
    };

    let built = bail!(build_carriers(&ids));
    match pipeline::validate_composition(&as_refs(&built)) {
        Ok(()) => Outcome::Done(json!({
            "accepted": true,
            "carriers_in_order": ids,
            "reordered": ids != given,
            "order_preserved": preserve_order,
        })),
        Err(e) => Outcome::refused("composition_refused", e.to_string()),
    }
}

/// A short, non-repeating probe payload. Not all zeros, so a carrier that
/// returns padding cannot be mistaken for one that returned the payload.
const PROBE: [u8; 8] = [0x53, 0x48, 0x21, 0x9C, 0x0F, 0xA5, 0x60, 0xE3];

/// Explain a zero, or return null when the figure is not zero.
///
/// A carrier that reports no room says why, and the reasons are different
/// answers a caller acts on differently: a cover in a script the carrier
/// cannot touch, a cover with too few positions for even one byte, a cover
/// with too few for a whole frame, and a cover that holds a frame the envelope
/// then fills. A carrier the cover does not bound reports zero for a reason
/// that is not a shortfall at all: it places by extending the document, so no
/// fixed limit applies here.
fn capacity_zero_reason(
    positions: usize,
    cover_bounds_writes: bool,
    framed_bytes: usize,
    secret_bytes: usize,
) -> Value {
    if secret_bytes > 0 {
        return Value::Null;
    }
    let reason = if !cover_bounds_writes {
        "the cover does not bound this carrier: it places by extending the document, so no fixed \
         limit applies here and secret_bytes is not a ceiling this carrier is held to."
            .to_string()
    } else if positions == 0 {
        "this cover offers no position this carrier can use. Availability depends on the script \
         and shape of the cover text."
            .to_string()
    } else if framed_bytes == 0 {
        if positions < 8 {
            format!(
                "this cover offers {positions} positions, fewer than the 8 needed to hold a single byte"
            )
        } else {
            format!(
                "this cover offers {positions} positions, fewer than a framed document needs, so it \
                 holds no frame at all"
            )
        }
    } else {
        format!(
            "this cover holds a {framed_bytes} byte frame, but the envelope and its integrity step \
             take all of it, so no secret fits"
        )
    };
    json!(reason)
}

fn run_capacity_report(args: &Value, store: &SettingsStore) -> Outcome {
    let cover = bail!(required_str(args, "cover"));
    let selected = bail!(string_array(args, "carriers"));
    let ids = match selected {
        Some(list) => bail!(catalogue::normalise_carriers(&list).map_err(Outcome::BadArguments)),
        None => catalogue::CARRIER_ORDER.iter().map(|id| id.to_string()).collect(),
    };
    // The reported figures follow the chosen frame (COMPOSE-2): the light default
    // or the heavy, recovery-robust frame the caller asks for with robust.
    let robust = bail!(optional_bool(args, "robust", false));
    let frame_mode = pipeline::FrameMode::from_robust(robust);

    let missions = store.settings().missions();
    let mut reports = Vec::with_capacity(ids.len());

    for id in &ids {
        let built = bail!(catalogue::carrier(id).map_err(Outcome::BadArguments));
        let method = built.as_ref();
        // The substitutable positions the carrier can actually write into. A
        // cover the carrier cannot write to at all offers it none, even where
        // the same characters are ones the carrier would read: a script it must
        // not overwrite is the everyday case (the Cyrillic trap), and reporting
        // its letters as room would be the dishonesty this whole task removes.
        let positions = if method.check_writable(cover).is_ok() {
            method.positions(cover)
        } else {
            0
        };
        let bounded = format::cover_bounds_writes(method, cover);

        // The honest figure, from the engine that will place the secret.
        // `pipeline::capacity` deducts the frame, the envelope and the
        // integrity step, so `secret_bytes` is exactly what `conceal` accepts
        // for a carrier the cover bounds, and one byte more is refused. For a
        // carrier the cover does not bound it is zero, and the reason below
        // says the carrier overflows rather than being held to the cover.
        let single: [&dyn StegoMethod; 1] = [method];
        let (secret_bytes, framed_bytes, overhead_bytes) =
            match pipeline::capacity_framed(cover, &single, None, frame_mode) {
                Ok(capacity) => {
                    let carrier = &capacity.carriers[0];
                    (
                        carrier.secret_bytes,
                        carrier.framed_bytes,
                        carrier.overhead_bytes,
                    )
                }
                // A bounded carrier the cover cannot frame holds nothing, which
                // the reason names rather than passing off as a figure.
                Err(_) => (0, 0, 0),
            };

        let zero_reason = capacity_zero_reason(positions, bounded, framed_bytes, secret_bytes);

        let planning: Vec<Value> = missions
            .iter()
            .map(|(mission, ratio)| {
                json!({
                    "mission": mission,
                    "fill_ratio": ratio,
                    "planning_bytes": (secret_bytes as f64 * ratio).floor() as u64,
                })
            })
            .collect();

        reports.push(json!({
            "carrier": id,
            "positions": positions,
            "secret_bytes": secret_bytes,
            "framed_bytes": framed_bytes,
            "overhead_bytes": overhead_bytes,
            "cover_bounds_writes": bounded,
            "zero_reason": zero_reason,
            "planning_by_mission": planning,
        }));
    }

    Outcome::Done(json!({
        "cover_chars": cover.chars().count(),
        "cover_bytes": cover.len(),
        "carriers": reports,
        "planning_note": "secret_bytes is the largest secret this carrier accepts in this cover: place that many bytes and the engine takes them, one more is refused with named arithmetic. framed_bytes is what the framed document holds and overhead_bytes is what the envelope and its integrity step take from it, so secret_bytes plus overhead_bytes is framed_bytes. planning_bytes applies a configured fill ratio to secret_bytes. When a carrier is not bounded by the cover, secret_bytes is zero and zero_reason says the carrier places by extending the document rather than being held to the cover.",
    }))
}

/// Recommend the best settings for hiding a specific secret in a specific cover:
/// which carrier, mission and density hold it with the most margin and no
/// overflow, or, when nothing does, how far short the cover falls. Every figure
/// is the one the engine enforces; the caller applies the recommendation or
/// ignores it.
fn run_recommend_settings(args: &Value) -> Outcome {
    let cover = bail!(required_str(args, "cover"));
    let payload = bail!(payload_from(args, "secret", "secret_base64"));
    if payload.is_empty() {
        return Outcome::BadArguments("the secret must not be empty".into());
    }

    let selected = bail!(string_array(args, "carriers"));
    let ids = match selected {
        Some(list) => bail!(catalogue::normalise_carriers(&list).map_err(Outcome::BadArguments)),
        None => catalogue::CARRIER_ORDER.iter().map(|id| id.to_string()).collect(),
    };
    let built = bail!(build_carriers(&ids));
    let cipher = bail!(cipher_from(args));
    let robust = bail!(optional_bool(args, "robust", false));
    let frame_mode = pipeline::FrameMode::from_robust(robust);

    let carriers = as_refs(&built);
    let crypto: Option<(&dyn CryptoMethod, &str)> = cipher
        .as_ref()
        .map(|(method, passcode)| (method.as_ref(), passcode.as_str()));

    match pipeline::recommend_framed(cover, &payload, &carriers, crypto, frame_mode) {
        Ok(rec) => Outcome::Done(serde_json::to_value(rec).unwrap_or(Value::Null)),
        Err(e) => Outcome::refused("recommendation_refused", e.to_string()),
    }
}

fn run_conceal(args: &Value) -> Outcome {
    let cover = bail!(required_str(args, "cover"));
    let mut payload = bail!(payload_from(args, "secret", "secret_base64"));
    if payload.is_empty() {
        return Outcome::BadArguments("the secret must not be empty".into());
    }
    let secret_bytes_plain = payload.len();

    // Optional post-quantum recipient sealing, applied to the payload BEFORE
    // placement: the insertion engine sees ordinary bytes and is untouched. The
    // sealed blob is what gets hidden, so only the recipient's secret key opens
    // what is concealed here, with no shared passcode.
    let recipient_public = bail!(optional_base64(args, "recipient_public_key_base64"));
    let sealed_to_recipient = recipient_public.is_some();
    if let Some(public) = &recipient_public {
        payload = match crypto::pqc::seal(public, &payload) {
            Ok(sealed) => sealed,
            Err(e) => return Outcome::refused("recipient_seal_refused", e.to_string()),
        };
    }

    let ids = bail!(carriers_from(args, &["zero_width"]));
    let built = bail!(build_carriers(&ids));
    let cipher = bail!(cipher_from(args));
    let require_recovery = bail!(optional_bool(args, "require_round_trip", true));
    // The light frame is the default; the heavy, recovery-robust frame is the
    // opt-in the caller asks for with robust (COMPOSE-2). Saturation is the
    // aggressive variant that fills the channel with the mark repeated (SATURATE).
    let robust = bail!(optional_bool(args, "robust", false));
    let saturate = bail!(optional_bool(args, "saturate", false));
    let frame_mode = pipeline::FrameMode::from_robust(robust);

    let carriers = as_refs(&built);
    let crypto: Option<(&dyn CryptoMethod, &str)> = cipher
        .as_ref()
        .map(|(method, passcode)| (method.as_ref(), passcode.as_str()));

    let placed =
        match pipeline::encode_composed(cover, &payload, &carriers, crypto, frame_mode, saturate) {
            Ok(result) => result,
            Err(e) => return Outcome::refused("placement_refused", e.to_string()),
        };

    // Recover it before handing it over. A document whose content cannot be
    // read back is not a result, it is a failure that happens to look like one.
    let all_ciphers = catalogue::all_ciphers();
    let cipher_refs: Vec<&dyn CryptoMethod> = all_ciphers.iter().map(|c| c.as_ref()).collect();
    let passcode = cipher.as_ref().map(|(_, passcode)| passcode.as_str());

    let recovery = match pipeline::decode(&placed.stego_text, &carriers, &cipher_refs, passcode) {
        Err(e) => Err(e.to_string()),
        Ok(recovered) if recovered.hidden_data != payload => Err(format!(
            "the recovered content did not match the secret that was placed: {} bytes went in, {} bytes came back",
            payload.len(),
            recovered.hidden_data.len()
        )),
        Ok(recovered) if !recovered.integrity_valid => {
            Err("the recovered content failed its own integrity check".to_string())
        }
        Ok(_) => Ok(()),
    };

    if let Err(reason) = &recovery {
        if require_recovery {
            return Outcome::refused(
                "round_trip_unverified",
                format!(
                    "the text was produced but could not be read back with this selection, so it is not being returned: {reason}. Set require_round_trip to false to receive it anyway."
                ),
            );
        }
    }

    // What the tool's own analyser sees on the exact document produced, carried
    // back so the caller reads the density and verdict an analyst would, never
    // an estimate. Placement is permissive; this is how it stays honest.
    let report = pipeline::overflow_report(&placed.stego_text);

    Outcome::Done(json!({
        "stego_text": placed.stego_text,
        "carriers_used": placed.methods_used,
        "cipher": cipher.as_ref().map(|(method, _)| method.id().to_string()),
        "sealed_to_recipient": sealed_to_recipient,
        "secret_bytes": secret_bytes_plain,
        "placed_bytes": payload.len(),
        "capacity_bits_used": placed.capacity_used_bits,
        "capacity_bits_available": placed.capacity_available_bits,
        "noise_density": report.noise_density,
        "verdict": report.verdict,
        "round_trip": match &recovery {
            Ok(()) => json!({ "verified": true }),
            Err(reason) => json!({ "verified": false, "reason": reason }),
        },
        "warnings": placed.warnings,
    }))
}

fn run_reveal(args: &Value) -> Outcome {
    let text = bail!(required_str(args, "text"));
    let ids = bail!(carriers_from(args, &catalogue::CARRIER_ORDER));
    let built = bail!(build_carriers(&ids));
    let passcode = bail!(optional_str(args, "passcode"));
    let accept_unverified = bail!(optional_bool(args, "accept_unverified", false));

    let named_cipher = bail!(optional_str(args, "cipher"));
    let ciphers = match named_cipher {
        None | Some(CIPHER_NONE) => catalogue::all_ciphers(),
        Some(id) => vec![bail!(catalogue::cipher(id).map_err(Outcome::BadArguments))],
    };
    let cipher_refs: Vec<&dyn CryptoMethod> = ciphers.iter().map(|c| c.as_ref()).collect();

    let recovered = match pipeline::decode(text, &as_refs(&built), &cipher_refs, passcode) {
        Ok(result) => result,
        Err(e) => return Outcome::refused("recovery_refused", e.to_string()),
    };

    if !recovered.integrity_valid && !accept_unverified {
        return Outcome::refused(
            "integrity_unverified",
            format!(
                "content was recovered but failed its own integrity check, so it is not being returned. Set accept_unverified to true to receive it as it stands. Carriers that answered: {}",
                recovered.methods_detected.join(", ")
            ),
        );
    }

    // Optional post-quantum recipient opening, applied AFTER extraction: the
    // hidden bytes are a payload sealed to this recipient, opened with the
    // secret key. A wrong key or any tampering is refused by name, never a
    // partial (invariant 2).
    let recipient_secret = bail!(optional_base64(args, "recipient_secret_key_base64"));
    let opened_for_recipient = recipient_secret.is_some();
    let revealed = match &recipient_secret {
        None => recovered.hidden_data.clone(),
        Some(secret) => match crypto::pqc::open(secret, &recovered.hidden_data) {
            Ok(plaintext) => plaintext,
            Err(e) => return Outcome::refused("recipient_open_refused", e.to_string()),
        },
    };

    Outcome::Done(json!({
        "secret": payload_view(&revealed),
        "carriers_detected": recovered.methods_detected,
        "cipher_used": recovered.crypto_used,
        "opened_for_recipient": opened_for_recipient,
        "integrity_valid": recovered.integrity_valid,
        "warnings": recovered.warnings,
    }))
}

fn run_roundtrip_check(args: &Value) -> Outcome {
    let cover = bail!(required_str(args, "cover"));
    let payload = match args.get("secret").or_else(|| args.get("secret_base64")) {
        Some(_) => bail!(payload_from(args, "secret", "secret_base64")),
        None => PROBE.to_vec(),
    };
    let ids = bail!(carriers_from(args, &["zero_width"]));
    let built = bail!(build_carriers(&ids));
    let cipher = bail!(cipher_from(args));
    let carriers = as_refs(&built);

    let composition = match pipeline::validate_composition(&carriers) {
        Ok(()) => json!({ "passed": true }),
        Err(e) => {
            return Outcome::Done(json!({
                "carriers_in_order": ids,
                "composition": { "passed": false, "reason": e.to_string() },
                "placement": Value::Null,
                "recovery": Value::Null,
                "payload_recovered_exactly": false,
            }))
        }
    };

    let crypto: Option<(&dyn CryptoMethod, &str)> = cipher
        .as_ref()
        .map(|(method, passcode)| (method.as_ref(), passcode.as_str()));

    let placed = match pipeline::encode(cover, &payload, &carriers, crypto) {
        Ok(result) => result,
        Err(e) => {
            return Outcome::Done(json!({
                "carriers_in_order": ids,
                "composition": composition,
                "placement": { "passed": false, "reason": e.to_string() },
                "recovery": Value::Null,
                "payload_recovered_exactly": false,
            }))
        }
    };

    let all_ciphers = catalogue::all_ciphers();
    let cipher_refs: Vec<&dyn CryptoMethod> = all_ciphers.iter().map(|c| c.as_ref()).collect();
    let passcode = cipher.as_ref().map(|(_, passcode)| passcode.as_str());

    match pipeline::decode(&placed.stego_text, &carriers, &cipher_refs, passcode) {
        Err(e) => Outcome::Done(json!({
            "carriers_in_order": ids,
            "composition": composition,
            "placement": { "passed": true, "produced_chars": placed.stego_text.chars().count() },
            "recovery": { "passed": false, "reason": e.to_string() },
            "payload_recovered_exactly": false,
        })),
        Ok(recovered) => {
            let exact = recovered.hidden_data == payload;
            Outcome::Done(json!({
                "carriers_in_order": ids,
                "composition": composition,
                "placement": { "passed": true, "produced_chars": placed.stego_text.chars().count() },
                "recovery": {
                    "passed": true,
                    "carriers_detected": recovered.methods_detected,
                    "cipher_used": recovered.crypto_used,
                    "integrity_valid": recovered.integrity_valid,
                    "warnings": recovered.warnings,
                },
                "payload_recovered_exactly": exact,
                "payload_bytes_in": payload.len(),
                "payload_bytes_out": recovered.hidden_data.len(),
            }))
        }
    }
}

/// The mission a document was produced for, as the caller names it elsewhere.
///
/// The same three words the density settings use, so a report and a setting
/// never call the same mission by two different names.
fn mission_label(mission: Mission) -> &'static str {
    match mission {
        Mission::Conceal => "conceal",
        Mission::Sign => "sign",
        Mission::Mark => "mark",
    }
}

/// The readable shape of what a carrier holds, as written by the core pipeline.
///
/// Everything here is structure. The document states its own format version,
/// mission and payload size, and lists the transforms that were applied to the
/// content in the order they were applied. All of it is readable without a
/// passcode and none of it opens the protected part: the content itself is
/// reported only as a byte count.
///
/// Returns `Null` when this carrier holds nothing readable in this text. When
/// the document states a format but its content region cannot be read, the
/// reason is reported rather than left as an absent field a caller would read
/// as "no confidentiality layer".
///
/// The shape is checked against the core in this crate's tests, so a change in
/// the core breaks a test rather than silently producing an empty report.
fn document_shape(carrier: &dyn StegoMethod, text: &str) -> Value {
    let Ok(raw) = carrier.decode(text) else {
        return Value::Null;
    };
    let bits = frame::bytes_to_bits(&raw);

    // The light frame is the default the core writes (§3.2): one head-written
    // header carrying the version, the mission flags and the payload length,
    // with the envelope in its payload. Read it directly. The heavy frame below,
    // located by its preamble replicas, is the secondary path.
    if let Some(version) = format::frame_light::peek_version(&bits) {
        if let Ok(light) = format::frame_light::read_light(&bits) {
            let mut shape = json!({
                "format_version": version.to_string(),
                "mission": mission_label(light.flags.mission),
                "stealth": light.flags.stealth,
                "detached_signature": light.flags.detached_signature,
                "read_from": "head",
                "declared_payload_bits": light.payload.len() * 8,
                "content_version": Value::Null,
                "chain_declared": Value::Null,
                "cipher_declared": Value::Null,
                "payload_bytes": Value::Null,
                "note": "read from the document structure only. Nothing was decrypted and no passcode was used.",
            });
            match Envelope::parse(&light.payload) {
                Ok(content) => {
                    let chain: Vec<String> =
                        content.chain.iter().map(|step| step.id.clone()).collect();
                    let cipher = chain
                        .iter()
                        .find(|id| catalogue::cipher(id).is_ok())
                        .cloned();
                    shape["content_version"] = json!(content.v);
                    shape["chain_declared"] = json!(chain);
                    shape["cipher_declared"] = json!(cipher);
                    shape["payload_bytes"] = json!(content.payload.len());
                }
                Err(e) => {
                    shape["content_unreadable"] = json!(e.to_string());
                }
            }
            return shape;
        }
    }

    let Ok((preamble, source)) = format::locate_preamble(&bits) else {
        return Value::Null;
    };

    let mut shape = json!({
        "format_version": preamble.version.to_string(),
        "mission": mission_label(preamble.flags.mission),
        "stealth": preamble.flags.stealth,
        "detached_signature": preamble.flags.detached_signature,
        "read_from": match source {
            PreambleSource::Head => "head",
            PreambleSource::Tail => "tail",
        },
        "declared_payload_bits": preamble.payload_bits,
        "content_version": Value::Null,
        "chain_declared": Value::Null,
        "cipher_declared": Value::Null,
        "payload_bytes": Value::Null,
        "note": "read from the document structure only. Nothing was decrypted and no passcode was used.",
    });

    match format::read(&bits).and_then(|contents| Envelope::parse(&contents.payload)) {
        Ok(content) => {
            let chain: Vec<String> = content.chain.iter().map(|step| step.id.clone()).collect();
            let cipher = chain
                .iter()
                .find(|id| catalogue::cipher(id).is_ok())
                .cloned();
            shape["content_version"] = json!(content.v);
            shape["chain_declared"] = json!(chain);
            shape["cipher_declared"] = json!(cipher);
            shape["payload_bytes"] = json!(content.payload.len());
        }
        Err(e) => {
            shape["content_unreadable"] = json!(e.to_string());
        }
    }

    shape
}

fn run_inspect(args: &Value) -> Outcome {
    let text = bail!(required_str(args, "text"));
    let carriers = catalogue::all_carriers();
    let refs = as_refs(&carriers);
    let scores = pipeline::detect(text, &refs);

    let mut findings = Vec::new();
    for carrier in &carriers {
        let score = carrier.detect(text);
        let envelope = document_shape(carrier.as_ref(), text);
        findings.push(json!({
            "carrier": carrier.id(),
            "score": score,
            "envelope": envelope,
        }));
    }

    let chain: Vec<String> = findings
        .iter()
        .filter(|f| f["score"].as_f64().unwrap_or(0.0) > 0.0)
        .map(|f| f["carrier"].as_str().unwrap().to_string())
        .collect();

    Outcome::Done(json!({
        "overall_score": scores.overall_confidence,
        "carriers": findings,
        "chain_summary": {
            "carriers_responding": chain,
            "note": "the order carriers were applied in is not recorded in this format, so this is the set that responded, not a sequence.",
        },
        "decrypted": false,
    }))
}

fn run_analyze(args: &Value) -> Outcome {
    let text = bail!(required_str(args, "text"));
    match serde_json::to_value(forensic::analyze(text)) {
        Ok(report) => Outcome::Done(report),
        Err(e) => Outcome::refused("report_unavailable", e.to_string()),
    }
}

fn run_sanitize(args: &Value) -> Outcome {
    let text = bail!(required_str(args, "text"));
    let allow_visible_rewrite = bail!(optional_bool(args, "allow_visible_text_rewrite", false));

    let described = catalogue::describe_carriers();
    let alters_visible = |id: &str| -> bool {
        described
            .iter()
            .find(|entry| entry["id"] == json!(id))
            .map(|entry| entry["alters_visible_text"] == json!(true))
            .unwrap_or(false)
    };

    let requested = bail!(string_array(args, "channels"));
    let ids = match requested {
        Some(list) => bail!(catalogue::normalise_carriers(&list).map_err(Outcome::BadArguments)),
        None => catalogue::CARRIER_ORDER
            .iter()
            .filter(|id| !alters_visible(id))
            .map(|id| id.to_string())
            .collect(),
    };

    let rewriting: Vec<&String> = ids.iter().filter(|id| alters_visible(id)).collect();
    if !rewriting.is_empty() {
        if !allow_visible_rewrite {
            return Outcome::refused(
                "visible_rewrite_refused",
                format!(
                    "cleaning with {} rewrites visible characters, which changes the text itself. Set allow_visible_text_rewrite to true to ask for it deliberately.",
                    rewriting
                        .iter()
                        .map(|id| id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
        }

        // A text that was never marked looks exactly like a text written in a
        // script this operation would rewrite. Refusing here is the difference
        // between cleaning a marked document and corrupting an ordinary one.
        let report = forensic::analyze(text);
        let shows_marking = report
            .unicode_analysis
            .mixed_scripts
            .iter()
            .any(|mix| mix.pattern == "homoglyph_substitution");
        if !shows_marking {
            return Outcome::refused(
                "no_marking_found",
                format!(
                    "this text shows no sign of the marking that {} would remove, so running it would rewrite characters that belong to the text. Verdict on the text as it stands: {}.",
                    rewriting
                        .iter()
                        .map(|id| id.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    report.verdict
                ),
            );
        }
    }

    let before = text.chars().count();
    let mut cleaned = text.to_string();
    let mut applied = Vec::new();
    for id in &ids {
        let carrier = bail!(catalogue::carrier(id).map_err(Outcome::BadArguments));
        cleaned = carrier.strip(&cleaned);
        applied.push(id.clone());
    }
    let after = cleaned.chars().count();

    Outcome::Done(json!({
        "text": cleaned,
        "channels_applied": applied,
        "chars_before": before,
        "chars_after": after,
        "chars_removed": before.saturating_sub(after),
        "changed": cleaned != text,
    }))
}

fn run_normalize_text(args: &Value) -> Outcome {
    let text = bail!(required_str(args, "text"));
    let accept_loss = bail!(optional_bool(args, "accept_payload_loss", false));

    let options = CleanOptions {
        remove_accents: bail!(optional_bool(args, "remove_accents", false)),
        lowercase: bail!(optional_bool(args, "lowercase", false)),
        collapse_whitespace: bail!(optional_bool(args, "collapse_whitespace", false)),
        remove_punctuation: bail!(optional_bool(args, "remove_punctuation", false)),
        normalize_nfc: bail!(optional_bool(args, "normalize_nfc", false)),
    };

    if !accept_loss {
        let carriers = catalogue::all_carriers();
        let detected = pipeline::detect(text, &as_refs(&carriers));
        if !detected.methods.is_empty() {
            return Outcome::refused(
                "payload_loss_refused",
                format!(
                    "this text is carrying something and normalising it would destroy that. Set accept_payload_loss to true to proceed. Carriers responding: {}.",
                    detected
                        .methods
                        .iter()
                        .map(|m| m.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
        }
    }

    let cleaned = TextClean::new().clean(text, &options);
    Outcome::Done(json!({
        "text": cleaned,
        "chars_before": text.chars().count(),
        "chars_after": cleaned.chars().count(),
        "changed": cleaned != text,
    }))
}

fn run_mark_batch(args: &Value) -> Outcome {
    let text = bail!(required_str(args, "text"));
    let salt = bail!(required_str(args, "salt"));
    let recipients = match bail!(string_array(args, "recipients")) {
        Some(list) if !list.is_empty() => list,
        Some(_) | None => {
            return Outcome::BadArguments(
                "'recipients' is required and must name at least one recipient".into(),
            )
        }
    };
    let refs: Vec<&str> = recipients.iter().map(|r| r.as_str()).collect();

    let batch = match canary::generate_batch(text, &refs, salt) {
        Ok(batch) => batch,
        Err(e) => return Outcome::refused("marking_refused", e.to_string()),
    };

    let mut copies = Vec::with_capacity(batch.versions.len());
    let mut registry = Vec::with_capacity(batch.versions.len());
    for version in &batch.versions {
        copies.push(json!({
            "recipient_id": version.recipient.id,
            "mark_hash": version.recipient.fingerprint_hash,
            "text": version.text,
        }));
        match serde_json::to_value(&version.recipient) {
            Ok(entry) => registry.push(entry),
            Err(e) => return Outcome::refused("registry_unavailable", e.to_string()),
        }
    }

    Outcome::Done(json!({
        "copies": copies,
        "registry": registry,
        "mark_bits": batch.fingerprint_bits,
        "max_recipients": batch.max_recipients,
        "registry_note": "keep the registry: it is what turns a leaked copy back into a name. trace_origin takes it as supplied here.",
    }))
}

fn run_trace_origin(args: &Value) -> Outcome {
    let text = bail!(required_str(args, "text"));
    let registry_value = match args.get("registry") {
        Some(value @ Value::Array(_)) => value.clone(),
        Some(other) => {
            return Outcome::BadArguments(format!(
                "'registry' must be the array produced by mark_batch, received {}",
                type_name(other)
            ))
        }
        None => return Outcome::BadArguments("'registry' is required".into()),
    };

    let registry: Vec<canary::Recipient> = match serde_json::from_value(registry_value) {
        Ok(entries) => entries,
        Err(e) => {
            return Outcome::BadArguments(format!(
                "'registry' is not in the shape mark_batch produced: {e}"
            ))
        }
    };

    let located = match canary::identify_leak(text, &registry) {
        Ok(result) => result,
        Err(e) => return Outcome::refused("tracing_refused", e.to_string()),
    };

    Outcome::Done(json!({
        "recipient_id": located.recipient.as_ref().map(|r| r.id.clone()),
        "mark_hash": located.recipient.as_ref().map(|r| r.fingerprint_hash.clone()),
        "confidence": located.confidence,
        "extracted_mark_base64": B64.encode(&located.extracted_fingerprint),
        "identified": located.recipient.is_some(),
        "registry_size": registry.len(),
    }))
}

fn run_verify_mark(args: &Value) -> Outcome {
    let text = bail!(required_str(args, "text"));
    let recipient = bail!(required_str(args, "recipient_id"));
    let salt = bail!(required_str(args, "salt"));
    let mark_bytes = bail!(optional_u64(args, "mark_bytes", 0));
    if mark_bytes == 0 {
        return Outcome::BadArguments(
            "'mark_bytes' is required and must be the mark size reported when the copies were made"
                .into(),
        );
    }

    match canary::verify_recipient(text, recipient, salt, mark_bytes as usize) {
        Ok(matches) => Outcome::Done(json!({
            "recipient_id": recipient,
            "matches": matches,
        })),
        Err(e) => Outcome::refused("verification_refused", e.to_string()),
    }
}

fn run_authorship_keypair(_args: &Value) -> Outcome {
    let keypair = signing::MasterKeyPair::generate();
    Outcome::Done(json!({
        "private_key_base64": B64.encode(keypair.private_bytes()),
        "public_key_base64": B64.encode(keypair.public_key().to_bytes()),
        "note": "the private half is returned once and is kept nowhere by this surface. Store it yourself; without it no further document can be signed under this identity.",
    }))
}

/// What an authorship claim protects, stated on every result that carries one.
///
/// The claim is signed on its own contents. The surrounding writing is not
/// part of what is signed, so a claim that verifies says the claim is intact
/// and says nothing about whether the visible text was edited afterwards.
/// Stating that on the result is the difference between a true capability and
/// an overstated one.
const CLAIM_COVERAGE: &str = "the claim and the writing it was attached to. A claim that verifies confirms it was made by the holder of the private half, and that the visible text has not been altered since it was attached. Altering one character makes verification fail and say so.";

fn claim_view(claim: &license::License) -> Value {
    json!({
        "author": claim.licensee,
        "claim_id": claim.id,
        "scope": claim.modules,
        "issued": claim.issued,
        "expires": claim.expires,
        "organisation": claim.org,
        "reference": claim.canary,
    })
}

fn run_authorship_sign(args: &Value) -> Outcome {
    let cover = bail!(required_str(args, "cover"));
    let author = bail!(required_str(args, "author"));
    let private_key = bail!(required_base64(args, "private_key_base64"));
    let carrier_id = bail!(optional_str(args, "carrier")).unwrap_or("zero_width");
    let carrier = bail!(catalogue::carrier(carrier_id).map_err(Outcome::BadArguments));

    let bytes: [u8; 32] = match private_key.as_slice().try_into() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Outcome::BadArguments(format!(
                "'private_key_base64' must decode to 32 bytes, received {}",
                private_key.len()
            ))
        }
    };
    let keypair = signing::MasterKeyPair::from_private_bytes(&bytes);

    let mut builder = license::LicenseBuilder::new(author);
    match bail!(string_array(args, "scope")) {
        Some(scope) if !scope.is_empty() => {
            for entry in &scope {
                builder = builder.module(entry);
            }
        }
        _ => builder = builder.module("*"),
    }
    if let Some(expires) = bail!(optional_str(args, "expires")) {
        builder = builder.expires(expires);
    }
    if let Some(organisation) = bail!(optional_str(args, "organisation")) {
        builder = builder.org(organisation);
    }
    let claim = builder.build();

    let signed = match license::sign_and_embed(&claim, &keypair, cover, carrier.as_ref()) {
        Ok(text) => text,
        Err(e) => return Outcome::refused("signing_refused", e.to_string()),
    };

    // Read it back with the public half before handing it over.
    let public = keypair.public_key();
    if let Err(e) = license::extract_and_verify(&signed, &public, carrier.as_ref()) {
        return Outcome::refused(
            "round_trip_unverified",
            format!(
                "the claim was attached but could not be read back from the result, so it is not being returned: {e}"
            ),
        );
    }

    Outcome::Done(json!({
        "signed_text": signed,
        "carrier": carrier_id,
        "claim": claim_view(&claim),
        "public_key_base64": B64.encode(public.to_bytes()),
        "round_trip": { "verified": true },
        "covers": CLAIM_COVERAGE,
    }))
}

fn run_authorship_verify(args: &Value) -> Outcome {
    let text = bail!(required_str(args, "text"));
    let public_key = bail!(required_base64(args, "public_key_base64"));
    let carrier_id = bail!(optional_str(args, "carrier")).unwrap_or("zero_width");
    let carrier = bail!(catalogue::carrier(carrier_id).map_err(Outcome::BadArguments));

    let bytes: [u8; 32] = match public_key.as_slice().try_into() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Outcome::BadArguments(format!(
                "'public_key_base64' must decode to 32 bytes, received {}",
                public_key.len()
            ))
        }
    };
    let public = match signing::MasterPublicKey::from_bytes(&bytes) {
        Ok(key) => key,
        Err(e) => return Outcome::BadArguments(e.to_string()),
    };

    match license::extract_and_verify(text, &public, carrier.as_ref()) {
        Ok(claim) => Outcome::Done(json!({
            "verified": true,
            "carrier": carrier_id,
            "claim": claim_view(&claim),
            "covers": CLAIM_COVERAGE,
        })),
        Err(e) => Outcome::refused("verification_refused", e.to_string()),
    }
}

// ─────────────────────────────────────────────────────────────
// Provenance
// ─────────────────────────────────────────────────────────────
//
// The signing identity is an Ed25519 key pair, the same shape authorship_keypair
// produces. Private key material appears only in the arguments a caller supplies;
// it is never returned by these commands and never written into a reason or log.

/// The stated purpose of a provenance record, carried on every result, so the
/// tool never overclaims: it enables the marking and the verification, it is not
/// itself the legal obligation, which sits on AI providers and deployers.
const PROVENANCE_NOTE: &str = "this enables Article 50 aligned marking and verification. The legal obligation itself sits on AI providers and deployers, not on this utility.";

/// Read an optional string field off an assertion object, as an owned value.
fn assertion_str(item: &Value, key: &str) -> Result<Option<String>, Outcome> {
    Ok(optional_str(item, key)?.map(|s| s.to_string()))
}

/// Build the typed assertion set a claim will state, from the request. Refuses
/// by name on an empty set, an unknown kind, or a kind missing a required field,
/// rather than signing a claim that says less than the caller asked for.
fn assertions_from(args: &Value, cover: &str) -> Result<Vec<Box<dyn Assertion>>, Outcome> {
    let items = match args.get("assertions") {
        Some(Value::Array(items)) if !items.is_empty() => items,
        Some(Value::Array(_)) | None => {
            return Err(Outcome::BadArguments(
                "'assertions' is required and must state at least one claim".into(),
            ))
        }
        Some(other) => {
            return Err(Outcome::BadArguments(format!(
                "'assertions' must be an array of objects, received {}",
                type_name(other)
            )))
        }
    };

    let mut built: Vec<Box<dyn Assertion>> = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        if !item.is_object() {
            return Err(Outcome::BadArguments(format!(
                "'assertions[{index}]' must be an object, received {}",
                type_name(item)
            )));
        }
        let kind = match item.get("kind") {
            Some(Value::String(kind)) => kind.as_str(),
            Some(other) => {
                return Err(Outcome::BadArguments(format!(
                    "'assertions[{index}].kind' must be a string, received {}",
                    type_name(other)
                )))
            }
            None => {
                return Err(Outcome::BadArguments(format!(
                    "'assertions[{index}].kind' is required"
                )))
            }
        };

        let assertion: Box<dyn Assertion> = match kind {
            KIND_HUMAN_AUTHORSHIP => Box::new(HumanAuthorship {
                author: assertion_str(item, "author")?,
            }),
            KIND_AI_GENERATED => Box::new(AiGenerated {
                model: assertion_str(item, "model")?,
                provider: assertion_str(item, "provider")?,
                system_version: assertion_str(item, "system_version")?,
            }),
            KIND_INTEGRITY => match license::document_hash(cover) {
                Ok(document_hash) => Box::new(Integrity { document_hash }),
                Err(e) => {
                    return Err(Outcome::refused(
                        "claim_refused",
                        format!("the integrity claim could not be computed for this document: {e}"),
                    ))
                }
            },
            KIND_RECIPIENT_FINGERPRINT => {
                let recipient_id = match assertion_str(item, "recipient_id")? {
                    Some(value) => value,
                    None => {
                        return Err(Outcome::BadArguments(format!(
                            "'assertions[{index}].recipient_id' is required for a {KIND_RECIPIENT_FINGERPRINT} claim"
                        )))
                    }
                };
                let salt = match assertion_str(item, "salt")? {
                    Some(value) => value,
                    None => {
                        return Err(Outcome::BadArguments(format!(
                            "'assertions[{index}].salt' is required for a {KIND_RECIPIENT_FINGERPRINT} claim"
                        )))
                    }
                };
                match RecipientFingerprint::derive(&recipient_id, &salt, cover) {
                    Ok(rf) => Box::new(rf),
                    Err(e) => {
                        return Err(Outcome::refused(
                            "claim_refused",
                            format!("the recipient claim could not be derived for this document: {e}"),
                        ))
                    }
                }
            }
            other => {
                return Err(Outcome::BadArguments(format!(
                    "'assertions[{index}].kind' names an unknown claim '{other}': the available claims are {KIND_HUMAN_AUTHORSHIP}, {KIND_AI_GENERATED}, {KIND_INTEGRITY}, {KIND_RECIPIENT_FINGERPRINT}"
                )))
            }
        };
        built.push(assertion);
    }
    Ok(built)
}

/// The readable view of a signed claim. It states the schema version, the claim
/// kinds and their payloads, the document hash the claim is bound to, the
/// creation time, and the public signer. It never carries any private key.
fn signed_claim_view(signed: &SignedClaim) -> Value {
    let kinds: Vec<String> = signed
        .claim
        .assertions
        .iter()
        .map(|a| a.kind.clone())
        .collect();
    json!({
        "schema_version": signed.claim.v,
        "assertion_kinds": kinds,
        "assertions": serde_json::to_value(&signed.claim.assertions).unwrap_or(Value::Null),
        "document_hash": signed.claim.document_hash,
        "created": signed.claim.created,
        "signer": serde_json::to_value(&signed.claim.signer).unwrap_or(Value::Null),
    })
}

/// Decode a 32 byte Ed25519 public key supplied as base64 into a key reference,
/// refusing by name rather than substituting a default.
fn public_key_ref_from_base64(text: &str, field: &str) -> Result<PublicKeyRef, Outcome> {
    let bytes = B64
        .decode(text)
        .map_err(|_| Outcome::BadArguments(format!("'{field}' is not valid base64")))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        Outcome::BadArguments(format!(
            "'{field}' must decode to 32 bytes, received {}",
            bytes.len()
        ))
    })?;
    let public = signing::MasterPublicKey::from_bytes(&arr)
        .map_err(|e| Outcome::BadArguments(e.to_string()))?;
    Ok(PublicKeyRef::ed25519(&public))
}

/// The signer public key a verified claim names, re-encoded as base64 so it
/// reads the same way as the keys a caller supplies to this surface.
fn signer_base64_from_ref(signer: &Value) -> Option<String> {
    let hex = signer.get("key").and_then(|k| k.as_str())?;
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let raw = hex.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        let byte = u8::from_str_radix(std::str::from_utf8(&raw[i..i + 2]).ok()?, 16).ok()?;
        bytes.push(byte);
        i += 2;
    }
    Some(B64.encode(&bytes))
}

fn run_provenance_sign(args: &Value) -> Outcome {
    let cover = bail!(required_str(args, "cover"));
    let private_key = bail!(required_base64(args, "private_key_base64"));
    let binding_kind = bail!(optional_str(args, "binding")).unwrap_or("detached");
    let created = bail!(optional_str(args, "created")).map(|s| s.to_string());

    let key_bytes: [u8; 32] = match private_key.as_slice().try_into() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Outcome::BadArguments(format!(
                "'private_key_base64' must decode to 32 bytes, received {}",
                private_key.len()
            ))
        }
    };
    let keypair = signing::MasterKeyPair::from_private_bytes(&key_bytes);
    let public = keypair.public_key();

    let assertions = bail!(assertions_from(args, cover));
    let refs: Vec<&dyn Assertion> = assertions.iter().map(|a| a.as_ref()).collect();

    let claim = match ProvenanceClaim::new(&refs, cover, &public, created) {
        Ok(claim) => claim,
        Err(e) => return Outcome::refused("claim_refused", e.to_string()),
    };
    let signed = match SignedClaim::sign(claim, &keypair) {
        Ok(signed) => signed,
        Err(e) => return Outcome::refused("signing_refused", e.to_string()),
    };
    let signer_public_key_base64 = B64.encode(public.to_bytes());
    let trusted = TrustPolicy::new(vec![PublicKeyRef::ed25519(&public)]);

    match binding_kind {
        "detached" => {
            let out = match DetachedBinding::new().bind(cover, &signed) {
                Ok(out) => out,
                Err(e) => return Outcome::refused("binding_refused", e.to_string()),
            };

            // Read it back before handing it over: a record that does not verify
            // when re-read is a failure, not a result.
            let report = match verify_document(cover, Some(&out.bytes), &[], &trusted) {
                Ok(report) => report,
                Err(e) => {
                    return Outcome::refused(
                        "round_trip_unverified",
                        format!("the record was produced but could not be read back, so it is not being returned: {e}"),
                    )
                }
            };
            if report
                .claims
                .first()
                .map(|c| !c.signature_valid || !c.document_unaltered)
                .unwrap_or(true)
            {
                return Outcome::refused(
                    "round_trip_unverified",
                    "the record was produced but did not verify when read back, so it is not being returned",
                );
            }

            Outcome::Done(json!({
                "binding": "detached",
                "sidecar": payload_view(&out.bytes),
                "signer_public_key_base64": signer_public_key_base64,
                "claim": signed_claim_view(&signed),
                "declared_robustness": serde_json::to_value(DetachedBinding::new().declared_robustness()).unwrap_or(Value::Null),
                "round_trip": { "verified": true },
                "note": PROVENANCE_NOTE,
            }))
        }
        "in_band" => {
            let carrier_id = bail!(optional_str(args, "carrier")).unwrap_or("zero_width");
            let carrier = bail!(catalogue::carrier(carrier_id).map_err(Outcome::BadArguments));
            let binding = InBandBinding::new(carrier.as_ref());

            let out = match binding.bind(cover, &signed) {
                Ok(out) => out,
                Err(SteganoError::CapacityExceeded { needed, available }) => {
                    return Outcome::refused(
                        "capacity_exceeded",
                        format!(
                            "the document cannot carry this record in-band through the '{carrier_id}' carrier: it needs {needed} bits but the document offers {available} bits. Use a longer document or the detached binding."
                        ),
                    )
                }
                Err(e) => return Outcome::refused("binding_refused", e.to_string()),
            };
            let marked = match String::from_utf8(out.bytes) {
                Ok(marked) => marked,
                Err(_) => {
                    return Outcome::refused(
                        "binding_refused",
                        "the in-band binding produced bytes that are not valid text",
                    )
                }
            };

            // The realised robustness is measured on the produced document, never
            // taken from the declaration and never raised above what an in-band
            // record can deliver.
            let realised = binding.realised_robustness(&marked);

            let report = match verify_document(&marked, None, &[carrier.as_ref()], &trusted) {
                Ok(report) => report,
                Err(e) => {
                    return Outcome::refused(
                        "round_trip_unverified",
                        format!("the record was placed but could not be read back, so it is not being returned: {e}"),
                    )
                }
            };
            if report
                .claims
                .first()
                .map(|c| !c.signature_valid || !c.document_unaltered)
                .unwrap_or(true)
            {
                return Outcome::refused(
                    "round_trip_unverified",
                    "the record was placed but did not verify when read back, so it is not being returned",
                );
            }

            Outcome::Done(json!({
                "binding": "in_band",
                "carrier": carrier_id,
                "marked_text": marked,
                "signer_public_key_base64": signer_public_key_base64,
                "claim": signed_claim_view(&signed),
                "measured_robustness": serde_json::to_value(realised).unwrap_or(Value::Null),
                "round_trip": { "verified": true },
                "note": PROVENANCE_NOTE,
            }))
        }
        other => Outcome::BadArguments(format!(
            "'binding' must be 'detached' or 'in_band', received '{other}'"
        )),
    }
}

fn run_provenance_verify(args: &Value) -> Outcome {
    let document = bail!(required_str(args, "document"));

    let sidecar = match bail!(optional_str(args, "sidecar_base64")) {
        Some(text) => Some(
            bail!(B64
                .decode(text)
                .map_err(|_| Outcome::BadArguments("'sidecar_base64' is not valid base64".into()))),
        ),
        None => None,
    };

    let mut trusted_keys = Vec::new();
    if let Some(keys) = bail!(string_array(args, "trusted_keys_base64")) {
        for key in &keys {
            trusted_keys.push(bail!(public_key_ref_from_base64(key, "trusted_keys_base64")));
        }
    }
    let mut policy = TrustPolicy::new(trusted_keys);

    let requirement_items: &[Value] = match args.get("require_assertion_signers") {
        None | Some(Value::Null) => &[],
        Some(Value::Array(items)) => items.as_slice(),
        Some(other) => {
            return Outcome::BadArguments(format!(
                "'require_assertion_signers' must be an array of objects, received {}",
                type_name(other)
            ))
        }
    };
    {
        for (index, item) in requirement_items.iter().enumerate() {
            let kind = match item.get("kind") {
                Some(Value::String(kind)) => kind.clone(),
                _ => {
                    return Outcome::BadArguments(format!(
                        "'require_assertion_signers[{index}].kind' is required and must be a string"
                    ))
                }
            };
            let key = match item.get("public_key_base64").and_then(|k| k.as_str()) {
                Some(key) => key,
                None => {
                    return Outcome::BadArguments(format!(
                        "'require_assertion_signers[{index}].public_key_base64' is required and must be a string"
                    ))
                }
            };
            let signer = bail!(public_key_ref_from_base64(
                key,
                "require_assertion_signers.public_key_base64"
            ));
            policy = policy.require(&kind, &signer);
        }
    }

    let carrier_ids = match bail!(string_array(args, "carriers")) {
        Some(list) => bail!(catalogue::normalise_carriers(&list).map_err(Outcome::BadArguments)),
        None => Vec::new(),
    };
    let carriers = bail!(build_carriers(&carrier_ids));
    let method_refs = as_refs(&carriers);

    let report = match verify_document(document, sidecar.as_deref(), &method_refs, &policy) {
        Ok(report) => report,
        Err(e) => return Outcome::refused("verification_refused", e.to_string()),
    };

    let provenance_holds = report.strongest.is_some() && report.unmet_requirements.is_empty();

    let mut report_value = serde_json::to_value(&report).unwrap_or(Value::Null);
    // Re-encode each claim's signer key as base64, so the report reads keys the
    // same way a caller supplies them to this surface.
    if let Some(claims) = report_value
        .get_mut("claims")
        .and_then(|claims| claims.as_array_mut())
    {
        for claim in claims.iter_mut() {
            let signer_base64 = claim
                .get("signer")
                .and_then(signer_base64_from_ref);
            if let (Some(base64), Some(object)) = (signer_base64, claim.as_object_mut()) {
                object.insert("signer_public_key_base64".into(), json!(base64));
            }
        }
    }
    if let Some(object) = report_value.as_object_mut() {
        object.insert("provenance_holds".into(), json!(provenance_holds));
        object.insert("carriers_read".into(), json!(carrier_ids));
        object.insert("note".into(), json!(PROVENANCE_NOTE));
    }

    Outcome::Done(report_value)
}

// ─────────────────────────────────────────────────────────────
// Document sovereignty (the AI-regulation tool)
// ─────────────────────────────────────────────────────────────
//
// Two questions about a document a person holds: what marks are on it, and,
// for the classes they choose, remove exactly those and leave the rest byte
// for byte. Both delegate to the frozen core and report exactly what it
// returns, honest residual note included. The file side reads a C2PA content
// credential and reports only what the conformant reader validated.

/// Every mark-class identifier this tool recognises, in canonical order.
fn mark_class_ids() -> Vec<&'static str> {
    MarkClass::ALL.iter().map(|class| class.id()).collect()
}

/// Resolve the chosen mark classes, defaulting to every removable class when
/// the caller names none. An unknown identifier is refused by name rather than
/// silently dropped.
fn mark_classes_from(args: &Value) -> Result<Vec<MarkClass>, Outcome> {
    match string_array(args, "classes")? {
        None => Ok(MarkClass::ALL.to_vec()),
        Some(list) => {
            let mut classes = Vec::with_capacity(list.len());
            for id in &list {
                match MarkClass::from_id(id) {
                    Some(class) => classes.push(class),
                    None => {
                        return Err(Outcome::BadArguments(format!(
                            "unknown mark class '{id}': known classes are {}",
                            mark_class_ids().join(", ")
                        )))
                    }
                }
            }
            Ok(classes)
        }
    }
}

fn run_document_inspect(args: &Value) -> Outcome {
    let document = bail!(required_str(args, "document"));
    match serde_json::to_value(sovereignty::inspect(document)) {
        Ok(report) => Outcome::Done(report),
        Err(e) => Outcome::refused("report_unavailable", e.to_string()),
    }
}

fn run_document_clean(args: &Value) -> Outcome {
    let document = bail!(required_str(args, "document"));
    let classes = bail!(mark_classes_from(args));
    match serde_json::to_value(sovereignty::clean(document, &classes)) {
        Ok(report) => Outcome::Done(report),
        Err(e) => Outcome::refused("report_unavailable", e.to_string()),
    }
}

/// Resolve a [`FileFormat`] from a caller's hint: an extension, a filename, or
/// a leading-dot extension. The file layer's own named error is surfaced when the
/// hint names a format it cannot read, so an unsupported input refuses by name
/// rather than returning empty (invariant 2).
fn file_format_from(args: &Value) -> Result<FileFormat, Outcome> {
    let hint = required_str(args, "format")?;
    // Reduce a filename or a dotted hint to its extension; a bare extension is
    // left as-is. The file layer maps the extension to a format or refuses.
    let ext = hint.rsplit(['.', '/', '\\']).next().unwrap_or(hint).trim();
    FileFormat::from_extension(ext)
        .map_err(|e| Outcome::refused("file_unsupported_format", e.to_string()))
}

fn run_file_inspect(args: &Value) -> Outcome {
    let bytes = bail!(required_base64(args, "file_base64"));
    let format = bail!(file_format_from(args));
    let report = match inspect_file(&bytes, format) {
        Ok(report) => report,
        // Extraction that could not keep its promise names itself; it is a
        // refusal, never a silent empty report (invariant 2).
        Err(e) => return Outcome::refused("file_unreadable", e.to_string()),
    };
    let mut value = match serde_json::to_value(report) {
        Ok(value) => value,
        Err(e) => return Outcome::refused("report_unavailable", e.to_string()),
    };
    if let Value::Object(map) = &mut value {
        map.insert("format".into(), json!(format.name()));
    }
    Outcome::Done(value)
}

fn run_file_clean(args: &Value) -> Outcome {
    let bytes = bail!(required_base64(args, "file_base64"));
    let format = bail!(file_format_from(args));
    let classes = bail!(mark_classes_from(args));
    let outcome = match clean_file(&bytes, format, &classes) {
        Ok(outcome) => outcome,
        // A refusal by name: unsupported combination, lossy encoding, HTML clean,
        // or a write-back that did not round-trip. The transform's own message is
        // surfaced unchanged.
        Err(e) => return Outcome::refused("file_clean_refused", e.to_string()),
    };

    // The cleaned text is only the document itself for the text-native formats.
    // For a container it is a rendering of the text, not the file, so it is not
    // presented as the cleaned document; the base64 bytes are the cleaned file.
    let text_native = matches!(format, FileFormat::Markdown | FileFormat::PlainText);
    let removed = match serde_json::to_value(&outcome.removed) {
        Ok(value) => value,
        Err(e) => return Outcome::refused("report_unavailable", e.to_string()),
    };

    Outcome::Done(json!({
        "format": format.name(),
        "altered": outcome.altered,
        "removed": removed,
        "residual": outcome.residual,
        "cleaned_file_base64": B64.encode(&outcome.bytes),
        "byte_count": outcome.bytes.len(),
        "cleaned_text": if text_native { json!(outcome.cleaned_text) } else { Value::Null },
    }))
}

fn run_file_strip(args: &Value) -> Outcome {
    let bytes = bail!(required_base64(args, "file_base64"));
    let format = bail!(file_format_from(args));
    // Strip the metadata surfaces, content byte-identical. A format with no
    // strippable metadata surface names itself; it is a refusal, never a silent
    // unchanged return (invariant 2).
    let outcome = match strip_file(&bytes, format) {
        Ok(outcome) => outcome,
        Err(e) => return Outcome::refused("file_strip_refused", e.to_string()),
    };
    Outcome::Done(json!({
        "format": format.name(),
        "altered": outcome.altered,
        "content_identical": outcome.content_identical,
        "stripped_file_base64": B64.encode(&outcome.bytes),
        "byte_count": outcome.bytes.len(),
    }))
}

fn run_file_pristine(args: &Value) -> Outcome {
    let bytes = bail!(required_base64(args, "file_base64"));
    let format = bail!(file_format_from(args));
    // Pristine-clean a text-native document in full; a container or markup format
    // names itself as an unsupported combination (invariant 2).
    let outcome = match pristine_file(&bytes, format) {
        Ok(outcome) => outcome,
        Err(e) => return Outcome::refused("file_pristine_refused", e.to_string()),
    };
    let class_removed = match serde_json::to_value(&outcome.class_removed) {
        Ok(value) => value,
        Err(e) => return Outcome::refused("report_unavailable", e.to_string()),
    };
    Outcome::Done(json!({
        "format": format.name(),
        "altered": outcome.altered,
        "class_removed": class_removed,
        "invisibles_removed": outcome.invisibles_removed,
        "notes": outcome.notes,
        "cleaned_file_base64": B64.encode(&outcome.bytes),
        "byte_count": outcome.bytes.len(),
        "cleaned_text": outcome.cleaned_text,
    }))
}

fn run_pqc_keypair(_args: &Value) -> Outcome {
    let kp = crypto::pqc::generate_keypair();
    Outcome::Done(json!({
        "public_key_base64": B64.encode(&kp.public),
        "secret_key_base64": B64.encode(&kp.secret),
        "note": "post-quantum recipient keypair (ML-KEM-768). The secret half is returned once and kept nowhere by this surface; store it yourself. Give the public half to anyone who needs to seal a secret to you.",
    }))
}

fn run_pqc_seal(args: &Value) -> Outcome {
    let recipient_public = bail!(required_base64(args, "recipient_public_key_base64"));
    let text = bail!(required_str(args, "text"));
    match crypto::pqc::seal(&recipient_public, text.as_bytes()) {
        Ok(sealed) => Outcome::Done(json!({
            "sealed_base64": B64.encode(&sealed),
            "note": "sealed to the recipient's public key with ML-KEM-768 and AES-256-GCM. Only the matching secret key opens it. It is ordinary base64; hide it in a cover text with conceal to send it inside a plain message.",
        })),
        Err(e) => Outcome::refused("pqc_seal_refused", e.to_string()),
    }
}

fn run_pqc_open(args: &Value) -> Outcome {
    let secret = bail!(required_base64(args, "secret_key_base64"));
    let sealed = bail!(required_base64(args, "sealed_base64"));
    match crypto::pqc::open(&secret, &sealed) {
        Ok(plaintext) => match String::from_utf8(plaintext) {
            Ok(text) => Outcome::Done(json!({ "text": text })),
            Err(e) => Outcome::Done(json!({
                "plaintext_base64": B64.encode(e.into_bytes()),
                "note": "the opened bytes are not valid UTF-8 text; returned as base64.",
            })),
        },
        Err(e) => Outcome::refused("pqc_open_refused", e.to_string()),
    }
}

/// Resolve a conversion TARGET from the caller's `target` hint (an extension, a
/// filename, or a dotted extension). A target this build cannot write is refused
/// BY NAME rather than attempted (invariant 2); the refusal lists what can be
/// produced.
fn convert_target_from(args: &Value) -> Result<FileFormat, Outcome> {
    let hint = required_str(args, "target")?;
    let ext = hint.rsplit(['.', '/', '\\']).next().unwrap_or(hint).trim();
    target_from_extension(ext).ok_or_else(|| {
        Outcome::refused(
            "file_convert_unsupported_target",
            format!(
                "converting to '{ext}' is not a supported conversion target in this build; the supported targets are {}, and pdf when a local browser is available",
                supported_target_names().join(", ")
            ),
        )
    })
}

/// The names of the pure-Rust conversion targets this build can write, taken from
/// the engine's own list so the surface never advertises a target it lacks.
fn supported_target_names() -> Vec<&'static str> {
    supported_targets().into_iter().map(|f| f.name()).collect()
}

/// Report the presence of the additive metadata channel for the formats that
/// carry one (DOCX, PNG, SVG); `Null` for a format that has no such channel. A
/// present-but-unreadable channel is named, never reported absent (invariant 2).
fn embedded_channel_view(bytes: &[u8], format: FileFormat) -> Value {
    if !matches!(format, FileFormat::Docx | FileFormat::Png | FileFormat::Svg) {
        return Value::Null;
    }
    match recover_metadata(bytes, format) {
        Ok(Some(payload)) => json!({ "present": true, "byte_count": payload.len() }),
        Ok(None) => json!({ "present": false }),
        Err(e) => json!({ "present": false, "unreadable": e.to_string() }),
    }
}

fn run_file_analyze(args: &Value) -> Outcome {
    let bytes = bail!(required_base64(args, "file_base64"));
    let format = bail!(file_format_from(args));
    // Extract the document's own text, then run the same analysis the `analyze`
    // command runs over a text argument. A format whose text cannot be read names
    // itself; it is a refusal, never a silent empty report (invariant 2).
    let extracted = match extract_text(&bytes, format) {
        Ok(extracted) => extracted,
        Err(e) => return Outcome::refused("file_unreadable", e.to_string()),
    };
    match serde_json::to_value(forensic::analyze(&extracted.text)) {
        Ok(mut report) => {
            if let Value::Object(map) = &mut report {
                map.insert("format".into(), json!(format.name()));
            }
            Outcome::Done(report)
        }
        Err(e) => Outcome::refused("report_unavailable", e.to_string()),
    }
}

/// Decode exactly 32 bytes from 64 hex characters, or `None`.
fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[2 * i] as char).to_digit(16)?;
        let lo = (bytes[2 * i + 1] as char).to_digit(16)?;
        *slot = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

fn run_wordmark_analyze(args: &Value) -> Outcome {
    let text = bail!(required_str(args, "text"));
    let mut opts = stegano_wm::AnalyzeOptions::default();
    if let Some(target) = args.get("acrostic_target").and_then(Value::as_str) {
        if !target.is_empty() {
            opts.acrostic_target = Some(target.to_string());
        }
    }
    if let Some(hex) = args.get("mark_key_hex").and_then(Value::as_str) {
        match decode_hex_32(hex) {
            Some(key) => opts.our_key = Some(key),
            None => {
                return Outcome::BadArguments(
                    "mark_key_hex must be 64 hex characters (32 bytes)".into(),
                )
            }
        }
    }
    match serde_json::to_value(stegano_wm::analyze(text, &opts)) {
        Ok(report) => Outcome::Done(report),
        Err(e) => Outcome::refused("report_unavailable", e.to_string()),
    }
}

fn run_wordmark_scrub(args: &Value) -> Outcome {
    let text = bail!(required_str(args, "text"));
    let aggression = match args.get("aggression").and_then(Value::as_str).unwrap_or("medium") {
        "light" => stegano_wm::Aggression::Light,
        "medium" => stegano_wm::Aggression::Medium,
        "heavy" => stegano_wm::Aggression::Heavy,
        other => {
            return Outcome::BadArguments(format!(
                "aggression must be light, medium, or heavy, not '{other}'"
            ))
        }
    };
    let report = stegano_wm::scrub_synonyms(text, aggression);
    Outcome::Done(json!({
        "text": report.text,
        "synonym_positions": report.positions_total,
        "positions_changed": report.positions_changed,
        "note": "Best-effort disruption by changing synonym choices, done locally. This is not a removal and makes no guarantee; a word-choice watermark can only be reduced by rewriting.",
    }))
}

fn run_wordmark_online_disclaimer(_args: &Value) -> Outcome {
    // Option (b), owner decision 2026-08-27: the surface returns the interface
    // KEYS, and the consumer (the GUI, or a driving agent with locale access)
    // resolves them in the user's language. The keys are defined in the locale
    // catalogues and held there by a guardrail test.
    Outcome::Done(json!({
        "requires_disclaimer": true,
        "title_key": "wordmark.online.title",
        "disclaimer_key": "wordmark.online.disclaimer",
        "acknowledge_key": "wordmark.online.acknowledge",
        "instruction": "Resolve these interface keys in the user's language and show the disclaimer as a frame or an artifact before sending the text to an online model. Proceed only after the user acknowledges. After the online rewrite, run a local re-clean on the result.",
    }))
}

fn run_file_conceal(args: &Value) -> Outcome {
    let bytes = bail!(required_base64(args, "file_base64"));
    let format = bail!(file_format_from(args));
    let payload = bail!(payload_from(args, "secret", "secret_base64"));
    if payload.is_empty() {
        return Outcome::BadArguments("the secret must not be empty".into());
    }
    // The file conceal places a text secret into the document's own text, so the
    // secret must be valid UTF-8. A non-text payload is refused by name rather
    // than silently reinterpreted (invariant 2).
    let secret = match std::str::from_utf8(&payload) {
        Ok(secret) => secret,
        Err(_) => {
            return Outcome::BadArguments(
                "the secret must be valid UTF-8 text for a file conceal".into(),
            )
        }
    };
    let ids = bail!(carriers_from(args, &["zero_width"]));
    let built = bail!(build_carriers(&ids));
    let cipher = bail!(cipher_from(args));
    let saturate = bail!(optional_bool(args, "saturate", false));

    let carriers = as_refs(&built);
    let crypto: Option<(&dyn CryptoMethod, &str)> = cipher
        .as_ref()
        .map(|(method, passcode)| (method.as_ref(), passcode.as_str()));

    // The transform proves the round-trip internally (it re-extracts the written
    // bytes and requires the marked text back), so a returned result is a marked
    // file that reads back. A container, HTML or lowered format is refused BY
    // NAME by the engine; that refusal is surfaced unchanged (invariant 2).
    let outcome = match conceal_file(&bytes, format, secret, &carriers, crypto, saturate) {
        Ok(outcome) => outcome,
        Err(e) => return Outcome::refused("file_conceal_refused", e.to_string()),
    };

    Outcome::Done(json!({
        "format": outcome.format.name(),
        "marked_file_base64": B64.encode(&outcome.bytes),
        "byte_count": outcome.marked_len,
        "source_byte_count": outcome.source_len,
        "secret_bytes": outcome.secret_len,
        "carriers_used": outcome.carriers,
        "cipher": outcome.cipher,
        "marked_text": outcome.marked_text,
        "round_trip": { "verified": true },
    }))
}

fn run_file_convert(args: &Value) -> Outcome {
    let bytes = bail!(required_base64(args, "file_base64"));
    let source = bail!(file_format_from(args));
    let target = bail!(convert_target_from(args));
    // Conversion lowers the source to a Markdown waypoint and regenerates the
    // target; it is DECLARED LOSSY and never places a mark. A source that carries
    // no extractable text, an unsupported target, or a host with no browser for a
    // PDF target are each refused BY NAME by the engine (invariant 2).
    let converted = match convert_file(&bytes, source, target) {
        Ok(converted) => converted,
        Err(e) => return Outcome::refused("file_convert_refused", e.to_string()),
    };
    Outcome::Done(json!({
        "source_format": source.name(),
        "target_format": target.name(),
        "converted_file_base64": B64.encode(&converted),
        "byte_count": converted.len(),
        "source_byte_count": bytes.len(),
        "lossy": true,
        "note": "conversion is declared lossy and never places a mark; the bytes are the engine's real output.",
    }))
}

fn run_file_metadata(args: &Value) -> Outcome {
    let bytes = bail!(required_base64(args, "file_base64"));
    let format = bail!(file_format_from(args));
    match format {
        // Office documents: the format's own standard metadata (docProps / meta).
        FileFormat::Docx | FileFormat::Odt => {
            let native = match read_native_metadata(&bytes, format) {
                Ok(native) => native,
                Err(e) => return Outcome::refused("file_metadata_refused", e.to_string()),
            };
            let native = match serde_json::to_value(native) {
                Ok(value) => value,
                Err(e) => return Outcome::refused("report_unavailable", e.to_string()),
            };
            Outcome::Done(json!({
                "format": format.name(),
                "kind": "document",
                "native_metadata": native,
                "embedded_channel": embedded_channel_view(&bytes, format),
            }))
        }
        // Images: the EXIF and XMP the image declares.
        FileFormat::Jpeg | FileFormat::Tiff | FileFormat::Png | FileFormat::Webp => {
            let image = match read_image_metadata(&bytes, format) {
                Ok(image) => image,
                Err(e) => return Outcome::refused("file_metadata_refused", e.to_string()),
            };
            let image = match serde_json::to_value(image) {
                Ok(value) => value,
                Err(e) => return Outcome::refused("report_unavailable", e.to_string()),
            };
            Outcome::Done(json!({
                "format": format.name(),
                "kind": "image",
                "image_metadata": image,
                "embedded_channel": embedded_channel_view(&bytes, format),
            }))
        }
        // SVG carries no EXIF or docProps, only the additive channel; report just
        // that presence rather than an empty standard-metadata block.
        FileFormat::Svg => Outcome::Done(json!({
            "format": format.name(),
            "kind": "vector_image",
            "embedded_channel": embedded_channel_view(&bytes, format),
        })),
        // Every other format carries no metadata this tool reads: refuse BY NAME
        // rather than return an empty result (invariant 2).
        other => Outcome::refused(
            "file_metadata_unsupported",
            format!(
                "the {} format carries no metadata this tool reads; metadata reading serves Office documents (docx, odt), images (jpeg, tiff, png, webp), and svg",
                other.name()
            ),
        ),
    }
}

fn run_c2pa_inspect(args: &Value) -> Outcome {
    let bytes = bail!(required_base64(args, "file_base64"));
    let format_hint = bail!(optional_str(args, "format_hint"));
    match c2pa_read::inspect_c2pa(&bytes, format_hint) {
        Ok(report) => match serde_json::to_value(report) {
            Ok(value) => Outcome::Done(value),
            Err(e) => Outcome::refused("report_unavailable", e.to_string()),
        },
        // A file with no credential is an ordinary Absent report, not this
        // path: only a genuine failure to read the bytes as an asset arrives
        // here, and it names itself.
        Err(e) => Outcome::refused("c2pa_unreadable", e.to_string()),
    }
}

fn run_measure_text(args: &Value) -> Outcome {
    let text = bail!(required_str(args, "text"));
    let reference = bail!(optional_str(args, "reference"));

    let mut report = json!({
        "chars": text.chars().count(),
        "bytes": text.len(),
        "information_density": metrics::shannon_entropy(text),
        "non_writing_share": metrics::noise_density(text),
        "lookalike_share": metrics::homoglyph_density(text),
    });

    if let Some(reference) = reference {
        let delta = metrics::compute_metrics(reference, text);
        report["change_from_reference"] = json!({
            "information_density_delta": delta.shannon_delta,
            "combined_density": delta.noise_density,
            "estimated_model_impact": delta.perplexity_delta,
            "note": "estimated_model_impact is a local estimate derived from character density, not a measurement against any external service.",
        });
    }

    Outcome::Done(report)
}

/// Resolve one side of a two-input operation from either a text field or a file
/// field with its format. Exactly one must be given. This gives the two-input
/// comparison the same uniform file input the single-text tools get, which the
/// shared resolver could not (it acts on one primary field).
fn resolve_side(
    args: &Value,
    text_key: &str,
    file_key: &str,
    format_key: &str,
) -> Result<String, Outcome> {
    match (optional_str(args, text_key)?, args.get(file_key)) {
        (Some(text), None) => Ok(text.to_string()),
        (None, Some(_)) => {
            let bytes = required_base64(args, file_key)?;
            let hint = required_str(args, format_key)?;
            let ext = hint.rsplit(['.', '/', '\\']).next().unwrap_or(hint).trim();
            let format = FileFormat::from_extension(ext)
                .map_err(|e| Outcome::refused("file_unsupported_format", e.to_string()))?;
            extract_text(&bytes, format)
                .map(|extracted| extracted.text)
                .map_err(|e| Outcome::refused("file_unreadable", e.to_string()))
        }
        (Some(_), Some(_)) => Err(Outcome::BadArguments(format!(
            "supply either '{text_key}' or '{file_key}', not both"
        ))),
        (None, None) => Err(Outcome::BadArguments(format!(
            "supply '{text_key}' or a document via '{file_key}'"
        ))),
    }
}

fn run_compare_texts(args: &Value) -> Outcome {
    let left = bail!(resolve_side(args, "left", "left_file_base64", "left_format"));
    let right = bail!(resolve_side(args, "right", "right_file_base64", "right_format"));

    let left_report = forensic::analyze(&left);
    let right_report = forensic::analyze(&right);

    let mut only_in_right = Map::new();
    for (name, count) in &right_report.unicode_analysis.invisible_breakdown {
        let before = left_report
            .unicode_analysis
            .invisible_breakdown
            .get(name)
            .copied()
            .unwrap_or(0);
        if *count > before {
            only_in_right.insert(name.clone(), json!(count - before));
        }
    }
    let mut only_in_left = Map::new();
    for (name, count) in &left_report.unicode_analysis.invisible_breakdown {
        let after = right_report
            .unicode_analysis
            .invisible_breakdown
            .get(name)
            .copied()
            .unwrap_or(0);
        if *count > after {
            only_in_left.insert(name.clone(), json!(count - after));
        }
    }

    let delta = metrics::compute_metrics(&left, &right);

    Outcome::Done(json!({
        "identical": left == right,
        "left": {
            "chars": left.chars().count(),
            "verdict": left_report.verdict.to_string(),
            "suspicion_score": left_report.suspicion_score,
            "non_writing_chars": left_report.unicode_analysis.invisible_chars,
            "lookalike_share": left_report.statistics.homoglyph_density,
        },
        "right": {
            "chars": right.chars().count(),
            "verdict": right_report.verdict.to_string(),
            "suspicion_score": right_report.suspicion_score,
            "non_writing_chars": right_report.unicode_analysis.invisible_chars,
            "lookalike_share": right_report.statistics.homoglyph_density,
        },
        "gained_by_right": only_in_right,
        "lost_by_right": only_in_left,
        "information_density_delta": delta.shannon_delta,
        "visible_text_identical": strip_all(&left) == strip_all(&right),
    }))
}

/// The text with every registered carrier's alphabet removed, used only to
/// answer whether two texts read the same to a person.
fn strip_all(text: &str) -> String {
    let mut current = text.to_string();
    for carrier in catalogue::all_carriers() {
        current = carrier.strip(&current);
    }
    current
}

fn run_protect_payload(args: &Value) -> Outcome {
    let payload = bail!(payload_from(args, "plaintext", "plaintext_base64"));
    let cipher_id = bail!(required_str(args, "cipher"));
    if cipher_id == CIPHER_NONE {
        return Outcome::BadArguments(
            "'cipher' must name a confidentiality layer: there is nothing to do with 'none'".into(),
        );
    }
    let cipher = bail!(catalogue::cipher(cipher_id).map_err(Outcome::BadArguments));
    let passcode = bail!(required_str(args, "passcode"));
    if passcode.is_empty() {
        return Outcome::BadArguments("'passcode' must not be empty".into());
    }

    match cipher.encrypt(&payload, passcode) {
        Ok(protected) => Outcome::Done(json!({
            "cipher": cipher.id(),
            "protected_base64": B64.encode(&protected),
            "plaintext_bytes": payload.len(),
            "protected_bytes": protected.len(),
        })),
        Err(e) => Outcome::refused("protection_refused", e.to_string()),
    }
}

fn run_unprotect_payload(args: &Value) -> Outcome {
    let protected = bail!(required_base64(args, "protected_base64"));
    let cipher_id = bail!(required_str(args, "cipher"));
    let cipher = bail!(catalogue::cipher(cipher_id).map_err(Outcome::BadArguments));
    let passcode = bail!(required_str(args, "passcode"));

    match cipher.decrypt(&protected, passcode) {
        Ok(plaintext) => Outcome::Done(json!({
            "cipher": cipher.id(),
            "plaintext": payload_view(&plaintext),
        })),
        Err(e) => Outcome::refused("opening_refused", e.to_string()),
    }
}

fn run_compress_payload(args: &Value) -> Outcome {
    let payload = bail!(payload_from(args, "plaintext", "plaintext_base64"));
    let level = bail!(optional_u64(args, "level", 6));
    if level > 9 {
        return Outcome::BadArguments("'level' must be between 0 and 9".into());
    }

    match Compression::new().compress(&payload, level as u32) {
        Ok(compressed) => Outcome::Done(json!({
            "compressed_base64": B64.encode(&compressed),
            "original_bytes": payload.len(),
            "compressed_bytes": compressed.len(),
            "ratio": if payload.is_empty() { 0.0 } else { compressed.len() as f64 / payload.len() as f64 },
        })),
        Err(e) => Outcome::refused("compression_refused", e.to_string()),
    }
}

fn run_expand_payload(args: &Value) -> Outcome {
    let compressed = bail!(required_base64(args, "compressed_base64"));
    match Compression::new().decompress(&compressed) {
        Ok(expanded) => Outcome::Done(json!({
            "plaintext": payload_view(&expanded),
            "compressed_bytes": compressed.len(),
        })),
        Err(e) => Outcome::refused("expansion_refused", e.to_string()),
    }
}

fn run_attach_payload(args: &Value) -> Outcome {
    let text = bail!(required_str(args, "text"));
    let filename = bail!(required_str(args, "filename"));
    if filename.contains('|') {
        return Outcome::BadArguments("'filename' must not contain the character |".into());
    }
    let data = bail!(required_base64(args, "data_base64"));

    match FileEmbed::new().embed(text, filename, &data) {
        Ok(combined) => Outcome::Done(json!({
            "text": combined,
            "filename": filename,
            "attached_bytes": data.len(),
            "chars_before": text.chars().count(),
            "chars_after": combined.chars().count(),
        })),
        Err(e) => Outcome::refused("attachment_refused", e.to_string()),
    }
}

fn run_list_attachments(args: &Value) -> Outcome {
    let text = bail!(required_str(args, "text"));
    let embedder = FileEmbed::new();
    let files: Vec<Value> = embedder
        .extract(text)
        .into_iter()
        .map(|file| {
            json!({
                "filename": file.name,
                "byte_count": file.data.len(),
                "data_base64": B64.encode(&file.data),
            })
        })
        .collect();

    Outcome::Done(json!({
        "present": embedder.detect(text),
        "count": files.len(),
        "files": files,
    }))
}

fn run_detach_payload(args: &Value) -> Outcome {
    let text = bail!(required_str(args, "text"));
    let embedder = FileEmbed::new();
    let stripped = embedder.strip(text);
    Outcome::Done(json!({
        "text": stripped,
        "removed_count": embedder.extract(text).len(),
        "changed": stripped != text,
    }))
}

/// Output formats offered by `render`.
pub const RENDER_FORMATS: [&str; 6] = ["plain", "markdown", "html", "json", "base64", "data_uri"];

fn run_render(args: &Value) -> Outcome {
    let text = bail!(required_str(args, "text"));
    let format = bail!(optional_str(args, "format")).unwrap_or("plain");
    let title = bail!(optional_str(args, "title"));
    let include_report = bail!(optional_bool(args, "include_report", true));

    if !RENDER_FORMATS.contains(&format) {
        return Outcome::BadArguments(format!(
            "unknown format '{format}': the available formats are {}",
            RENDER_FORMATS.join(", ")
        ));
    }

    let output = match format {
        "plain" => text.to_string(),
        "markdown" => match title {
            Some(title) => format!("# {}\n\n{text}\n", escape_markdown_heading(title)),
            None => format!("{text}\n"),
        },
        "html" => {
            let body = escape_html(text);
            match title {
                Some(title) => format!(
                    "<article>\n<h1>{}</h1>\n<pre>{body}</pre>\n</article>\n",
                    escape_html(title)
                ),
                None => format!("<article>\n<pre>{body}</pre>\n</article>\n"),
            }
        }
        "json" => match serde_json::to_string_pretty(&json!({ "title": title, "text": text })) {
            Ok(rendered) => rendered,
            Err(e) => return Outcome::refused("render_refused", e.to_string()),
        },
        "base64" => B64.encode(text.as_bytes()),
        "data_uri" => format!(
            "data:text/plain;charset=utf-8;base64,{}",
            B64.encode(text.as_bytes())
        ),
        _ => unreachable!("the format list is checked above"),
    };

    let mut rendered = json!({
        "format": format,
        "output": output,
        "integrity": {
            "sha256": sha256_hex(text.as_bytes()),
            "chars": text.chars().count(),
            "bytes": text.len(),
        },
    });

    if include_report {
        let report = forensic::analyze(text);
        rendered["report"] = json!({
            "verdict": report.verdict.to_string(),
            "suspicion_score": report.suspicion_score,
            "carriers_responding": report
                .stego_signatures
                .iter()
                .map(|s| s.method.clone())
                .collect::<Vec<_>>(),
            "note": "this is what an analysis of the rendered text reports. It describes what is being handed over.",
        });
    }

    Outcome::Done(rendered)
}

/// Export a result string to a chosen document format, returned as base64 bytes to
/// save as a file. This is the universal-export point: any tool's text result, or a
/// document's text via file_base64, becomes a downloadable file. Plain text and
/// Markdown are byte-faithful; a container or PDF, or an unknown target, is refused
/// by name (invariant 2).
fn run_export(args: &Value) -> Outcome {
    let text = bail!(required_str(args, "text"));
    let target_hint = bail!(required_str(args, "target"));
    // Reduce a filename or dotted hint to its extension, the same way the file
    // format hint is resolved, so "report.rtf" and "rtf" both work.
    let ext = target_hint
        .rsplit(['.', '/', '\\'])
        .next()
        .unwrap_or(target_hint)
        .trim()
        .to_ascii_lowercase();
    let target = match target_from_extension(&ext) {
        Some(target) => target,
        None => {
            return Outcome::BadArguments(format!(
                "unknown export target '{target_hint}': choose one of {}",
                export_target_names()
            ))
        }
    };

    match export_text(text, target) {
        Ok(bytes) => {
            let mut out = json!({
                "target": ext,
                "exported_base64": B64.encode(&bytes),
                "bytes": bytes.len(),
            });
            // The byte-faithful targets are also handed back as text, so a caller
            // can copy the result directly as well as save it.
            if matches!(target, FileFormat::PlainText | FileFormat::Markdown) {
                if let Value::Object(map) = &mut out {
                    map.insert("text".into(), json!(text));
                    map.insert("byte_faithful".into(), json!(true));
                }
            }
            Outcome::Done(out)
        }
        // A container, PDF, or a writer that could not keep its promise names
        // itself rather than returning an empty file.
        Err(e) => Outcome::refused("export_refused", e.to_string()),
    }
}

/// The export target extensions offered by [`run_export`], for the error message
/// and the schema. The pure-Rust waypoint writers only; PDF and the binary
/// containers are refused by name.
fn export_target_names() -> String {
    let mut names: Vec<&str> = supported_targets()
        .iter()
        .filter_map(|format| export_extension(*format))
        .collect();
    // PDF is an export target too, through the native writer, though it is not one
    // of convert's pure-Rust waypoint targets.
    names.push("pdf");
    names.join(", ")
}

/// The canonical output extension for a supported export target.
fn export_extension(format: FileFormat) -> Option<&'static str> {
    Some(match format {
        FileFormat::Markdown => "md",
        FileFormat::Html => "html",
        FileFormat::PlainText => "txt",
        FileFormat::Latex => "tex",
        FileFormat::Rtf => "rtf",
        FileFormat::Org => "org",
        FileFormat::Rst => "rst",
        FileFormat::AsciiDoc => "asciidoc",
        FileFormat::Ipynb => "ipynb",
        FileFormat::Typst => "typ",
        _ => return None,
    })
}

fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

fn escape_markdown_heading(text: &str) -> String {
    text.replace('\n', " ").replace('\r', " ")
}

fn run_settings_read(store: &SettingsStore) -> Outcome {
    Outcome::Done(json!({
        "settings": store.settings().public_view(),
        "constraints": Settings::constraints(),
    }))
}

fn run_settings_update(args: &Value, store: &mut SettingsStore) -> Outcome {
    let update = match args.get("settings") {
        Some(value) => value.clone(),
        None => return Outcome::BadArguments("'settings' is required".into()),
    };

    match store.apply(&update) {
        Ok(()) => Outcome::Done(json!({
            "applied": true,
            "settings": store.settings().public_view(),
        })),
        Err(rejections) => {
            let rendered = serde_json::to_value(&rejections).unwrap_or(Value::Null);
            let summary = rejections
                .iter()
                .map(|r| format!("{}: {}", r.field, r.reason))
                .collect::<Vec<_>>()
                .join("; ");
            Outcome::Refused {
                code: "settings_rejected",
                reason: format!(
                    "nothing was changed. {} field(s) refused. {summary}. Detail: {rendered}",
                    rejections.len()
                ),
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Parameter schemas
// ─────────────────────────────────────────────────────────────

fn object_schema(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    })
}

fn carriers_property(description: &str) -> Value {
    json!({
        "type": "array",
        "items": { "type": "string", "enum": catalogue::CARRIER_ORDER },
        "description": description,
    })
}

fn cipher_property() -> Value {
    let mut options: Vec<&str> = catalogue::CIPHER_ORDER.to_vec();
    options.push(CIPHER_NONE);
    json!({
        "type": "string",
        "enum": options,
        "description": "Confidentiality layer to apply. Defaults to none.",
    })
}

fn schema_capabilities_list() -> Value {
    object_schema(json!({}), &[])
}

fn schema_chain_validate() -> Value {
    object_schema(
        json!({
            "carriers": carriers_property("The carriers to combine."),
            "preserve_order": { "type": "boolean", "description": "Check the selection exactly as given instead of putting it into application order first. Defaults to false." },
        }),
        &["carriers"],
    )
}

fn schema_capacity_report() -> Value {
    object_schema(
        json!({
            "cover": { "type": "string", "description": "The text the payload would go into." },
            "carriers": carriers_property("Limit the report to these carriers. Defaults to all of them."),
            "robust": { "type": "boolean", "description": "Report against the heavy, recovery-robust frame instead of the light default. Defaults to false." },
        }),
        &["cover"],
    )
}

fn schema_recommend_settings() -> Value {
    object_schema(
        json!({
            "cover": { "type": "string", "description": "The text the secret would go into." },
            "secret": { "type": "string", "description": "The secret, as text. Supply this or secret_base64." },
            "secret_base64": { "type": "string", "description": "The secret, as bytes. Supply this or secret." },
            "carriers": carriers_property("Carriers to weigh. Defaults to all of them, so the best one is suggested."),
            "cipher": cipher_property(),
            "passcode": { "type": "string", "description": "Optional. Included in the size so the recommendation accounts for the cipher's overhead. Never logged." },
            "robust": { "type": "boolean", "description": "Weigh against the heavy, recovery-robust frame instead of the light default. Defaults to false." },
        }),
        &["cover"],
    )
}

fn schema_conceal() -> Value {
    object_schema(
        json!({
            "cover": { "type": "string", "description": "The text the secret goes into." },
            "secret": { "type": "string", "description": "The secret, as text. Supply this or secret_base64." },
            "secret_base64": { "type": "string", "description": "The secret, as bytes. Supply this or secret." },
            "carriers": carriers_property("Carriers to use. Defaults to zero_width."),
            "cipher": cipher_property(),
            "passcode": { "type": "string", "description": "Required when a confidentiality layer is named. Never logged." },
            "recipient_public_key_base64": { "type": "string", "description": "Optional. A recipient's public key (from pqc_keypair). When given, the secret is sealed to that recipient with post-quantum encryption before it is hidden, so only their secret key can open what is concealed, with no shared passcode." },
            "require_round_trip": { "type": "boolean", "description": "Refuse to return a result that could not be read back. Defaults to true." },
            "robust": { "type": "boolean", "description": "Write the heavy, recovery-robust frame instead of the light default. It survives a partly damaged or excerpted document, at more overhead, so it needs more room for the same secret. Defaults to false." },
            "saturate": { "type": "boolean", "description": "Saturation mode: fill each named carrier's channel to its maximum with the secret repeated. The aggressive variant, still recoverable and still compatible with a cipher, that survives a heavy cut. Overrides robust. Defaults to false." },
        }),
        &["cover"],
    )
}

fn schema_reveal() -> Value {
    object_schema(
        json!({
            "text": { "type": "string", "description": "The text to read." },
            "carriers": carriers_property("Carriers to try. Defaults to all of them."),
            "cipher": cipher_property(),
            "passcode": { "type": "string", "description": "Needed when the content was protected. Never logged." },
            "recipient_secret_key_base64": { "type": "string", "description": "Optional. Your secret key (from pqc_keypair). When given, the recovered payload is opened as a secret sealed to you. A wrong key or any tampering is refused by name." },
            "accept_unverified": { "type": "boolean", "description": "Return content that failed its integrity check. Defaults to false." },
        }),
        &["text"],
    )
}

fn schema_roundtrip_check() -> Value {
    object_schema(
        json!({
            "cover": { "type": "string", "description": "The document to test the plan against." },
            "secret": { "type": "string", "description": "Optional test payload as text. A short built-in payload is used when neither is given." },
            "secret_base64": { "type": "string", "description": "Optional test payload as bytes." },
            "carriers": carriers_property("Carriers to test. Defaults to zero_width."),
            "cipher": cipher_property(),
            "passcode": { "type": "string", "description": "Required when a confidentiality layer is named. Never logged." },
        }),
        &["cover"],
    )
}

fn schema_inspect() -> Value {
    object_schema(
        json!({ "text": { "type": "string", "description": "The text to inspect." } }),
        &["text"],
    )
}

fn schema_analyze() -> Value {
    object_schema(
        json!({ "text": { "type": "string", "description": "The text to analyse." } }),
        &["text"],
    )
}

fn schema_sanitize() -> Value {
    object_schema(
        json!({
            "text": { "type": "string", "description": "The text to clean." },
            "channels": carriers_property("Which channels to clear. Defaults to those that leave visible characters untouched."),
            "allow_visible_text_rewrite": { "type": "boolean", "description": "Permit cleaning that rewrites visible characters. Defaults to false, and is still refused on a text that shows no sign of marking." },
        }),
        &["text"],
    )
}

fn schema_normalize_text() -> Value {
    object_schema(
        json!({
            "text": { "type": "string", "description": "The text to normalise." },
            "remove_accents": { "type": "boolean" },
            "lowercase": { "type": "boolean" },
            "collapse_whitespace": { "type": "boolean" },
            "remove_punctuation": { "type": "boolean" },
            "normalize_nfc": { "type": "boolean" },
            "accept_payload_loss": { "type": "boolean", "description": "Proceed even though the text is carrying something that will be destroyed. Defaults to false." },
        }),
        &["text"],
    )
}

fn schema_mark_batch() -> Value {
    object_schema(
        json!({
            "text": { "type": "string", "description": "The document to distribute." },
            "recipients": { "type": "array", "items": { "type": "string" }, "description": "One identifier per recipient." },
            "salt": { "type": "string", "description": "A value tying these copies to this distribution. Reuse it to reproduce the same copies." },
        }),
        &["text", "recipients", "salt"],
    )
}

fn schema_trace_origin() -> Value {
    object_schema(
        json!({
            "text": { "type": "string", "description": "The text that turned up." },
            "registry": { "type": "array", "items": { "type": "object" }, "description": "The registry returned by mark_batch, unchanged." },
        }),
        &["text", "registry"],
    )
}

fn schema_verify_mark() -> Value {
    object_schema(
        json!({
            "text": { "type": "string", "description": "The text to check." },
            "recipient_id": { "type": "string", "description": "The one recipient to check against." },
            "salt": { "type": "string", "description": "The value used when the copies were made." },
            "mark_bytes": { "type": "integer", "minimum": 1, "description": "The mark size reported when the copies were made." },
        }),
        &["text", "recipient_id", "salt", "mark_bytes"],
    )
}

fn schema_authorship_keypair() -> Value {
    object_schema(json!({}), &[])
}

fn schema_authorship_sign() -> Value {
    object_schema(
        json!({
            "cover": { "type": "string", "description": "The document to attach the claim to." },
            "author": { "type": "string", "description": "Who the document is claimed to come from." },
            "private_key_base64": { "type": "string", "description": "The private half of the authorship key pair. Never logged." },
            "carrier": { "type": "string", "enum": catalogue::CARRIER_ORDER, "description": "Which carrier holds the claim. Defaults to zero_width." },
            "scope": { "type": "array", "items": { "type": "string" }, "description": "What the claim covers. Defaults to everything." },
            "expires": { "type": "string", "description": "Optional expiry, as an ISO 8601 timestamp." },
            "organisation": { "type": "string", "description": "Optional organisation the claim is bound to." },
        }),
        &["cover", "author", "private_key_base64"],
    )
}

fn schema_authorship_verify() -> Value {
    object_schema(
        json!({
            "text": { "type": "string", "description": "The document to check." },
            "public_key_base64": { "type": "string", "description": "The public half of the author's key pair." },
            "carrier": { "type": "string", "enum": catalogue::CARRIER_ORDER, "description": "Which carrier to read the claim from. Defaults to zero_width." },
        }),
        &["text", "public_key_base64"],
    )
}

fn schema_provenance_sign() -> Value {
    object_schema(
        json!({
            "cover": { "type": "string", "description": "The document to attach the record to." },
            "assertions": {
                "type": "array",
                "items": { "type": "object" },
                "description": "One or more claims to state, freely combined. Each is an object with a 'kind': human_authorship (optional 'author'), ai_generated (optional 'model', 'provider', 'system_version', the Article 50 disclosure), integrity (bound to the document hash), or recipient_fingerprint (required 'recipient_id' and 'salt').",
            },
            "private_key_base64": { "type": "string", "description": "The private half of the signing identity. Never logged, never returned." },
            "binding": { "type": "string", "enum": ["detached", "in_band"], "description": "detached keeps the record in a sidecar beside the document; in_band carries it within the document itself. Defaults to detached." },
            "carrier": { "type": "string", "enum": catalogue::CARRIER_ORDER, "description": "Which carrier holds an in-band record. Defaults to zero_width." },
            "created": { "type": "string", "description": "Optional creation timestamp, as an ISO 8601 string." },
        }),
        &["cover", "assertions", "private_key_base64"],
    )
}

fn schema_provenance_verify() -> Value {
    object_schema(
        json!({
            "document": { "type": "string", "description": "The document to check." },
            "sidecar_base64": { "type": "string", "description": "The detached record kept beside the document, if there is one." },
            "trusted_keys_base64": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Public keys the verifier trusts. A record signed by a key outside this set is reported present but untrusted.",
            },
            "carriers": carriers_property("Carriers to read an in-band record from. Defaults to reading the detached record only."),
            "require_assertion_signers": {
                "type": "array",
                "items": { "type": "object" },
                "description": "Optional per-claim signer policy. Each is an object with a 'kind' and the 'public_key_base64' that must have signed it, so a claim signed by another key is not accepted for that kind.",
            },
        }),
        &["document"],
    )
}

fn schema_document_inspect() -> Value {
    object_schema(
        json!({
            "document": { "type": "string", "description": "The document to inspect." },
        }),
        &["document"],
    )
}

fn schema_document_clean() -> Value {
    object_schema(
        json!({
            "document": { "type": "string", "description": "Your own document to clean." },
            "classes": {
                "type": "array",
                "items": { "type": "string", "enum": mark_class_ids() },
                "description": "Which mark classes to remove. Defaults to every class this tool can remove.",
            },
        }),
        &["document"],
    )
}

fn schema_file_inspect() -> Value {
    object_schema(
        json!({
            "file_base64": { "type": "string", "description": "The document's bytes, base64 encoded." },
            "format": { "type": "string", "description": "The document format, as an extension or a filename: docx, odt, html, md or txt." },
        }),
        &["file_base64", "format"],
    )
}

fn schema_file_clean() -> Value {
    object_schema(
        json!({
            "file_base64": { "type": "string", "description": "The document's bytes, base64 encoded." },
            "format": { "type": "string", "description": "The document format, as an extension or a filename: docx, odt, md or txt (HTML clean is refused by name; use file_inspect for HTML)." },
            "classes": {
                "type": "array",
                "items": { "type": "string", "enum": mark_class_ids() },
                "description": "Which mark classes to remove. Defaults to every class this tool can remove.",
            },
        }),
        &["file_base64", "format"],
    )
}

fn schema_file_analyze() -> Value {
    object_schema(
        json!({
            "file_base64": { "type": "string", "description": "The document's bytes, base64 encoded." },
            "format": { "type": "string", "description": "The document format, as an extension or a filename (for example docx, odt, html, md, txt, and the other readable document formats)." },
        }),
        &["file_base64", "format"],
    )
}

fn schema_file_strip() -> Value {
    object_schema(
        json!({
            "file_base64": { "type": "string", "description": "The file's bytes, base64 encoded." },
            "format": { "type": "string", "description": "The file format, as an extension or a filename: docx, odt, png, svg or jpeg (a format with no metadata surface is refused by name)." },
        }),
        &["file_base64", "format"],
    )
}

fn schema_file_pristine() -> Value {
    object_schema(
        json!({
            "file_base64": { "type": "string", "description": "The text file's bytes, base64 encoded." },
            "format": { "type": "string", "description": "The document format, as an extension or a filename: md or txt (a container or markup format is refused by name)." },
        }),
        &["file_base64", "format"],
    )
}

fn schema_pqc_keypair() -> Value {
    object_schema(json!({}), &[])
}

fn schema_pqc_seal() -> Value {
    object_schema(
        json!({
            "recipient_public_key_base64": { "type": "string", "description": "The recipient's ML-KEM-768 public key, base64 (from pqc_keypair)." },
            "text": { "type": "string", "description": "The secret message to seal to the recipient." },
        }),
        &["recipient_public_key_base64", "text"],
    )
}

fn schema_pqc_open() -> Value {
    object_schema(
        json!({
            "secret_key_base64": { "type": "string", "description": "Your ML-KEM-768 secret key, base64." },
            "sealed_base64": { "type": "string", "description": "The sealed payload from pqc_seal, base64." },
        }),
        &["secret_key_base64", "sealed_base64"],
    )
}

fn schema_wordmark_analyze() -> Value {
    object_schema(
        json!({
            "text": { "type": "string", "description": "The text to analyze." },
            "acrostic_target": { "type": "string", "description": "Optional. A word you suspect is hidden as an acrostic; the tool reports, exactly, whether the word-initial or line-initial letters spell it." },
            "mark_key_hex": { "type": "string", "description": "Optional. Your own 32-byte key as 64 hex characters, to test for a mark you placed yourself under that key." },
        }),
        &["text"],
    )
}

fn schema_wordmark_scrub() -> Value {
    object_schema(
        json!({
            "text": { "type": "string", "description": "The text to perturb." },
            "aggression": { "type": "string", "description": "How much to perturb: light, medium (the default), or heavy." },
        }),
        &["text"],
    )
}

fn schema_wordmark_online_disclaimer() -> Value {
    object_schema(json!({}), &[])
}

fn schema_file_conceal() -> Value {
    object_schema(
        json!({
            "file_base64": { "type": "string", "description": "The document's bytes, base64 encoded." },
            "format": { "type": "string", "description": "The document format, as an extension or a filename. Text-native formats (md, txt) are served; a container or markup format is refused by name." },
            "secret": { "type": "string", "description": "The secret, as text. Supply this or secret_base64." },
            "secret_base64": { "type": "string", "description": "The secret, as bytes that must decode to UTF-8 text. Supply this or secret." },
            "carriers": carriers_property("Carriers to use. Defaults to zero_width."),
            "cipher": cipher_property(),
            "passcode": { "type": "string", "description": "Required when a confidentiality layer is named. Never logged." },
            "saturate": { "type": "boolean", "description": "Saturation mode: fill each carrier's channel in the file with the secret repeated, the aggressive variant that survives a heavy cut. Still recoverable. Defaults to false." },
        }),
        &["file_base64", "format"],
    )
}

fn schema_file_convert() -> Value {
    object_schema(
        json!({
            "file_base64": { "type": "string", "description": "The source document's bytes, base64 encoded." },
            "format": { "type": "string", "description": "The SOURCE document format, as an extension or a filename." },
            "target": { "type": "string", "description": "The TARGET format to convert to, as an extension or a filename (for example html, md, txt, tex, rtf, org, rst, adoc, ipynb, typ; pdf when a local browser is available). Conversion is declared lossy and never marks; an unsupported target is refused by name." },
        }),
        &["file_base64", "format", "target"],
    )
}

fn schema_file_metadata() -> Value {
    object_schema(
        json!({
            "file_base64": { "type": "string", "description": "The file's bytes, base64 encoded." },
            "format": { "type": "string", "description": "The file format, as an extension or a filename: an Office document (docx, odt), an image (jpeg, tiff, png, webp), or svg. A format with no metadata this tool reads is refused by name." },
        }),
        &["file_base64", "format"],
    )
}

fn schema_c2pa_inspect() -> Value {
    object_schema(
        json!({
            "file_base64": { "type": "string", "description": "The file's bytes, base64 encoded." },
            "format_hint": { "type": "string", "description": "Optional format hint: a MIME type, extension or filename. The reader detects the container from the bytes when this is omitted." },
        }),
        &["file_base64"],
    )
}

fn schema_measure_text() -> Value {
    object_schema(
        json!({
            "text": { "type": "string", "description": "The text to score." },
            "reference": { "type": "string", "description": "Optional text to measure the change from." },
        }),
        &["text"],
    )
}

fn schema_compare_texts() -> Value {
    object_schema(
        json!({
            "left": { "type": "string", "description": "The first text. Supply this or left_file_base64." },
            "right": { "type": "string", "description": "The second text. Supply this or right_file_base64." },
            "left_file_base64": { "type": "string", "description": "The first side as a document file (base64). Supply with left_format." },
            "left_format": { "type": "string", "description": "Format of left_file_base64, as an extension or filename." },
            "right_file_base64": { "type": "string", "description": "The second side as a document file (base64). Supply with right_format." },
            "right_format": { "type": "string", "description": "Format of right_file_base64, as an extension or filename." },
        }),
        &[],
    )
}

fn schema_protect_payload() -> Value {
    object_schema(
        json!({
            "plaintext": { "type": "string", "description": "The payload as text. Supply this or plaintext_base64." },
            "plaintext_base64": { "type": "string", "description": "The payload as bytes. Supply this or plaintext." },
            "cipher": cipher_property(),
            "passcode": { "type": "string", "description": "Never logged." },
        }),
        &["cipher", "passcode"],
    )
}

fn schema_unprotect_payload() -> Value {
    object_schema(
        json!({
            "protected_base64": { "type": "string", "description": "The protected payload." },
            "cipher": cipher_property(),
            "passcode": { "type": "string", "description": "Never logged." },
        }),
        &["protected_base64", "cipher", "passcode"],
    )
}

fn schema_compress_payload() -> Value {
    object_schema(
        json!({
            "plaintext": { "type": "string", "description": "The payload as text. Supply this or plaintext_base64." },
            "plaintext_base64": { "type": "string", "description": "The payload as bytes. Supply this or plaintext." },
            "level": { "type": "integer", "minimum": 0, "maximum": 9, "description": "Effort, 0 to 9. Defaults to 6." },
        }),
        &[],
    )
}

fn schema_expand_payload() -> Value {
    object_schema(
        json!({ "compressed_base64": { "type": "string", "description": "The compressed payload." } }),
        &["compressed_base64"],
    )
}

fn schema_attach_payload() -> Value {
    object_schema(
        json!({
            "text": { "type": "string", "description": "The text to attach to." },
            "filename": { "type": "string", "description": "The name the file keeps." },
            "data_base64": { "type": "string", "description": "The file contents." },
        }),
        &["text", "filename", "data_base64"],
    )
}

fn schema_list_attachments() -> Value {
    object_schema(
        json!({ "text": { "type": "string", "description": "The text to look in." } }),
        &["text"],
    )
}

fn schema_detach_payload() -> Value {
    object_schema(
        json!({ "text": { "type": "string", "description": "The text to remove attachments from." } }),
        &["text"],
    )
}

fn schema_render() -> Value {
    object_schema(
        json!({
            "text": { "type": "string", "description": "The text to render." },
            "format": { "type": "string", "enum": RENDER_FORMATS, "description": "Output format. Defaults to plain." },
            "title": { "type": "string", "description": "Optional title, used by the formats that have somewhere to put one." },
            "include_report": { "type": "boolean", "description": "Include the verdict on the rendered text. Defaults to true." },
        }),
        &["text"],
    )
}

fn schema_export() -> Value {
    object_schema(
        json!({
            "text": { "type": "string", "description": "The result text to export. Supply this or a document via file_base64." },
            "target": { "type": "string", "enum": ["md", "html", "txt", "tex", "rtf", "org", "rst", "asciidoc", "ipynb", "typ", "pdf"], "description": "The document format to export to, as an extension. md and txt are byte-faithful; the rest, including pdf, are a declared-lossy rendering. PDF is a self-contained native render (a marked cover's hidden layer does not survive it)." },
        }),
        &["target"],
    )
}

fn schema_settings_read() -> Value {
    object_schema(json!({}), &[])
}

fn schema_settings_update() -> Value {
    object_schema(
        json!({
            "settings": { "type": "object", "description": "The fields to change, in the shape settings_read returns." },
        }),
        &["settings"],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> SettingsStore {
        SettingsStore::in_memory(Settings::default())
    }

    fn done(name: &str, args: Value) -> Value {
        match call(name, &args, &mut store()) {
            Outcome::Done(value) => value,
            Outcome::Refused { code, reason } => panic!("{name} refused [{code}]: {reason}"),
            Outcome::BadArguments(reason) => panic!("{name} rejected its arguments: {reason}"),
            Outcome::Unknown(reason) => panic!("{reason}"),
        }
    }

    fn refusal(name: &str, args: Value) -> (&'static str, String) {
        match call(name, &args, &mut store()) {
            Outcome::Refused { code, reason } => (code, reason),
            other => panic!(
                "{name} was expected to refuse, it returned {}",
                match other {
                    Outcome::Done(_) => "a result",
                    Outcome::BadArguments(_) => "an argument rejection",
                    _ => "something else",
                }
            ),
        }
    }

    const LONG_COVER: &str = "Access to the open science project expectations are exceptional in scope and practice today across every possible aspect of ecosystem operations including all cooperative joint exercises and the wider programme of shared observation";

    #[test]
    fn recommend_settings_names_a_carrier_and_the_mission_that_applies() {
        // A cover with room to spare, so the recommendation fits and applies.
        let cover = format!("{LONG_COVER} {LONG_COVER} {LONG_COVER} {LONG_COVER}");
        let rec = done(
            "recommend_settings",
            json!({ "cover": cover, "secret": "north gate at nine" }),
        );
        assert_eq!(rec["fits"], json!(true));
        assert!(
            rec["carrier"].is_string(),
            "a fitting recommendation names a carrier"
        );
        assert!(rec["mission"].is_string(), "and a mission to apply");
        assert_eq!(rec["shortfall_bytes"], json!(0));

        // Applying it composes: the recommended carrier takes the secret.
        let carrier = rec["carrier"].as_str().unwrap().to_string();
        let placed = done(
            "conceal",
            json!({ "cover": cover, "secret": "north gate at nine", "carriers": [carrier] }),
        );
        assert_eq!(placed["round_trip"]["verified"], json!(true));
    }

    #[test]
    fn conceal_writes_the_robust_frame_on_request_and_it_reads_back() {
        let cover = format!("{LONG_COVER} {LONG_COVER}");
        let placed = done(
            "conceal",
            json!({ "cover": &cover, "secret": "robust layer", "carriers": ["zero_width"], "robust": true }),
        );
        assert_eq!(
            placed["round_trip"]["verified"],
            json!(true),
            "the robust frame is written and read back"
        );

        // The robust frame's larger overhead reports a smaller capacity than the
        // light default, on the same cover and carrier.
        let light = done("capacity_report", json!({ "cover": &cover, "carriers": ["homoglyph"] }));
        let heavy = done(
            "capacity_report",
            json!({ "cover": &cover, "carriers": ["homoglyph"], "robust": true }),
        );
        let l = light["carriers"][0]["secret_bytes"].as_u64().unwrap();
        let h = heavy["carriers"][0]["secret_bytes"].as_u64().unwrap();
        assert!(h < l, "robust capacity {h} must be below light {l}");
    }

    #[test]
    fn conceal_saturate_fills_the_channel_and_reads_back() {
        // SAT-E2E, MCP. Saturation fills the channel past a single copy, and the
        // round-trip check inside conceal proves it still reads back. The cover is
        // repeated so it offers positions for several whole copies.
        let cover = LONG_COVER.repeat(20);
        let normal = done(
            "conceal",
            json!({ "cover": &cover, "secret": "sat mcp", "carriers": ["zero_width"] }),
        );
        let saturated = done(
            "conceal",
            json!({ "cover": &cover, "secret": "sat mcp", "carriers": ["zero_width"], "saturate": true }),
        );
        assert_eq!(
            saturated["round_trip"]["verified"],
            json!(true),
            "the saturated document reads back"
        );
        let channel = |v: &Value| {
            v["stego_text"]
                .as_str()
                .unwrap()
                .chars()
                .filter(|c| matches!(*c, '\u{200B}' | '\u{200C}'))
                .count()
        };
        assert!(
            channel(&saturated) >= channel(&normal) * 2,
            "the saturated channel is at least twice as dense as a single copy"
        );
    }

    #[test]
    fn conceal_reports_the_analyser_verdict_on_the_produced_document() {
        // Placement is permissive; the honest overlay is the density and verdict
        // the tool's own analyser reaches on the exact document produced.
        let cover = format!("{LONG_COVER} {LONG_COVER}");
        let placed = done(
            "conceal",
            json!({ "cover": cover, "secret": "north gate", "carriers": ["zero_width"] }),
        );
        assert!(
            placed["noise_density"].as_f64().unwrap() > 0.0,
            "a placed layer leaves a measurable channel density"
        );
        assert!(
            !placed["verdict"].as_str().unwrap().is_empty(),
            "the analyser verdict travels with the result"
        );
    }

    #[test]
    fn recommend_settings_names_the_shortfall_when_nothing_fits() {
        let rec = done(
            "recommend_settings",
            json!({ "cover": "A short line.", "secret": "far more than this tiny cover can ever hold in a mark" }),
        );
        assert_eq!(rec["fits"], json!(false));
        assert_eq!(rec["carrier"], json!(null));
        assert!(
            rec["shortfall_bytes"].as_u64().unwrap() > 0,
            "the shortfall is named, not a false figure"
        );
    }

    /// A cover long enough to hold a full authorship claim.
    fn signing_cover() -> String {
        LONG_COVER.repeat(4)
    }

    #[test]
    fn every_command_name_is_unique() {
        let mut names = tool_names();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "duplicate command name");
    }

    #[test]
    fn every_command_advertises_an_object_schema() {
        for spec in tool_specs() {
            let schema = (spec.schema)();
            assert_eq!(schema["type"], json!("object"), "{}", spec.name);
            assert!(schema["properties"].is_object(), "{}", spec.name);
            assert!(schema["required"].is_array(), "{}", spec.name);
        }
    }

    /// Nothing that reaches an agent may carry the rejected punctuation.
    #[test]
    fn no_advertised_text_carries_a_rejected_mark() {
        for spec in tool_specs() {
            for text in [spec.name, spec.title, spec.description] {
                assert!(!text.contains('\u{2014}'), "em dash in {}", spec.name);
                assert!(!text.contains('\u{2013}'), "en dash in {}", spec.name);
            }
            let schema = (spec.schema)().to_string();
            assert!(!schema.contains('\u{2014}'), "em dash in {} schema", spec.name);
        }
        let listed = tool_list_payload().to_string();
        assert!(!listed.contains('\u{2014}'));
    }

    #[test]
    fn an_unknown_command_is_refused_by_name() {
        match call("not_a_command", &json!({}), &mut store()) {
            Outcome::Unknown(reason) => assert!(reason.contains("not_a_command")),
            _ => panic!("expected an unknown-command outcome"),
        }
    }

    #[test]
    fn capabilities_are_read_from_the_live_registry() {
        let listed = done("capabilities_list", json!({}));
        let carriers: Vec<&str> = listed["carriers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap())
            .collect();
        assert_eq!(carriers, catalogue::CARRIER_ORDER.to_vec());
        assert_eq!(
            listed["commands"].as_array().unwrap().len(),
            tool_names().len()
        );
    }

    #[test]
    fn wordmark_analyze_always_names_the_structural_wall() {
        let report = done(
            "wordmark_analyze",
            json!({ "text": "just some plain ordinary words here" }),
        );
        let findings = report["findings"].as_array().expect("a findings array");
        assert!(
            findings.iter().any(|f| f["verdict"] == json!("impossible")),
            "every analysis states the limit it cannot pass"
        );
    }

    #[test]
    fn wordmark_analyze_names_a_present_acrostic_with_certainty() {
        let report = done(
            "wordmark_analyze",
            json!({
                "text": "Hello indeed dragons dance every night.",
                "acrostic_target": "hidden"
            }),
        );
        let findings = report["findings"].as_array().unwrap();
        assert!(findings
            .iter()
            .any(|f| f["verdict"] == json!("certain") && f["label"] == json!("acrostic")));
    }

    #[test]
    fn wordmark_scrub_perturbs_locally_and_reports_the_count() {
        let report = done(
            "wordmark_scrub",
            json!({ "text": "big fast help many keep whole", "aggression": "heavy" }),
        );
        assert_eq!(report["positions_changed"], json!(6));
        assert_ne!(report["text"], json!("big fast help many keep whole"));
    }

    #[test]
    fn wordmark_online_disclaimer_returns_the_interface_keys() {
        let out = done("wordmark_online_disclaimer", json!({}));
        assert_eq!(out["requires_disclaimer"], json!(true));
        assert_eq!(out["title_key"], json!("wordmark.online.title"));
        assert_eq!(out["disclaimer_key"], json!("wordmark.online.disclaimer"));
        assert_eq!(out["acknowledge_key"], json!("wordmark.online.acknowledge"));
    }

    #[test]
    fn wordmark_scrub_rejects_an_unknown_aggression() {
        match call("wordmark_scrub", &json!({ "text": "big", "aggression": "nuclear" }), &mut store()) {
            Outcome::BadArguments(reason) => assert!(reason.contains("aggression")),
            _ => panic!("expected a bad-arguments outcome"),
        }
    }

    /// A minimal PNG carrying a metadata (tEXt) chunk alongside the pixel data.
    fn png_with_text_chunk() -> (Vec<u8>, Vec<u8>) {
        fn chunk(ctype: &[u8; 4], data: &[u8]) -> Vec<u8> {
            let mut c = Vec::new();
            c.extend_from_slice(&(data.len() as u32).to_be_bytes());
            c.extend_from_slice(ctype);
            c.extend_from_slice(data);
            c.extend_from_slice(&[0, 0, 0, 0]);
            c
        }
        let idat = [3u8, 1, 4, 1, 5, 9, 2, 6];
        let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend_from_slice(&chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]));
        png.extend_from_slice(&chunk(b"tEXt", b"steganohero\0payload"));
        png.extend_from_slice(&chunk(b"IDAT", &idat));
        png.extend_from_slice(&chunk(b"IEND", &[]));
        (png, chunk(b"IDAT", &idat))
    }

    #[test]
    fn file_strip_removes_metadata_and_keeps_content() {
        let (png, idat_chunk) = png_with_text_chunk();
        let out = done(
            "file_strip",
            json!({ "file_base64": B64.encode(&png), "format": "png" }),
        );
        assert_eq!(out["altered"], json!(true));
        assert_eq!(out["content_identical"], json!(true));
        let stripped = B64.decode(out["stripped_file_base64"].as_str().unwrap()).unwrap();
        assert!(
            !stripped.windows(4).any(|w| w == b"tEXt"),
            "the metadata chunk is removed"
        );
        assert!(
            stripped.windows(idat_chunk.len()).any(|w| w == idat_chunk.as_slice()),
            "the pixel data survives byte-identical"
        );
    }

    #[test]
    fn file_strip_on_a_text_format_is_refused_by_name() {
        let (code, _reason) = refusal(
            "file_strip",
            json!({ "file_base64": B64.encode("# just text\n"), "format": "md" }),
        );
        assert_eq!(code, "file_strip_refused");
    }

    #[test]
    fn file_pristine_removes_marks_and_invisibles_and_names_the_tradeoff() {
        // A zero-width space, an invisible separator and a soft hyphen: none may
        // survive a pristine clean.
        let dirty = "Note here\u{200B} and\u{2063} more\u{00AD} text.";
        let out = done(
            "file_pristine",
            json!({ "file_base64": B64.encode(dirty), "format": "md" }),
        );
        assert_eq!(out["altered"], json!(true));
        assert!(out["invisibles_removed"].as_u64().unwrap() >= 1);
        assert!(!out["notes"].as_array().unwrap().is_empty());
        let cleaned = out["cleaned_text"].as_str().unwrap();
        assert!(
            !cleaned.chars().any(|c| matches!(c as u32,
                0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x2069
                | 0xFEFF | 0x00AD | 0x034F | 0x061C | 0x180E)),
            "no invisible or format-control character remains: {cleaned:?}"
        );
    }

    #[test]
    fn file_pristine_on_a_container_is_refused_by_name() {
        let (code, _reason) = refusal(
            "file_pristine",
            json!({ "file_base64": B64.encode("not a real docx"), "format": "docx" }),
        );
        assert_eq!(code, "file_pristine_refused");
    }

    #[test]
    fn pqc_seals_and_opens_a_message_round_trip() {
        let kp = done("pqc_keypair", json!({}));
        let public = kp["public_key_base64"].as_str().unwrap().to_string();
        let secret = kp["secret_key_base64"].as_str().unwrap().to_string();
        let sealed = done(
            "pqc_seal",
            json!({ "recipient_public_key_base64": public, "text": "the documents are in the second drawer" }),
        );
        let sealed_b64 = sealed["sealed_base64"].as_str().unwrap().to_string();
        let opened = done(
            "pqc_open",
            json!({ "secret_key_base64": secret, "sealed_base64": sealed_b64 }),
        );
        assert_eq!(opened["text"], json!("the documents are in the second drawer"));
    }

    #[test]
    fn pqc_open_with_the_wrong_key_is_refused_by_name() {
        let recipient = done("pqc_keypair", json!({}));
        let intruder = done("pqc_keypair", json!({}));
        let sealed = done(
            "pqc_seal",
            json!({
                "recipient_public_key_base64": recipient["public_key_base64"].as_str().unwrap(),
                "text": "for the recipient only",
            }),
        );
        let (code, _reason) = refusal(
            "pqc_open",
            json!({
                "secret_key_base64": intruder["secret_key_base64"].as_str().unwrap(),
                "sealed_base64": sealed["sealed_base64"].as_str().unwrap(),
            }),
        );
        assert_eq!(code, "pqc_open_refused");
    }

    #[test]
    fn conceal_seals_to_a_recipient_and_reveal_opens_it_end_to_end() {
        // The headline flow: seal a secret to a recipient, hide it in a cover in
        // one call, then reveal and open it in one call. No shared passcode.
        let kp = done("pqc_keypair", json!({}));
        let public = kp["public_key_base64"].as_str().unwrap().to_string();
        let secret = kp["secret_key_base64"].as_str().unwrap().to_string();

        let placed = done(
            "conceal",
            json!({
                "cover": LONG_COVER,
                "secret": "meet at the north gate at nine",
                "recipient_public_key_base64": public,
            }),
        );
        assert_eq!(placed["sealed_to_recipient"], json!(true));
        assert_eq!(placed["round_trip"]["verified"], json!(true));
        // The placed payload is the sealed blob, larger than the plaintext.
        assert!(placed["placed_bytes"].as_u64().unwrap() > placed["secret_bytes"].as_u64().unwrap());

        let read = done(
            "reveal",
            json!({
                "text": placed["stego_text"],
                "carriers": ["zero_width"],
                "recipient_secret_key_base64": secret,
            }),
        );
        assert_eq!(read["opened_for_recipient"], json!(true));
        assert_eq!(read["secret"]["text"], json!("meet at the north gate at nine"));
    }

    #[test]
    fn revealing_a_sealed_payload_with_the_wrong_key_is_refused_by_name() {
        let recipient = done("pqc_keypair", json!({}));
        let intruder = done("pqc_keypair", json!({}));
        let placed = done(
            "conceal",
            json!({
                "cover": LONG_COVER,
                "secret": "for the recipient only",
                "recipient_public_key_base64": recipient["public_key_base64"].as_str().unwrap(),
            }),
        );
        let (code, _reason) = refusal(
            "reveal",
            json!({
                "text": placed["stego_text"],
                "carriers": ["zero_width"],
                "recipient_secret_key_base64": intruder["secret_key_base64"].as_str().unwrap(),
            }),
        );
        assert_eq!(code, "recipient_open_refused");
    }

    #[test]
    fn conceal_with_a_malformed_recipient_key_is_refused_by_name() {
        let (code, _reason) = refusal(
            "conceal",
            json!({
                "cover": LONG_COVER,
                "secret": "x",
                "recipient_public_key_base64": B64.encode(b"not a real ML-KEM public key"),
            }),
        );
        assert_eq!(code, "recipient_seal_refused");
    }

    #[test]
    fn a_marked_text_saved_as_a_file_is_revealed_from_the_file() {
        // Hide in text, save it as a .txt file, then reveal FROM the file: the same
        // uniform file input every single-text tool now accepts.
        let placed = done("conceal", json!({ "cover": LONG_COVER, "secret": "hidden in a file" }));
        let stego = placed["stego_text"].as_str().unwrap();
        let read = done(
            "reveal",
            json!({
                "file_base64": B64.encode(stego.as_bytes()),
                "format": "txt",
                "carriers": ["zero_width"],
            }),
        );
        assert_eq!(read["secret"]["text"], json!("hidden in a file"));
    }

    #[test]
    fn a_text_tool_runs_on_a_document_file() {
        // analyze, a text-only tool, now runs on a real file: its text is extracted
        // before dispatch, so a Markdown document is analysed without the caller
        // extracting it first.
        let report = done(
            "analyze",
            json!({ "file_base64": B64.encode(b"# Note\n\nplain content, nothing hidden"), "format": "md" }),
        );
        assert!(report.get("verdict").is_some() || report.get("suspicion").is_some(),
            "analyze returned a report over the file's text");
    }

    #[test]
    fn supplying_both_text_and_a_file_is_refused_by_name() {
        match call(
            "reveal",
            &json!({ "text": "x", "file_base64": B64.encode(b"y"), "format": "txt" }),
            &mut store(),
        ) {
            Outcome::BadArguments(msg) => assert!(msg.contains("not both"), "names the conflict: {msg}"),
            _ => panic!("expected a rejection of the double supply"),
        }
    }

    #[test]
    fn a_tool_that_takes_no_document_refuses_a_file_by_name() {
        match call(
            "pqc_seal",
            &json!({ "file_base64": B64.encode(b"x"), "format": "txt" }),
            &mut store(),
        ) {
            Outcome::BadArguments(msg) => {
                assert!(msg.contains("does not take a document file"), "names the limit: {msg}");
            }
            _ => panic!("expected a rejection of the file input"),
        }
    }

    #[test]
    fn the_served_schema_advertises_the_uniform_file_input() {
        // A file-eligible tool advertises file_base64 and relaxes its text field
        // from required, so the schema matches the dispatch. A file-native tool is
        // left untouched.
        let reveal = served_schema("reveal", schema_reveal());
        assert!(reveal["properties"]["file_base64"].is_object(), "reveal advertises file_base64");
        let required = reveal["required"].as_array().unwrap();
        assert!(!required.iter().any(|v| v == "text"), "reveal's text field is relaxed to optional");

        let keypair = served_schema("pqc_keypair", schema_pqc_keypair());
        assert!(keypair["properties"].get("file_base64").is_none(), "a file-native tool is untouched");
    }

    #[test]
    fn export_hands_a_result_back_as_downloadable_bytes() {
        let out = done("export", json!({ "text": "one finding, stated plainly", "target": "rtf" }));
        let bytes = B64.decode(out["exported_base64"].as_str().unwrap()).unwrap();
        assert!(!bytes.is_empty(), "the rtf export has bytes to save");
        assert_eq!(out["target"], json!("rtf"));
    }

    #[test]
    fn export_to_text_is_byte_faithful_and_also_copyable() {
        // A marked cover exported to txt must come back exactly, so the hidden
        // layer survives, and the text is echoed so it can be copied too.
        let content = "the drop is at\u{200B} noon";
        let out = done("export", json!({ "text": content, "target": "txt" }));
        assert_eq!(out["byte_faithful"], json!(true));
        assert_eq!(out["text"], json!(content));
        let bytes = B64.decode(out["exported_base64"].as_str().unwrap()).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), content, "txt export is byte-faithful");
    }

    #[test]
    fn export_of_a_document_file_uses_its_text() {
        // A document supplied as a file is exported to another format: its text is
        // extracted first through the uniform file input.
        let out = done(
            "export",
            json!({ "file_base64": B64.encode(b"# Note\n\nbody"), "format": "md", "target": "html" }),
        );
        let html = String::from_utf8(B64.decode(out["exported_base64"].as_str().unwrap()).unwrap()).unwrap();
        assert!(html.contains("Note") || html.contains("body"), "html carries the document's text");
    }

    #[test]
    fn compare_texts_accepts_a_file_on_each_side() {
        // The two-input comparison takes a document on either side, not only text.
        let out = done(
            "compare_texts",
            json!({
                "left": "the original wording",
                "right_file_base64": B64.encode(b"# Doc\n\nthe revised wording"),
                "right_format": "md",
            }),
        );
        assert!(out.is_object(), "a comparison was produced from a text and a file");
    }

    #[test]
    fn compare_texts_refuses_both_text_and_file_on_a_side() {
        match call(
            "compare_texts",
            &json!({
                "left": "x", "right": "y",
                "left_file_base64": B64.encode(b"z"), "left_format": "txt",
            }),
            &mut store(),
        ) {
            Outcome::BadArguments(msg) => assert!(msg.contains("not both"), "names the conflict: {msg}"),
            _ => panic!("the double supply must be rejected"),
        }
    }

    #[test]
    fn export_to_an_unknown_target_is_refused_by_name() {
        match call("export", &json!({ "text": "x", "target": "xyz" }), &mut store()) {
            Outcome::BadArguments(msg) => assert!(msg.contains("unknown export target"), "names the target: {msg}"),
            _ => panic!("an unknown target must be rejected"),
        }
    }

    #[test]
    fn export_to_pdf_produces_a_native_pdf() {
        // PDF exports through the self-contained native writer.
        let out = done("export", json!({ "text": "a short report", "target": "pdf" }));
        let bytes = B64.decode(out["exported_base64"].as_str().unwrap()).unwrap();
        assert!(bytes.starts_with(b"%PDF"), "the export is a PDF document");
        assert_eq!(out["target"], json!("pdf"));
    }

    #[test]
    fn an_illegal_order_is_refused_when_the_order_is_the_question() {
        let (code, reason) = refusal(
            "chain_validate",
            json!({ "carriers": ["homoglyph", "zero_width"], "preserve_order": true }),
        );
        assert_eq!(code, "composition_refused");
        assert!(reason.contains("homoglyph"));
    }

    #[test]
    fn a_legal_selection_comes_back_in_application_order() {
        let checked = done(
            "chain_validate",
            json!({ "carriers": ["bidi", "zero_width"] }),
        );
        assert_eq!(checked["carriers_in_order"], json!(["zero_width", "bidi"]));
        assert_eq!(checked["reordered"], json!(true));
    }

    /// A selection given in an order the engine would refuse is accepted once
    /// it is put into application order, and the caller is told it moved.
    #[test]
    fn an_out_of_order_selection_is_reordered_rather_than_refused_by_default() {
        let checked = done(
            "chain_validate",
            json!({ "carriers": ["homoglyph", "zero_width"] }),
        );
        assert_eq!(checked["accepted"], json!(true));
        assert_eq!(checked["carriers_in_order"], json!(["zero_width", "homoglyph"]));
        assert_eq!(checked["reordered"], json!(true));
    }

    #[test]
    fn conceal_and_reveal_round_trip_without_a_confidentiality_layer() {
        let placed = done(
            "conceal",
            json!({ "cover": LONG_COVER, "secret": "attribution matters" }),
        );
        assert_eq!(placed["round_trip"]["verified"], json!(true));

        let read = done(
            "reveal",
            json!({ "text": placed["stego_text"], "carriers": ["zero_width"] }),
        );
        assert_eq!(read["secret"]["text"], json!("attribution matters"));
        assert_eq!(read["integrity_valid"], json!(true));
    }

    #[test]
    fn conceal_and_reveal_round_trip_under_a_confidentiality_layer() {
        let placed = done(
            "conceal",
            json!({
                "cover": LONG_COVER,
                "secret": "protected",
                "cipher": "chacha20_poly1305",
                "passcode": "a passcode that is not logged"
            }),
        );
        let read = done(
            "reveal",
            json!({
                "text": placed["stego_text"],
                "carriers": ["zero_width"],
                "passcode": "a passcode that is not logged"
            }),
        );
        assert_eq!(read["secret"]["text"], json!("protected"));
        assert_eq!(read["cipher_used"], json!("chacha20_poly1305"));
    }

    #[test]
    fn a_confidentiality_layer_without_a_passcode_is_rejected_rather_than_dropped() {
        match call(
            "conceal",
            &json!({ "cover": LONG_COVER, "secret": "x", "cipher": "aes256_gcm" }),
            &mut store(),
        ) {
            Outcome::BadArguments(reason) => assert!(reason.contains("passcode")),
            _ => panic!("an empty passcode must not silently disable the layer"),
        }
    }

    #[test]
    fn a_wrong_passcode_refuses_rather_than_returning_something() {
        let placed = done(
            "conceal",
            json!({
                "cover": LONG_COVER,
                "secret": "protected",
                "cipher": "chacha20_poly1305",
                "passcode": "right"
            }),
        );
        let (code, _) = refusal(
            "reveal",
            json!({
                "text": placed["stego_text"],
                "carriers": ["zero_width"],
                "passcode": "wrong"
            }),
        );
        assert_eq!(code, "recovery_refused");
    }

    #[test]
    fn cleaning_that_rewrites_visible_characters_is_refused_by_default() {
        let (code, reason) = refusal(
            "sanitize",
            json!({ "text": LONG_COVER, "channels": ["homoglyph"] }),
        );
        assert_eq!(code, "visible_rewrite_refused");
        assert!(reason.contains("allow_visible_text_rewrite"));
    }

    #[test]
    fn cleaning_that_rewrites_visible_characters_is_refused_on_unmarked_text() {
        let (code, _) = refusal(
            "sanitize",
            json!({
                "text": "The quick brown fox jumps over the lazy dog",
                "channels": ["homoglyph"],
                "allow_visible_text_rewrite": true
            }),
        );
        assert_eq!(code, "no_marking_found");
    }

    #[test]
    fn normalising_a_carrying_text_is_refused_unless_the_loss_is_accepted() {
        let placed = done(
            "conceal",
            json!({ "cover": LONG_COVER, "secret": "keep me" }),
        );
        let text = placed["stego_text"].as_str().unwrap().to_string();

        let (code, _) = refusal(
            "normalize_text",
            json!({ "text": text, "lowercase": true }),
        );
        assert_eq!(code, "payload_loss_refused");

        let normalised = done(
            "normalize_text",
            json!({ "text": text, "lowercase": true, "accept_payload_loss": true }),
        );
        assert_eq!(normalised["changed"], json!(true));
    }

    #[test]
    fn inspect_reports_the_format_without_opening_the_content() {
        let placed = done(
            "conceal",
            json!({
                "cover": LONG_COVER,
                "secret": "sealed",
                "cipher": "aes256_gcm",
                "passcode": "sealed passcode"
            }),
        );
        let seen = done("inspect", json!({ "text": placed["stego_text"] }));
        assert_eq!(seen["decrypted"], json!(false));

        let entry = seen["carriers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["carrier"] == json!("zero_width"))
            .expect("the carrier that was used must appear");
        assert_eq!(entry["envelope"]["cipher_declared"], json!("aes256_gcm"));
        assert!(entry["envelope"]["format_version"].is_string());

        // The recovered secret must appear nowhere in the report.
        assert!(!seen.to_string().contains("sealed passcode"));
    }

    /// The document shape this surface reads is written by the core. If the
    /// core changes it, this fails rather than reporting nothing.
    #[test]
    fn the_document_shape_matches_what_the_core_writes() {
        let carrier = catalogue::carrier("zero_width").unwrap();
        let placed = pipeline::encode(LONG_COVER, b"header check", &[carrier.as_ref()], None)
            .expect("must place");
        let shape = document_shape(carrier.as_ref(), &placed.stego_text);

        // The light frame is the default the core writes (§3.2); its plain
        // version is 3. The heavy frame's "2" is the secondary path.
        assert_eq!(shape["format_version"], json!("3"));
        assert_eq!(shape["mission"], json!("conceal"));
        assert_eq!(shape["read_from"], json!("head"));
        assert!(shape["declared_payload_bits"].as_u64().unwrap() > 0);
        assert_eq!(shape["content_version"], json!(2));
        assert_eq!(shape["chain_declared"], json!(["crc32"]));
        assert_eq!(
            shape["cipher_declared"],
            Value::Null,
            "nothing was protected, so nothing is declared"
        );
        assert!(shape["payload_bytes"].as_u64().unwrap() > 0);
        assert!(
            shape.get("content_unreadable").is_none(),
            "an intact document must not report its content region as unreadable"
        );

        // A carrier that holds nothing in this text says so, rather than
        // reporting an empty shape that reads as a document with no layers.
        let other = catalogue::carrier("homoglyph").unwrap();
        assert_eq!(
            document_shape(other.as_ref(), &placed.stego_text),
            Value::Null
        );
    }

    #[test]
    fn an_authorship_claim_round_trips() {
        let keys = done("authorship_keypair", json!({}));
        let signed = done(
            "authorship_sign",
            json!({
                "cover": signing_cover(),
                "author": "Hope 'n Mind",
                "private_key_base64": keys["private_key_base64"],
            }),
        );
        let checked = done(
            "authorship_verify",
            json!({
                "text": signed["signed_text"],
                "public_key_base64": keys["public_key_base64"],
            }),
        );
        assert_eq!(checked["verified"], json!(true));
        assert_eq!(checked["claim"]["author"], json!("Hope 'n Mind"));
    }

    #[test]
    fn an_authorship_claim_checked_against_another_key_is_refused() {
        let keys = done("authorship_keypair", json!({}));
        let other = done("authorship_keypair", json!({}));
        let signed = done(
            "authorship_sign",
            json!({
                "cover": signing_cover(),
                "author": "Hope 'n Mind",
                "private_key_base64": keys["private_key_base64"],
            }),
        );
        let (code, _) = refusal(
            "authorship_verify",
            json!({
                "text": signed["signed_text"],
                "public_key_base64": other["public_key_base64"],
            }),
        );
        assert_eq!(code, "verification_refused");
    }

    #[test]
    fn a_payload_survives_protection_and_compression_in_both_directions() {
        let protected = done(
            "protect_payload",
            json!({ "plaintext": "round trip", "cipher": "aes256_gcm", "passcode": "code" }),
        );
        let opened = done(
            "unprotect_payload",
            json!({
                "protected_base64": protected["protected_base64"],
                "cipher": "aes256_gcm",
                "passcode": "code"
            }),
        );
        assert_eq!(opened["plaintext"]["text"], json!("round trip"));

        let squeezed = done(
            "compress_payload",
            json!({ "plaintext": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }),
        );
        let expanded = done(
            "expand_payload",
            json!({ "compressed_base64": squeezed["compressed_base64"] }),
        );
        assert_eq!(
            expanded["plaintext"]["text"],
            json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn an_attachment_round_trips_and_detaches() {
        let attached = done(
            "attach_payload",
            json!({ "text": "cover", "filename": "note.txt", "data_base64": B64.encode(b"contents") }),
        );
        let listed = done("list_attachments", json!({ "text": attached["text"] }));
        assert_eq!(listed["count"], json!(1));
        assert_eq!(listed["files"][0]["filename"], json!("note.txt"));

        let detached = done("detach_payload", json!({ "text": attached["text"] }));
        assert_eq!(detached["text"], json!("cover"));
    }

    #[test]
    fn every_output_format_renders_and_states_what_it_is_handing_over() {
        for format in RENDER_FORMATS {
            let rendered = done(
                "render",
                json!({ "text": "a line of text", "format": format, "title": "Title" }),
            );
            assert_eq!(rendered["format"], json!(format));
            assert!(rendered["output"].as_str().unwrap().len() > 0);
            assert!(rendered["integrity"]["sha256"].is_string());
            assert!(rendered["report"]["verdict"].is_string());
        }
    }

    #[test]
    fn an_unknown_output_format_is_rejected_by_name() {
        match call(
            "render",
            &json!({ "text": "x", "format": "pdf" }),
            &mut store(),
        ) {
            Outcome::BadArguments(reason) => assert!(reason.contains("pdf")),
            _ => panic!("an unknown format must be rejected"),
        }
    }

    #[test]
    fn html_rendering_escapes_markup() {
        let rendered = done(
            "render",
            json!({ "text": "<script>alert(1)</script>", "format": "html" }),
        );
        let output = rendered["output"].as_str().unwrap();
        assert!(output.contains("&lt;script&gt;"));
        assert!(!output.contains("<script>"));
    }

    #[test]
    fn comparing_a_cover_with_its_result_names_what_was_added() {
        let placed = done(
            "conceal",
            json!({ "cover": LONG_COVER, "secret": "delta" }),
        );
        let compared = done(
            "compare_texts",
            json!({ "left": LONG_COVER, "right": placed["stego_text"] }),
        );
        assert_eq!(compared["identical"], json!(false));
        assert_eq!(compared["visible_text_identical"], json!(true));
        assert!(compared["gained_by_right"].as_object().unwrap().len() > 0);
    }

    #[test]
    fn settings_are_readable_and_writable_through_the_surface() {
        let mut store = store();
        let read = match call("settings_read", &json!({}), &mut store) {
            Outcome::Done(value) => value,
            _ => panic!("settings must be readable"),
        };
        assert_eq!(read["settings"]["language"], json!("en"));

        match call(
            "settings_update",
            &json!({ "settings": { "language": "fr" } }),
            &mut store,
        ) {
            Outcome::Done(value) => assert_eq!(value["settings"]["language"], json!("fr")),
            _ => panic!("a valid update must be accepted"),
        }

        match call(
            "settings_update",
            &json!({ "settings": { "density": { "mark": 0.01 } } }),
            &mut store,
        ) {
            Outcome::Refused { code, reason } => {
                assert_eq!(code, "settings_rejected");
                assert!(reason.contains("density.mark"));
            }
            _ => panic!("an out-of-range update must be refused"),
        }
        assert_eq!(store.settings().density.mark, 0.85);
    }

    #[test]
    fn a_measurement_reports_a_change_only_when_a_reference_is_given() {
        let alone = done("measure_text", json!({ "text": LONG_COVER }));
        assert!(alone.get("change_from_reference").is_none());

        let placed = done(
            "conceal",
            json!({ "cover": LONG_COVER, "secret": "measured" }),
        );
        let against = done(
            "measure_text",
            json!({ "text": placed["stego_text"], "reference": LONG_COVER }),
        );
        assert!(against["change_from_reference"]["combined_density"]
            .as_f64()
            .unwrap()
            > 0.0);
    }

    // ─── provenance ─────────────────────────────────────────

    #[test]
    fn a_detached_provenance_record_signs_verifies_and_names_a_tampered_document() {
        let keys = done("authorship_keypair", json!({}));
        let cover = signing_cover();

        let signed = done(
            "provenance_sign",
            json!({
                "cover": cover,
                "assertions": [{ "kind": "human_authorship", "author": "Hope 'n Mind" }],
                "private_key_base64": keys["private_key_base64"],
            }),
        );
        assert_eq!(signed["binding"], json!("detached"));
        assert_eq!(signed["round_trip"]["verified"], json!(true));
        // The private key never appears in the result.
        assert!(!signed
            .to_string()
            .contains(keys["private_key_base64"].as_str().unwrap()));
        let sidecar = signed["sidecar"]["base64"].clone();

        let verified = done(
            "provenance_verify",
            json!({
                "document": cover,
                "sidecar_base64": sidecar,
                "trusted_keys_base64": [keys["public_key_base64"]],
            }),
        );
        assert_eq!(verified["provenance_holds"], json!(true));
        assert_eq!(verified["claims"].as_array().unwrap().len(), 1);
        assert!(verified["claims"][0]["assertion_kinds"]
            .as_array()
            .unwrap()
            .contains(&json!("human_authorship")));
        assert_eq!(
            verified["claims"][0]["signer_public_key_base64"],
            keys["public_key_base64"]
        );

        // Editing one visible character invalidates the document binding, named.
        let edited = format!("{cover} An extra sentence added by somebody else.");
        let tampered = done(
            "provenance_verify",
            json!({
                "document": edited,
                "sidecar_base64": sidecar,
                "trusted_keys_base64": [keys["public_key_base64"]],
            }),
        );
        assert_eq!(tampered["provenance_holds"], json!(false));
        assert_eq!(tampered["claims"][0]["signature_valid"], json!(true));
        assert_eq!(tampered["claims"][0]["document_unaltered"], json!(false));
        assert!(tampered["claims"][0]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f.as_str().unwrap().contains("document altered")));
    }

    #[test]
    fn an_in_band_provenance_record_signs_and_verifies() {
        let keys = done("authorship_keypair", json!({}));
        let cover = signing_cover();

        let signed = done(
            "provenance_sign",
            json!({
                "cover": cover,
                "assertions": [{ "kind": "ai_generated", "model": "example-model-1", "provider": "ExampleAI" }],
                "private_key_base64": keys["private_key_base64"],
                "binding": "in_band",
                "carrier": "zero_width",
            }),
        );
        assert_eq!(signed["binding"], json!("in_band"));
        assert_eq!(signed["round_trip"]["verified"], json!(true));
        assert_eq!(
            signed["measured_robustness"]["class"],
            json!("BestEffort"),
            "an in-band record must never over-report robustness"
        );

        let verified = done(
            "provenance_verify",
            json!({
                "document": signed["marked_text"],
                "trusted_keys_base64": [keys["public_key_base64"]],
                "carriers": ["zero_width"],
            }),
        );
        assert_eq!(verified["provenance_holds"], json!(true));
        assert_eq!(verified["claims"][0]["binding"], json!("in_band"));
        assert!(verified["claims"][0]["assertion_kinds"]
            .as_array()
            .unwrap()
            .contains(&json!("ai_generated")));
    }

    #[test]
    fn an_in_band_record_too_large_for_the_document_is_refused_with_the_shortfall() {
        let keys = done("authorship_keypair", json!({}));
        let (code, reason) = refusal(
            "provenance_sign",
            json!({
                "cover": "ok thanks",
                "assertions": [{ "kind": "human_authorship" }],
                "private_key_base64": keys["private_key_base64"],
                "binding": "in_band",
                "carrier": "homoglyph",
            }),
        );
        assert_eq!(code, "capacity_exceeded");
        assert!(reason.contains("bits"), "the refusal must name the arithmetic: {reason}");
    }

    #[test]
    fn the_distinct_key_rule_keeps_a_pipeline_key_from_passing_as_a_human_key() {
        let human = done("authorship_keypair", json!({}));
        let pipeline = done("authorship_keypair", json!({}));
        let cover = signing_cover();

        // The pipeline key signs a claim that asserts human authorship.
        let signed = done(
            "provenance_sign",
            json!({
                "cover": cover,
                "assertions": [
                    { "kind": "human_authorship", "author": "Real Human" },
                    { "kind": "ai_generated", "model": "pipeline" }
                ],
                "private_key_base64": pipeline["private_key_base64"],
            }),
        );

        let verified = done(
            "provenance_verify",
            json!({
                "document": cover,
                "sidecar_base64": signed["sidecar"]["base64"],
                "trusted_keys_base64": [human["public_key_base64"], pipeline["public_key_base64"]],
                "require_assertion_signers": [
                    { "kind": "human_authorship", "public_key_base64": human["public_key_base64"] },
                    { "kind": "ai_generated", "public_key_base64": pipeline["public_key_base64"] }
                ],
            }),
        );

        // The signature is valid and the document unaltered, but the pipeline key
        // does not satisfy the human-authorship requirement.
        assert_eq!(verified["provenance_holds"], json!(false));
        let unmet: Vec<String> = verified["unmet_requirements"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["assertion_kind"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(unmet, vec!["human_authorship".to_string()]);
    }

    #[test]
    fn an_empty_assertion_set_is_rejected_by_name() {
        let keys = done("authorship_keypair", json!({}));
        match call(
            "provenance_sign",
            &json!({
                "cover": signing_cover(),
                "assertions": [],
                "private_key_base64": keys["private_key_base64"],
            }),
            &mut store(),
        ) {
            Outcome::BadArguments(reason) => assert!(reason.contains("at least one claim")),
            _ => panic!("an empty assertion set must be rejected"),
        }
    }
}
