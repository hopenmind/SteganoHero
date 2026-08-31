use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::{Parser, Subcommand};
use stegano_core::{
    c2pa_read,
    crypto::{pqc, Aes128, Aes256, Caesar, ChaCha20, Xor},
    error::SteganoError,
    forensic, format,
    license::{self, LicenseBuilder},
    metrics,
    pipeline,
    sovereignty::{self, MarkClass},
    provenance::{
        verify_document, AiGenerated, Assertion, Binding, DetachedBinding, HumanAuthorship,
        InBandBinding, Integrity, ProvenanceClaim, PublicKeyRef, RecipientFingerprint, SignedClaim,
        TrustPolicy,
    },
    signing::{MasterKeyPair, MasterPublicKey},
    stego::{Bidi, Homoglyph, WhitespaceVar, ZeroWidth},
    traits::{CryptoMethod, StegoMethod},
    watermark::fingerprint as canary,
};
// The file layer: inspect/clean the marks a real document (docx, odt, html, md,
// txt) carries. The CLI only wraps it; it reimplements no extraction, clean or
// write-back logic.
use stegano_files::{
    clean_file, conceal_file, convert_file, export_text, extract_text, extract_text_from_path,
    inspect_path, pristine_file, read_image_metadata, read_native_metadata, recover_metadata,
    strip_file, supported_targets, target_from_extension, FileFormat,
};

#[derive(Parser)]
#[command(name = "stegano")]
#[command(about = "SteganoHero, advanced text steganography CLI")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encode hidden data into cover text
    Encode {
        /// Cover text (visible message)
        #[arg(short, long)]
        cover: String,

        /// Secret message to hide
        #[arg(short, long)]
        secret: String,

        /// Steganography method: zero_width, homoglyph
        #[arg(short, long, default_value = "zero_width")]
        method: String,

        /// Encrypt with ChaCha20-Poly1305 (requires --password)
        #[arg(long)]
        encrypt: bool,

        /// Password for encryption
        #[arg(short, long)]
        password: Option<String>,

        /// Seal the secret to a recipient's public key (from pqc keypair) before
        /// hiding it. No shared password; only their secret key opens it.
        #[arg(long)]
        recipient_public_file: Option<String>,

        /// Write the heavy, recovery-robust frame instead of the light default.
        /// It survives a partly damaged or excerpted document, at more overhead.
        #[arg(long)]
        robust: bool,

        /// Saturation mode: fill each carrier's channel to its maximum with the
        /// mark repeated. The aggressive variant, still recoverable, survives a
        /// heavy cut. Overrides --robust (saturation always writes the light frame).
        #[arg(long)]
        saturate: bool,
    },

    /// Decode hidden data from stego text
    Decode {
        /// Stego text containing hidden data (or use --file for a marked document)
        #[arg(short = 't', long)]
        text: Option<String>,

        /// A marked document file to read back instead of --text
        #[arg(long)]
        file: Option<String>,

        /// Steganography method used
        #[arg(short, long, default_value = "zero_width")]
        method: String,

        /// Password for decryption (if encrypted)
        #[arg(short, long)]
        password: Option<String>,

        /// Open a payload sealed to you with your secret key (from pqc keypair).
        /// A wrong key or any tampering is refused by name.
        #[arg(long)]
        recipient_secret_file: Option<String>,
    },

    /// Detect steganographic methods in text
    Detect {
        /// Text to analyze (or use --file for a document)
        #[arg(short = 't', long)]
        text: Option<String>,

        /// A document file to analyze instead of --text
        #[arg(long)]
        file: Option<String>,
    },

    /// Compute noise metrics comparing original and stego text
    Metrics {
        /// Original text (or use --original-file for a document)
        #[arg(long)]
        original: Option<String>,

        /// An original document file instead of --original
        #[arg(long)]
        original_file: Option<String>,

        /// Stego text (or use --stego-file for a document)
        #[arg(long)]
        stego: Option<String>,

        /// A stego document file instead of --stego
        #[arg(long)]
        stego_file: Option<String>,
    },

    /// Generate canary trap: N unique versions of a document for leak tracing
    Canary {
        #[command(subcommand)]
        action: CanaryAction,
    },

    /// Manage steganographic licenses (admin + client)
    License {
        #[command(subcommand)]
        action: LicenseAction,
    },

    /// Forensic analysis: detect all steganographic artifacts in text (FREE)
    Forensic {
        /// Text to analyze (or use --file for a document)
        #[arg(short = 't', long)]
        text: Option<String>,

        /// A document file to analyze instead of --text
        #[arg(long)]
        file: Option<String>,

        /// Output format: human, json
        #[arg(short, long, default_value = "human")]
        format: String,
    },

    /// Report the honest per-carrier capacity of a cover text
    Capacity {
        /// Cover text the payload would go into (or use --file for a document)
        #[arg(short, long)]
        cover: Option<String>,

        /// A document file to measure instead of --cover
        #[arg(long)]
        file: Option<String>,

        /// Limit the report to one method; omit to report every carrier
        #[arg(short, long)]
        method: Option<String>,

        /// Report against the heavy, recovery-robust frame instead of the light default
        #[arg(long)]
        robust: bool,

        /// Output format: human, json
        #[arg(short, long, default_value = "human")]
        format: String,
    },

    /// Recommend the best carrier, mission and density for hiding a secret
    Recommend {
        /// Cover text the secret would go into (or use --file for a document)
        #[arg(short, long)]
        cover: Option<String>,

        /// A document file to weigh instead of --cover
        #[arg(long)]
        file: Option<String>,

        /// The secret to size the recommendation against
        #[arg(short, long)]
        secret: String,

        /// Weigh only this carrier; omit to weigh every carrier and suggest the best
        #[arg(short, long)]
        method: Option<String>,

        /// Account for a ChaCha20-Poly1305 confidentiality layer's overhead
        #[arg(long)]
        encrypt: bool,

        /// Password for the confidentiality layer (with --encrypt)
        #[arg(short, long)]
        password: Option<String>,

        /// Weigh against the heavy, recovery-robust frame instead of the light default
        #[arg(long)]
        robust: bool,

        /// Output format: human, json
        #[arg(short, long, default_value = "human")]
        format: String,
    },

    /// Sign, bind and verify document provenance (authorship and AI disclosure)
    Provenance {
        #[command(subcommand)]
        action: ProvenanceAction,
    },

    /// Inspect and clean the marks your own document carries (AI-regulation tool)
    Document {
        #[command(subcommand)]
        action: DocumentAction,
    },

    /// Read the C2PA content credential a file carries
    C2pa {
        #[command(subcommand)]
        action: C2paAction,
    },

    /// Work with real document files: analyse, conceal, convert, read metadata
    File {
        #[command(subcommand)]
        action: FileAction,
    },

    /// Post-quantum recipient encryption: seal a secret to a public key, open it
    /// with the matching secret key. No shared password, only the keypair.
    Pqc {
        #[command(subcommand)]
        action: PqcAction,
    },

    /// Export a text result (or a document file) to a chosen format, to a file or
    /// stdout. Formats: md, html, txt, tex, rtf, org, rst, asciidoc, ipynb, typ, pdf.
    Export {
        /// The text to export (or use --file for a document)
        #[arg(short = 't', long)]
        text: Option<String>,

        /// A document file to export instead of --text
        #[arg(long)]
        file: Option<String>,

        /// Target format, as an extension (md, html, txt, tex, rtf, org, rst,
        /// asciidoc, ipynb, typ, pdf). md and txt are byte-faithful; pdf is a
        /// self-contained native render.
        #[arg(long)]
        to: String,

        /// Write the exported bytes to this file; omit to write them to stdout.
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
enum PqcAction {
    /// Generate a recipient keypair, written to {output}.pqc-public and
    /// {output}.pqc-secret as base64. The public half is what senders seal to.
    Keypair {
        /// Output path prefix for the two key files
        #[arg(short, long)]
        output: String,
    },

    /// Seal a secret to a recipient's public key. Prints the sealed payload as
    /// base64, ready to send or to hide inside a cover text with conceal.
    Seal {
        /// Path to the recipient's public key file (base64, from keypair)
        #[arg(short = 'p', long)]
        recipient_public_file: String,

        /// The secret text to seal
        #[arg(short = 't', long)]
        text: String,
    },

    /// Open a sealed payload with the recipient's secret key. A wrong key, a
    /// truncated payload, or any tampering is refused by name, never a partial.
    Open {
        /// Path to the recipient's secret key file (base64, from keypair)
        #[arg(short = 's', long)]
        secret_file: String,

        /// The sealed payload as base64 (from seal)
        #[arg(short = 'S', long)]
        sealed: String,
    },
}

#[derive(Subcommand)]
enum CanaryAction {
    /// Generate watermarked versions for each recipient
    Generate {
        /// The document text to watermark (or use --file for a document)
        #[arg(short = 't', long)]
        text: Option<String>,

        /// A document file to watermark instead of --text
        #[arg(long)]
        file: Option<String>,

        /// Comma-separated list of recipient IDs
        #[arg(short, long)]
        recipients: String,

        /// Salt for fingerprint derivation (use a unique value per document)
        #[arg(short, long)]
        salt: String,
    },

    /// Identify who leaked a document
    Identify {
        /// The leaked document text (or use --file for a document)
        #[arg(short = 't', long)]
        text: Option<String>,

        /// A leaked document file to trace instead of --text
        #[arg(long)]
        file: Option<String>,

        /// Path to recipient registry JSON (output from generate)
        #[arg(short, long)]
        registry: String,
    },
}

#[derive(Subcommand)]
enum LicenseAction {
    /// Generate a new Ed25519 key pair for signing licenses
    Keygen {
        /// Output file prefix (creates <prefix>.key and <prefix>.pub)
        #[arg(short, long, default_value = "steganohero")]
        output: String,
    },

    /// Generate a signed license embedded in cover text (admin)
    Generate {
        /// Licensee name (who holds this license)
        #[arg(short, long)]
        licensee: String,

        /// Comma-separated module IDs to authorize
        #[arg(short, long)]
        modules: String,

        /// Path to private key file (.key)
        #[arg(short, long)]
        key_file: String,

        /// Bind to current machine hardware fingerprint
        #[arg(long)]
        hardware: bool,

        /// Bind to organization domain pattern (e.g., "*.company.ch")
        #[arg(long)]
        org: Option<String>,

        /// Expiry date in ISO 8601 (e.g., "2028-01-01T00:00:00Z")
        #[arg(long)]
        expires: Option<String>,

        /// Maximum number of operations allowed
        #[arg(long)]
        max_ops: Option<u64>,

        /// Custom cover text (default: built-in legal paragraph)
        #[arg(long)]
        cover: Option<String>,

        /// Stego method: zero_width, homoglyph
        #[arg(long, default_value = "zero_width")]
        method: String,
    },

    /// Verify a license from stego text (client)
    Verify {
        /// Stego text containing the license
        #[arg(short = 't', long)]
        text: String,

        /// Path to public key file (.pub)
        #[arg(short, long)]
        public_key: String,

        /// Stego method used
        #[arg(long, default_value = "zero_width")]
        method: String,

        /// Also check hardware binding against this machine
        #[arg(long)]
        check_hardware: bool,

        /// Also check org domain against current hostname
        #[arg(long)]
        check_org: bool,
    },

    /// Inspect a license: extract and display its contents
    Inspect {
        /// Stego text containing the license
        #[arg(short = 't', long)]
        text: String,

        /// Path to public key file (.pub)
        #[arg(short, long)]
        public_key: String,

        /// Stego method used
        #[arg(long, default_value = "zero_width")]
        method: String,
    },
}

#[derive(Subcommand)]
enum ProvenanceAction {
    /// Generate an Ed25519 signing identity for provenance records
    Keygen {
        /// Output file prefix (writes <prefix>.key and <prefix>.pub as base64); omit to print the pair
        #[arg(short, long)]
        output: Option<String>,

        /// Output format when printing: human, json
        #[arg(short, long, default_value = "human")]
        format: String,
    },

    /// Attach a signed provenance record to a document
    Sign {
        /// The document to attach the record to (or use --file for a document)
        #[arg(short, long)]
        cover: Option<String>,

        /// A document file to sign instead of --cover
        #[arg(long)]
        file: Option<String>,

        /// The private signing key, as base64 (supply this or --key-file)
        #[arg(long)]
        private_key: Option<String>,

        /// A file holding the base64 private signing key (supply this or --private-key)
        #[arg(long)]
        key_file: Option<String>,

        /// Where the record attaches: detached (a sidecar) or in_band (within the document)
        #[arg(long, default_value = "detached")]
        binding: String,

        /// Carrier for an in-band record: zero_width, whitespace_var, bidi, homoglyph
        #[arg(long, default_value = "zero_width")]
        carrier: String,

        /// Optional creation timestamp, as an ISO 8601 string
        #[arg(long)]
        created: Option<String>,

        /// State a human-authorship claim
        #[arg(long)]
        human: bool,

        /// Optional author label for the human-authorship claim
        #[arg(long)]
        author: Option<String>,

        /// State an AI-generated disclosure claim (Article 50)
        #[arg(long)]
        ai: bool,

        /// Optional model name for the AI-generated claim
        #[arg(long)]
        model: Option<String>,

        /// Optional provider name for the AI-generated claim
        #[arg(long)]
        provider: Option<String>,

        /// Optional system or pipeline version for the AI-generated claim
        #[arg(long)]
        system_version: Option<String>,

        /// State an integrity claim, bound to the document hash
        #[arg(long)]
        integrity: bool,

        /// State a recipient claim for the named recipient (requires --salt)
        #[arg(long)]
        recipient: Option<String>,

        /// Salt for the recipient claim
        #[arg(long)]
        salt: Option<String>,
    },

    /// Verify the provenance record attached to a document
    Verify {
        /// The document to check (or use --file for a document)
        #[arg(short = 'd', long)]
        document: Option<String>,

        /// A document file to check instead of --document
        #[arg(long)]
        file: Option<String>,

        /// A file holding the detached record kept beside the document
        #[arg(long)]
        sidecar_file: Option<String>,

        /// A public key the verifier trusts, as base64 (repeatable)
        #[arg(long = "trusted-key")]
        trusted_key: Vec<String>,

        /// A carrier to read an in-band record from (repeatable)
        #[arg(long = "carrier")]
        carrier: Vec<String>,

        /// Require a claim kind to be signed by a key: kind=public_key_base64 (repeatable)
        #[arg(long = "require")]
        require: Vec<String>,

        /// Output format: human, json
        #[arg(short, long, default_value = "human")]
        format: String,
    },
}

#[derive(Subcommand)]
enum DocumentAction {
    /// Report the marks a document carries, by class and count
    Inspect {
        /// The document text to inspect (supply this or --file)
        #[arg(short, long)]
        document: Option<String>,

        /// A document FILE to inspect, by path (docx, odt, html, md, txt); the format is taken from the extension
        #[arg(long)]
        file: Option<String>,

        /// Output format: human, json
        #[arg(short, long, default_value = "human")]
        format: String,
    },

    /// Remove the chosen mark classes from your own document
    Clean {
        /// The document text to clean (supply this or --file)
        #[arg(short, long)]
        document: Option<String>,

        /// A document FILE to clean, by path (docx, odt, md, txt); the format is taken from the extension
        #[arg(long)]
        file: Option<String>,

        /// Where to write the cleaned FILE; omit to write it back in place (only used with --file)
        #[arg(long)]
        output: Option<String>,

        /// A mark class to remove: zero_width, homoglyph, bidi, whitespace_var (repeatable; omit to remove every removable class)
        #[arg(long = "class")]
        class: Vec<String>,

        /// Output format: human, json
        #[arg(short, long, default_value = "human")]
        format: String,
    },
}

#[derive(Subcommand)]
enum C2paAction {
    /// Read and verify the content credential in a file
    Inspect {
        /// Path to the file to read
        #[arg(long)]
        file: String,

        /// Optional format hint (MIME type or extension); the file name is used when omitted
        #[arg(long)]
        format_hint: Option<String>,

        /// Output format: human, json
        #[arg(short, long, default_value = "human")]
        format: String,
    },
}

#[derive(Subcommand)]
enum FileAction {
    /// Full analysis of a document file's own text
    Analyze {
        /// The document FILE to analyse, by path; the format is taken from the extension
        #[arg(long)]
        file: String,

        /// Output format: human, json
        #[arg(short, long, default_value = "human")]
        format: String,
    },

    /// Hide a secret in a document file and write the marked file in its original format
    Conceal {
        /// The document FILE to mark, by path (text-native formats: md, txt)
        #[arg(long)]
        file: String,

        /// The secret to hide, as text
        #[arg(short, long)]
        secret: String,

        /// Where to write the marked FILE; omit to write it back in place
        #[arg(long)]
        output: Option<String>,

        /// A carrier to use (repeatable; omit to use zero_width): zero_width, homoglyph, bidi, whitespace_var
        #[arg(long = "carrier")]
        carrier: Vec<String>,

        /// Confidentiality layer to apply (omit for none): chacha20_poly1305, aes256_gcm, aes128_gcm, caesar, xor
        #[arg(long)]
        cipher: Option<String>,

        /// Passphrase, required when a cipher is named
        #[arg(long)]
        passphrase: Option<String>,

        /// Saturation mode: fill each carrier's channel with the secret repeated,
        /// the aggressive variant that survives a heavy cut. Still recoverable.
        #[arg(long)]
        saturate: bool,

        /// Output format: human, json
        #[arg(short, long, default_value = "human")]
        format: String,
    },

    /// Convert a document file to another format (declared lossy, never marks)
    Convert {
        /// The SOURCE document FILE, by path; the source format is taken from the extension
        #[arg(long)]
        file: String,

        /// The TARGET format to convert to, as an extension: html, md, txt, tex, rtf, org, rst, adoc, ipynb, typ, pdf
        #[arg(long)]
        target: String,

        /// Where to write the converted FILE
        #[arg(long)]
        output: String,

        /// Output format for the report: human, json
        #[arg(short, long, default_value = "human")]
        format: String,
    },

    /// Read the standard metadata a document or image file carries
    Metadata {
        /// The FILE to read, by path; the format is taken from the extension
        #[arg(long)]
        file: String,

        /// Output format: human, json
        #[arg(short, long, default_value = "human")]
        format: String,
    },

    /// Remove a file's metadata (native and our own channel), leaving the content byte-identical
    Strip {
        /// The FILE to strip, by path; the format is taken from the extension
        #[arg(long)]
        file: String,

        /// Where to write the stripped FILE; omit to write it back in place
        #[arg(long)]
        output: Option<String>,

        /// Output format: human, json
        #[arg(short, long, default_value = "human")]
        format: String,
    },

    /// Pristine-clean a text file: remove every mark class AND every remaining invisible (declared opt-in, names its trade-off)
    Pristine {
        /// The text FILE to pristine-clean, by path (text-native formats: md, txt)
        #[arg(long)]
        file: String,

        /// Where to write the cleaned FILE; omit to write it back in place
        #[arg(long)]
        output: Option<String>,

        /// Output format: human, json
        #[arg(short, long, default_value = "human")]
        format: String,
    },
}

fn get_stego_method(name: &str) -> Box<dyn StegoMethod> {
    match name {
        "zero_width" | "zw" => Box::new(ZeroWidth::new()),
        "homoglyph" | "hg" => Box::new(Homoglyph::new()),
        "bidi" | "bidirectional" => Box::new(Bidi::new()),
        "whitespace_var" | "ws" => Box::new(WhitespaceVar::new()),
        other => {
            eprintln!("Unknown method: {other}. Available: zero_width, homoglyph, bidi, whitespace_var");
            std::process::exit(1);
        }
    }
}

#[derive(serde::Serialize)]
struct CarrierCapacityReport {
    carrier: String,
    positions: usize,
    secret_bytes: usize,
    framed_bytes: usize,
    overhead_bytes: usize,
    cover_bounds_writes: bool,
    zero_reason: Option<String>,
}

/// Explain a zero, or `None` when the figure is not zero. Mirrors the reasons
/// the other surfaces give, so every surface answers the same way.
fn capacity_zero_reason(
    positions: usize,
    cover_bounds_writes: bool,
    framed_bytes: usize,
    secret_bytes: usize,
) -> Option<String> {
    if secret_bytes > 0 {
        return None;
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
    Some(reason)
}

/// The honest capacity of one carrier on one cover, every deduction named, for
/// the chosen frame.
fn carrier_capacity_report(
    method: &dyn StegoMethod,
    cover: &str,
    frame_mode: pipeline::FrameMode,
) -> CarrierCapacityReport {
    let positions = if method.check_writable(cover).is_ok() {
        method.positions(cover)
    } else {
        0
    };
    let bounded = format::cover_bounds_writes(method, cover);
    let single: [&dyn StegoMethod; 1] = [method];
    let (secret_bytes, framed_bytes, overhead_bytes) =
        match pipeline::capacity_framed(cover, &single, None, frame_mode)
    {
        Ok(capacity) => {
            let carrier = &capacity.carriers[0];
            (
                carrier.secret_bytes,
                carrier.framed_bytes,
                carrier.overhead_bytes,
            )
        }
        Err(_) => (0, 0, 0),
    };
    CarrierCapacityReport {
        carrier: method.id().to_string(),
        positions,
        secret_bytes,
        framed_bytes,
        overhead_bytes,
        cover_bounds_writes: bounded,
        zero_reason: capacity_zero_reason(positions, bounded, framed_bytes, secret_bytes),
    }
}

/// The four carriers, in application order, for the whole-report path.
fn all_capacity_methods() -> Vec<Box<dyn StegoMethod>> {
    vec![
        Box::new(ZeroWidth::new()),
        Box::new(WhitespaceVar::new()),
        Box::new(Bidi::new()),
        Box::new(Homoglyph::new()),
    ]
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encode {
            cover,
            secret,
            method,
            encrypt,
            password,
            recipient_public_file,
            robust,
            saturate,
        } => {
            let stego_method = get_stego_method(&method);
            let chacha = ChaCha20::new();

            let crypto: Option<(&dyn CryptoMethod, &str)> = if encrypt {
                let pw = password.as_deref().unwrap_or_else(|| {
                    eprintln!("--encrypt requires --password");
                    std::process::exit(1);
                });
                Some((&chacha, pw))
            } else {
                None
            };

            // Optional post-quantum recipient sealing, applied to the secret
            // BEFORE placement: the insertion engine sees ordinary bytes.
            let payload: Vec<u8> = match &recipient_public_file {
                None => secret.as_bytes().to_vec(),
                Some(path) => {
                    let public = read_pqc_key_file(path);
                    pqc::seal(&public, secret.as_bytes()).unwrap_or_else(|e| {
                        eprintln!("[error] seal refused: {e}");
                        std::process::exit(1);
                    })
                }
            };

            let frame_mode = pipeline::FrameMode::from_robust(robust);
            match pipeline::encode_composed(
                &cover,
                &payload,
                &[stego_method.as_ref()],
                crypto,
                frame_mode,
                saturate,
            ) {
                Ok(result) => {
                    println!("{}", result.stego_text);
                    // The honest overlay: what the analyser sees on the produced
                    // document. Placement is permissive; this keeps it honest.
                    let report = pipeline::overflow_report(&result.stego_text);
                    eprintln!(
                        "[info] methods: {:?}, capacity: {}/{} bits, density: {:.4}, verdict: {}",
                        result.methods_used,
                        result.capacity_used_bits,
                        result.capacity_available_bits,
                        report.noise_density,
                        report.verdict
                    );
                }
                Err(e) => {
                    eprintln!("[error] {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Decode {
            text,
            file,
            method,
            password,
            recipient_secret_file,
        } => {
            // A marked document file is read back exactly as pasted stego text is:
            // its text is extracted first, then the same reveal path runs.
            let text = resolve_text_subject(text, file, "text");
            let stego_method = get_stego_method(&method);
            let chacha = ChaCha20::new();
            let crypto_methods: Vec<&dyn CryptoMethod> = vec![&chacha];

            match pipeline::decode(&text, &[stego_method.as_ref()], &crypto_methods, password.as_deref()) {
                Ok(result) => {
                    // Optional post-quantum recipient opening, applied AFTER
                    // extraction. A wrong key or tampering is refused by name.
                    let revealed: Vec<u8> = match &recipient_secret_file {
                        None => result.hidden_data,
                        Some(path) => {
                            let secret = read_pqc_key_file(path);
                            pqc::open(&secret, &result.hidden_data).unwrap_or_else(|e| {
                                eprintln!("[error] open refused: {e}");
                                std::process::exit(1);
                            })
                        }
                    };
                    match String::from_utf8(revealed) {
                        Ok(text) => println!("{text}"),
                        Err(e) => {
                            eprintln!("[warn] data is not valid UTF-8, showing hex");
                            println!("{}", e.into_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>());
                        }
                    }
                    eprintln!(
                        "[info] integrity: {}, crypto: {:?}",
                        if result.integrity_valid { "OK" } else { "FAILED" },
                        result.crypto_used.as_deref().unwrap_or("none")
                    );
                }
                Err(e) => {
                    eprintln!("[error] {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Detect { text, file } => {
            let text = resolve_text_subject(text, file, "text");
            let zw = ZeroWidth::new();
            let hg = Homoglyph::new();
            let bd = Bidi::new();
            let ws = WhitespaceVar::new();
            let methods: Vec<&dyn StegoMethod> = vec![&zw, &hg, &bd, &ws];

            let result = pipeline::detect(&text, &methods);

            if result.methods.is_empty() {
                println!("No steganographic content detected.");
            } else {
                println!("Detected methods:");
                for m in &result.methods {
                    println!("  - {} ({}): {:.1}% confidence", m.name, m.id, m.confidence * 100.0);
                }
                println!("Overall confidence: {:.1}%", result.overall_confidence * 100.0);
            }
        }

        Commands::Metrics { original, original_file, stego, stego_file } => {
            let original = resolve_text_subject(original, original_file, "original");
            let stego = resolve_text_subject(stego, stego_file, "stego");
            let m = metrics::compute_metrics(&original, &stego);
            println!("Shannon entropy delta: {:.4}", m.shannon_delta);
            println!("Noise density:         {:.4}", m.noise_density);
            println!("Perplexity impact:     {:.4}", m.perplexity_delta);
            println!("Survival score:        {:.4}", m.survival_score);
        }

        Commands::License { action } => match action {
            LicenseAction::Keygen { output } => {
                let keypair = MasterKeyPair::generate();
                let private_bytes = keypair.private_bytes();
                let public_bytes = keypair.public_key().to_bytes();

                let private_hex: String = private_bytes.iter().map(|b| format!("{b:02x}")).collect();
                let public_hex: String = public_bytes.iter().map(|b| format!("{b:02x}")).collect();

                let key_path = format!("{output}.key");
                let pub_path = format!("{output}.pub");

                std::fs::write(&key_path, &private_hex).unwrap_or_else(|e| {
                    eprintln!("[error] Cannot write {key_path}: {e}");
                    std::process::exit(1);
                });
                std::fs::write(&pub_path, &public_hex).unwrap_or_else(|e| {
                    eprintln!("[error] Cannot write {pub_path}: {e}");
                    std::process::exit(1);
                });

                eprintln!("[info] Key pair generated:");
                eprintln!("  Private key: {key_path} (KEEP SECRET!)");
                eprintln!("  Public key:  {pub_path} (embed in binaries)");
                println!("{public_hex}");
            }

            LicenseAction::Generate {
                licensee,
                modules,
                key_file,
                hardware,
                org,
                expires,
                max_ops,
                cover,
                method,
            } => {
                // Load private key
                let key_hex = std::fs::read_to_string(&key_file).unwrap_or_else(|e| {
                    eprintln!("[error] Cannot read key file '{key_file}': {e}");
                    std::process::exit(1);
                });
                let key_bytes = hex_to_32_bytes(key_hex.trim());
                let keypair = MasterKeyPair::from_private_bytes(&key_bytes);

                // Build license
                let module_ids: Vec<&str> = modules.split(',').map(|s| s.trim()).collect();
                let mut builder = LicenseBuilder::new(&licensee).modules(&module_ids);

                if hardware {
                    let fp = license::machine_fingerprint();
                    eprintln!("[info] Hardware fingerprint: {fp}");
                    builder = builder.hardware(&fp);
                }
                if let Some(ref o) = org {
                    builder = builder.org(o);
                }
                if let Some(ref e) = expires {
                    builder = builder.expires(e);
                }
                if let Some(n) = max_ops {
                    builder = builder.max_ops(n);
                }

                let lic = builder.build();
                let stego_method = get_stego_method(&method);
                let cover_text = cover.as_deref().unwrap_or_else(|| license::default_license_cover());

                match license::sign_and_embed(&lic, &keypair, cover_text, stego_method.as_ref()) {
                    Ok(stego_text) => {
                        println!("{stego_text}");
                        eprintln!("[info] License generated:");
                        eprintln!("  ID:       {}", lic.id);
                        eprintln!("  Licensee: {}", lic.licensee);
                        eprintln!("  Modules:  {:?}", lic.modules);
                        eprintln!("  Canary:   {}", lic.canary);
                        if let Some(ref e) = lic.expires {
                            eprintln!("  Expires:  {e}");
                        } else {
                            eprintln!("  Expires:  perpetual");
                        }
                    }
                    Err(e) => {
                        eprintln!("[error] {e}");
                        std::process::exit(1);
                    }
                }
            }

            LicenseAction::Verify {
                text,
                public_key,
                method,
                check_hardware,
                check_org,
            } => {
                let pubkey = load_public_key(&public_key);
                let stego_method = get_stego_method(&method);

                // The claim is now bound to the document hash, so any framing the
                // shell adds around the text is an alteration. Strip the trailing
                // newline a pipe or a here-doc appends before verifying.
                match license::extract_and_verify(text.trim_end(), &pubkey, stego_method.as_ref()) {
                    Ok(lic) => {
                        println!("Signature: VALID");
                        println!("Licensee:  {}", lic.licensee);
                        println!("Modules:   {}", lic.modules.join(", "));

                        // Optional checks
                        let mut all_ok = true;

                        if check_hardware {
                            let fp = license::machine_fingerprint();
                            match lic.check_hardware(&fp) {
                                Ok(()) => println!("Hardware:  OK"),
                                Err(e) => { println!("Hardware:  FAILED, {e}"); all_ok = false; }
                            }
                        }

                        if check_org {
                            let hostname = hostname::get()
                                .map(|h| h.to_string_lossy().to_string())
                                .unwrap_or_else(|_| "unknown".into());
                            match lic.check_org(&hostname) {
                                Ok(()) => println!("Org:       OK ({hostname})"),
                                Err(e) => { println!("Org:       FAILED, {e}"); all_ok = false; }
                            }
                        }

                        if let Some(ref exp) = lic.expires {
                            // Use current time for expiry check
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            let now_iso = format_timestamp(now);
                            match lic.check_expiry(&now_iso) {
                                Ok(()) => println!("Expiry:    OK (until {exp})"),
                                Err(_) => { println!("Expiry:    EXPIRED ({exp})"); all_ok = false; }
                            }
                        } else {
                            println!("Expiry:    perpetual");
                        }

                        if !all_ok {
                            std::process::exit(1);
                        }
                    }
                    Err(e) => {
                        println!("Signature: INVALID, {e}");
                        std::process::exit(1);
                    }
                }
            }

            LicenseAction::Inspect {
                text,
                public_key,
                method,
            } => {
                let pubkey = load_public_key(&public_key);
                let stego_method = get_stego_method(&method);

                // The claim is now bound to the document hash, so any framing the
                // shell adds around the text is an alteration. Strip the trailing
                // newline a pipe or a here-doc appends before verifying.
                match license::extract_and_verify(text.trim_end(), &pubkey, stego_method.as_ref()) {
                    Ok(lic) => {
                        println!("{}", serde_json::to_string_pretty(&lic).unwrap());
                    }
                    Err(e) => {
                        eprintln!("[error] {e}");
                        std::process::exit(1);
                    }
                }
            }
        },

        Commands::Forensic { text, file, format } => {
            let text = resolve_text_subject(text, file, "text");
            let report = forensic::analyze(&text);

            match format.as_str() {
                "json" => {
                    println!("{}", serde_json::to_string_pretty(&report).unwrap());
                }
                _ => {
                    // Human-readable output
                    for line in &report.summary {
                        println!("{line}");
                    }

                    if !report.unicode_analysis.invisible_breakdown.is_empty() {
                        println!("\nInvisible character breakdown:");
                        let mut entries: Vec<_> = report.unicode_analysis.invisible_breakdown.iter().collect();
                        entries.sort_by(|a, b| b.1.cmp(a.1));
                        for (name, count) in entries {
                            println!("  {count:>4}x {name}");
                        }
                    }

                    if !report.unicode_analysis.unusual_categories.is_empty() {
                        println!("\nUnusual Unicode characters:");
                        for uc in &report.unicode_analysis.unusual_categories {
                            println!("  {}: {} ({}) x{}", uc.codepoint, uc.character, uc.category, uc.count);
                        }
                    }

                    println!("\nSuspicion score: {:.0}%", report.suspicion_score * 100.0);
                }
            }

            // Exit with non-zero if suspicious or worse
            if !matches!(report.verdict, forensic::Verdict::Clean) {
                std::process::exit(2);
            }
        }

        Commands::Capacity { cover, file, method, robust, format } => {
            let cover = resolve_text_subject(cover, file, "cover");
            let frame_mode = pipeline::FrameMode::from_robust(robust);
            let methods: Vec<Box<dyn StegoMethod>> = match method {
                Some(name) => vec![get_stego_method(&name)],
                None => all_capacity_methods(),
            };
            let reports: Vec<CarrierCapacityReport> = methods
                .iter()
                .map(|m| carrier_capacity_report(m.as_ref(), &cover, frame_mode))
                .collect();

            match format.as_str() {
                "json" => {
                    println!("{}", serde_json::to_string_pretty(&reports).unwrap());
                }
                _ => {
                    for report in &reports {
                        let bound = if report.cover_bounds_writes {
                            "bounded by the cover"
                        } else {
                            "not bounded by the cover"
                        };
                        println!(
                            "{}: {} bytes accepted (framed {}, overhead {}, {} positions, {})",
                            report.carrier,
                            report.secret_bytes,
                            report.framed_bytes,
                            report.overhead_bytes,
                            report.positions,
                            bound
                        );
                        if let Some(reason) = &report.zero_reason {
                            println!("  {reason}");
                        }
                    }
                }
            }
        }

        Commands::Recommend { cover, file, secret, method, encrypt, password, robust, format } => {
            let cover = resolve_text_subject(cover, file, "cover");
            let methods: Vec<Box<dyn StegoMethod>> = match method {
                Some(name) => vec![get_stego_method(&name)],
                None => all_capacity_methods(),
            };
            let refs: Vec<&dyn StegoMethod> = methods.iter().map(|m| m.as_ref()).collect();

            let chacha = ChaCha20::new();
            let crypto: Option<(&dyn CryptoMethod, &str)> = if encrypt {
                let pw = password.as_deref().unwrap_or_else(|| {
                    eprintln!("--encrypt requires --password");
                    std::process::exit(1);
                });
                Some((&chacha, pw))
            } else {
                None
            };

            let frame_mode = pipeline::FrameMode::from_robust(robust);
            let rec = pipeline::recommend_framed(&cover, secret.as_bytes(), &refs, crypto, frame_mode)
                .unwrap_or_else(|e| {
                    eprintln!("[error] {e}");
                    std::process::exit(1);
                });

            match format.as_str() {
                "json" => {
                    println!("{}", serde_json::to_string_pretty(&rec).unwrap());
                }
                _ => {
                    if rec.fits {
                        println!(
                            "recommended: {} at {} (density {:.2}), {} envelope bytes fit with margin",
                            rec.carrier.as_deref().unwrap_or("-"),
                            rec.mission.as_deref().unwrap_or("-"),
                            rec.density.unwrap_or(0.0),
                            rec.envelope_bytes
                        );
                    } else {
                        println!(
                            "no carrier holds this {} byte secret ({} envelope bytes) without overflow: short by {} bytes",
                            rec.secret_bytes, rec.envelope_bytes, rec.shortfall_bytes
                        );
                    }
                    for c in &rec.carriers {
                        let mission = c.strictest_mission.as_deref().unwrap_or("none fits");
                        println!(
                            "  {}: holds {} envelope bytes, fill {:.2}, strictest mission: {}",
                            c.carrier, c.frame_capacity_bytes, c.fill_ratio, mission
                        );
                    }
                }
            }
        }

        Commands::Provenance { action } => handle_provenance(action),

        Commands::Document { action } => handle_document(action),

        Commands::C2pa { action } => handle_c2pa(action),

        Commands::File { action } => handle_file(action),

        Commands::Pqc { action } => handle_pqc(action),

        Commands::Export { text, file, to, output } => {
            let content = resolve_text_subject(text, file, "text");
            let ext = to.rsplit(['.', '/', '\\']).next().unwrap_or(&to).trim();
            let target = target_from_extension(ext).unwrap_or_else(|| {
                eprintln!("[error] unknown export target '{to}'");
                std::process::exit(1);
            });
            let bytes = export_text(&content, target).unwrap_or_else(|e| {
                eprintln!("[error] export refused: {e}");
                std::process::exit(1);
            });
            match output {
                Some(path) => {
                    std::fs::write(&path, &bytes).unwrap_or_else(|e| {
                        eprintln!("[error] cannot write {path}: {e}");
                        std::process::exit(1);
                    });
                    eprintln!("[info] wrote {} bytes to {path}", bytes.len());
                }
                None => {
                    use std::io::Write;
                    std::io::stdout().write_all(&bytes).unwrap_or_else(|e| {
                        eprintln!("[error] cannot write to stdout: {e}");
                        std::process::exit(1);
                    });
                }
            }
        }

        Commands::Canary { action } => match action {
            CanaryAction::Generate { text, file, recipients, salt } => {
                let text = resolve_text_subject(text, file, "text");
                let ids: Vec<&str> = recipients.split(',').map(|s| s.trim()).collect();

                match canary::generate_batch(&text, &ids, &salt) {
                    Ok(batch) => {
                        eprintln!(
                            "[info] Generated {} versions, {} fingerprint bits, max {} recipients",
                            batch.versions.len(), batch.fingerprint_bits, batch.max_recipients
                        );

                        // Output each version
                        for v in &batch.versions {
                            println!("--- {} (fp: {}) ---", v.recipient.id, v.recipient.fingerprint_hash);
                            println!("{}", v.text);
                            println!();
                        }

                        // Output registry JSON to stderr (can redirect to file)
                        let registry: Vec<_> = batch.versions.iter().map(|v| &v.recipient).collect();
                        let registry_json = serde_json::to_string_pretty(&registry).unwrap();
                        eprintln!("\n[registry] Save this to identify leaks later:\n{registry_json}");
                    }
                    Err(e) => {
                        eprintln!("[error] {e}");
                        std::process::exit(1);
                    }
                }
            }

            CanaryAction::Identify { text, file, registry } => {
                let text = resolve_text_subject(text, file, "text");
                let registry_json = std::fs::read_to_string(&registry).unwrap_or_else(|e| {
                    eprintln!("[error] Cannot read registry file '{registry}': {e}");
                    std::process::exit(1);
                });

                let recipients: Vec<canary::Recipient> = serde_json::from_str(&registry_json)
                    .unwrap_or_else(|e| {
                        eprintln!("[error] Invalid registry JSON: {e}");
                        std::process::exit(1);
                    });

                match canary::identify_leak(&text, &recipients) {
                    Ok(result) => {
                        if let Some(ref r) = result.recipient {
                            println!("LEAK IDENTIFIED: {}", r.id);
                            println!("Fingerprint hash: {}", r.fingerprint_hash);
                            println!("Confidence: {:.0}%", result.confidence * 100.0);
                        } else if result.confidence > 0.0 {
                            println!("Watermark detected but no matching recipient found.");
                            println!("Confidence: {:.0}%", result.confidence * 100.0);
                        } else {
                            println!("No watermark detected in this text.");
                        }
                    }
                    Err(e) => {
                        eprintln!("[error] {e}");
                        std::process::exit(1);
                    }
                }
            }
        },
    }
}

// ─── Provenance ─────────────────────────────────────────────
//
// A signing identity is an Ed25519 key pair. The private key is an input to
// signing and the deliberate output of keygen; it is never echoed on stderr and
// never printed by sign or verify.

/// Decode a base64 32 byte key, exiting by name on a bad value.
fn decode_key_32(text: &str, what: &str) -> [u8; 32] {
    let bytes = B64.decode(text.trim()).unwrap_or_else(|_| {
        eprintln!("[error] {what} is not valid base64");
        std::process::exit(1);
    });
    bytes.as_slice().try_into().unwrap_or_else(|_| {
        eprintln!("[error] {what} must decode to 32 bytes, got {}", bytes.len());
        std::process::exit(1);
    })
}

/// Build a trusted-key reference from a base64 public key.
fn public_key_ref(text: &str) -> PublicKeyRef {
    let bytes = decode_key_32(text, "a public key");
    let public = MasterPublicKey::from_bytes(&bytes).unwrap_or_else(|e| {
        eprintln!("[error] invalid public key: {e}");
        std::process::exit(1);
    });
    PublicKeyRef::ed25519(&public)
}

fn handle_provenance(action: ProvenanceAction) {
    match action {
        ProvenanceAction::Keygen { output, format } => {
            let keypair = MasterKeyPair::generate();
            let private_b64 = B64.encode(keypair.private_bytes());
            let public_b64 = B64.encode(keypair.public_key().to_bytes());

            match output {
                Some(prefix) => {
                    let key_path = format!("{prefix}.key");
                    let pub_path = format!("{prefix}.pub");
                    std::fs::write(&key_path, &private_b64).unwrap_or_else(|e| {
                        eprintln!("[error] cannot write {key_path}: {e}");
                        std::process::exit(1);
                    });
                    std::fs::write(&pub_path, &public_b64).unwrap_or_else(|e| {
                        eprintln!("[error] cannot write {pub_path}: {e}");
                        std::process::exit(1);
                    });
                    eprintln!("[info] provenance key pair written:");
                    eprintln!("  private key: {key_path} (keep this secret)");
                    eprintln!("  public key:  {pub_path}");
                    // Public half to stdout, private half never echoed here.
                    println!("{public_b64}");
                }
                None => {
                    // The private key is the deliberate output of keygen, so it
                    // goes to stdout, never stderr, and never into a log line.
                    if format == "json" {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "private_key_base64": private_b64,
                                "public_key_base64": public_b64,
                            }))
                            .unwrap()
                        );
                    } else {
                        println!("private_key_base64 {private_b64}");
                        println!("public_key_base64 {public_b64}");
                    }
                    eprintln!("[info] keep the private key secret. It is not stored anywhere.");
                }
            }
        }

        ProvenanceAction::Sign {
            cover,
            file,
            private_key,
            key_file,
            binding,
            carrier,
            created,
            human,
            author,
            ai,
            model,
            provider,
            system_version,
            integrity,
            recipient,
            salt,
        } => {
            let cover = resolve_text_subject(cover, file, "cover");
            let private_b64 = match (private_key, key_file) {
                (Some(_), Some(_)) => {
                    eprintln!("[error] supply either --private-key or --key-file, not both");
                    std::process::exit(1);
                }
                (Some(key), None) => key,
                (None, Some(path)) => std::fs::read_to_string(&path).unwrap_or_else(|e| {
                    eprintln!("[error] cannot read key file '{path}': {e}");
                    std::process::exit(1);
                }),
                (None, None) => {
                    eprintln!("[error] a signing key is required: pass --private-key or --key-file");
                    std::process::exit(1);
                }
            };
            let key_bytes = decode_key_32(&private_b64, "the private key");
            let keypair = MasterKeyPair::from_private_bytes(&key_bytes);
            let public = keypair.public_key();

            // Build the assertion set from the flags.
            let mut assertions: Vec<Box<dyn Assertion>> = Vec::new();
            if human {
                assertions.push(Box::new(HumanAuthorship { author }));
            }
            if ai {
                assertions.push(Box::new(AiGenerated {
                    model,
                    provider,
                    system_version,
                }));
            }
            if integrity {
                let hash = license::document_hash(&cover).unwrap_or_else(|e| {
                    eprintln!("[error] could not compute the document hash: {e}");
                    std::process::exit(1);
                });
                assertions.push(Box::new(Integrity {
                    document_hash: hash,
                }));
            }
            if let Some(recipient_id) = recipient {
                let salt = salt.unwrap_or_else(|| {
                    eprintln!("[error] --recipient requires --salt");
                    std::process::exit(1);
                });
                let rf = RecipientFingerprint::derive(&recipient_id, &salt, &cover)
                    .unwrap_or_else(|e| {
                        eprintln!("[error] the recipient claim could not be derived: {e}");
                        std::process::exit(1);
                    });
                assertions.push(Box::new(rf));
            }
            if assertions.is_empty() {
                eprintln!(
                    "[error] name at least one claim: --human, --ai, --integrity, or --recipient"
                );
                std::process::exit(1);
            }

            let refs: Vec<&dyn Assertion> = assertions.iter().map(|a| a.as_ref()).collect();
            let claim = ProvenanceClaim::new(&refs, &cover, &public, created).unwrap_or_else(|e| {
                eprintln!("[error] {e}");
                std::process::exit(1);
            });
            let signed = SignedClaim::sign(claim, &keypair).unwrap_or_else(|e| {
                eprintln!("[error] {e}");
                std::process::exit(1);
            });

            match binding.as_str() {
                "detached" => {
                    let out = DetachedBinding::new()
                        .bind(&cover, &signed)
                        .unwrap_or_else(|e| {
                            eprintln!("[error] {e}");
                            std::process::exit(1);
                        });
                    // The sidecar is JSON; print it to stdout so it can be saved.
                    match String::from_utf8(out.bytes) {
                        Ok(sidecar) => println!("{sidecar}"),
                        Err(_) => {
                            eprintln!("[error] the sidecar was not valid text");
                            std::process::exit(1);
                        }
                    }
                    eprintln!(
                        "[info] detached provenance record written. Keep it beside the document."
                    );
                }
                "in_band" => {
                    let method = get_stego_method(&carrier);
                    match InBandBinding::new(method.as_ref()).bind(&cover, &signed) {
                        Ok(out) => match String::from_utf8(out.bytes) {
                            Ok(marked) => {
                                let realised =
                                    InBandBinding::new(method.as_ref()).realised_robustness(&marked);
                                println!("{marked}");
                                eprintln!(
                                    "[info] in-band provenance record placed. Measured robustness: {:?}.",
                                    realised.class
                                );
                            }
                            Err(_) => {
                                eprintln!("[error] the in-band record was not valid text");
                                std::process::exit(1);
                            }
                        },
                        Err(SteganoError::CapacityExceeded { needed, available }) => {
                            eprintln!(
                                "[error] the document cannot carry this record in-band through '{carrier}': needs {needed} bits, the document offers {available} bits"
                            );
                            std::process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("[error] {e}");
                            std::process::exit(1);
                        }
                    }
                }
                other => {
                    eprintln!("[error] --binding must be detached or in_band, got '{other}'");
                    std::process::exit(1);
                }
            }
        }

        ProvenanceAction::Verify {
            document,
            file,
            sidecar_file,
            trusted_key,
            carrier,
            require,
            format,
        } => {
            let document = resolve_text_subject(document, file, "document");
            let sidecar_bytes = sidecar_file.map(|path| {
                std::fs::read(&path).unwrap_or_else(|e| {
                    eprintln!("[error] cannot read sidecar file '{path}': {e}");
                    std::process::exit(1);
                })
            });

            let trusted: Vec<PublicKeyRef> =
                trusted_key.iter().map(|key| public_key_ref(key)).collect();
            let mut policy = TrustPolicy::new(trusted);
            for entry in &require {
                let (kind, key) = entry.split_once('=').unwrap_or_else(|| {
                    eprintln!("[error] --require must be kind=public_key_base64, got '{entry}'");
                    std::process::exit(1);
                });
                let signer = public_key_ref(key);
                policy = policy.require(kind, &signer);
            }

            let methods: Vec<Box<dyn StegoMethod>> =
                carrier.iter().map(|id| get_stego_method(id)).collect();
            let method_refs: Vec<&dyn StegoMethod> = methods.iter().map(|m| m.as_ref()).collect();

            let report = verify_document(
                &document,
                sidecar_bytes.as_deref(),
                &method_refs,
                &policy,
            )
            .unwrap_or_else(|e| {
                eprintln!("[error] {e}");
                std::process::exit(1);
            });

            let holds = report.strongest.is_some() && report.unmet_requirements.is_empty();

            match format.as_str() {
                "json" => {
                    println!("{}", serde_json::to_string_pretty(&report).unwrap());
                }
                _ => {
                    println!(
                        "Provenance: {}",
                        if holds { "HOLDS" } else { "NOT ESTABLISHED" }
                    );
                    println!("Claims found: {}", report.claims.len());
                    for claim in &report.claims {
                        println!(
                            "  binding {}: signature {}, document {}, signer {}",
                            claim.binding,
                            if claim.signature_valid { "valid" } else { "invalid" },
                            if claim.document_unaltered { "unaltered" } else { "ALTERED" },
                            if claim.signer_trusted { "trusted" } else { "untrusted" },
                        );
                        println!("    claims: {}", claim.assertion_kinds.join(", "));
                        for finding in &claim.findings {
                            println!("    - {finding}");
                        }
                    }
                    for unmet in &report.unmet_requirements {
                        println!("  unmet requirement '{}': {}", unmet.assertion_kind, unmet.reason);
                    }
                }
            }

            if !holds {
                std::process::exit(2);
            }
        }
    }
}

// ─── Document sovereignty (the AI-regulation tool) ──────────
//
// Two questions about a document a person holds: what marks are on it, and,
// for the classes they choose, remove exactly those and leave the rest byte
// for byte. Both delegate to the frozen core. The file side reads a C2PA
// content credential and reports only what the conformant reader validated.

/// Resolve the chosen mark classes, defaulting to every removable class when
/// none is named. An unknown identifier exits by name.
fn resolve_mark_classes(ids: &[String]) -> Vec<MarkClass> {
    if ids.is_empty() {
        return MarkClass::ALL.to_vec();
    }
    ids.iter()
        .map(|id| {
            MarkClass::from_id(id).unwrap_or_else(|| {
                let known: Vec<&str> = MarkClass::ALL.iter().map(|c| c.id()).collect();
                eprintln!("[error] unknown mark class '{id}'. Available: {}", known.join(", "));
                std::process::exit(1);
            })
        })
        .collect()
}

/// Print an inspection report the same way for a text argument and a real file,
/// so both answer in one shape.
fn print_inspection_report(report: &sovereignty::InspectionReport, format: &str) {
    match format {
        "json" => println!("{}", serde_json::to_string_pretty(report).unwrap()),
        _ => {
            println!(
                "Verdict: {} (suspicion {:.0}%)",
                report.verdict,
                report.suspicion_score * 100.0
            );
            println!(
                "Characters: {} total, {} visible, {} invisible",
                report.total_chars, report.visible_chars, report.invisible_chars
            );
            println!("Marks by class:");
            for class in &report.classes {
                println!("  {} ({}): {}", class.label, class.id, class.count);
            }
            if !report.carrier_signatures.is_empty() {
                println!("Carrier signatures:");
                for sig in &report.carrier_signatures {
                    println!(
                        "  {} ({}): confidence {:.0}%, readable payload {}",
                        sig.name,
                        sig.id,
                        sig.confidence * 100.0,
                        if sig.carries_readable_payload { "yes" } else { "no" }
                    );
                }
            }
            if !report.other_invisible.is_empty() {
                println!("Other invisible characters (left in place):");
                for other in &report.other_invisible {
                    println!("  {} {} x{}", other.codepoint, other.category, other.count);
                }
            }
            println!();
            for line in &report.summary {
                println!("{line}");
            }
        }
    }
}

fn handle_document(action: DocumentAction) {
    match action {
        DocumentAction::Inspect { document, file, format } => {
            match (document, file) {
                (Some(_), Some(_)) => {
                    eprintln!("[error] supply either --document or --file, not both");
                    std::process::exit(1);
                }
                (None, None) => {
                    eprintln!("[error] a document is required: pass --document <text> or --file <path>");
                    std::process::exit(1);
                }
                // A real file: read it, infer its format from the extension, and
                // report by name if it cannot be read (unknown format, missing
                // file). The extracted text is inspected exactly as text is.
                (None, Some(path)) => {
                    match inspect_path(std::path::Path::new(&path)) {
                        Ok(report) => print_inspection_report(&report, &format),
                        Err(e) => {
                            eprintln!("[error] {e}");
                            std::process::exit(1);
                        }
                    }
                }
                (Some(document), None) => {
                    let report = sovereignty::inspect(&document);
                    print_inspection_report(&report, &format);
                }
            }
        }

        DocumentAction::Clean { document, file, output, class, format } => {
            let classes = resolve_mark_classes(&class);
            match (document, file) {
                (Some(_), Some(_)) => {
                    eprintln!("[error] supply either --document or --file, not both");
                    std::process::exit(1);
                }
                (None, None) => {
                    eprintln!("[error] a document is required: pass --document <text> or --file <path>");
                    std::process::exit(1);
                }
                (Some(_), None) if output.is_some() => {
                    eprintln!("[error] --output writes a cleaned FILE; it applies to --file, not --document");
                    std::process::exit(1);
                }
                (None, Some(path)) => clean_document_file(&path, output.as_deref(), &classes, &format),
                (Some(document), None) => {
                    let report = sovereignty::clean(&document, &classes);
                    match format.as_str() {
                        "json" => println!("{}", serde_json::to_string_pretty(&report).unwrap()),
                        _ => {
                            // The cleaned document to stdout so it can be piped;
                            // the report and the honest residual note to stderr.
                            println!("{}", report.cleaned_text);
                            eprintln!("[info] altered: {}", report.altered);
                            for removal in &report.removed {
                                eprintln!("  removed {} ({}): {}", removal.label, removal.id, removal.count);
                            }
                            eprintln!("[residual] what a native clean does not address:");
                            for note in &report.residual {
                                eprintln!("  - {note}");
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Clean a real document file and write the cleaned bytes back, either in place
/// or to `output` when given (which never touches the source). A refusal
/// (unknown format, unsupported class combination, lossy encoding, HTML clean,
/// missing file) surfaces the transform's own named message and exits non-zero.
fn clean_document_file(path: &str, output: Option<&str>, classes: &[MarkClass], format: &str) {
    let src = std::path::Path::new(path);
    let file_format = match FileFormat::from_path(src) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[error] {e}");
            std::process::exit(1);
        }
    };
    let bytes = match std::fs::read(src) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("[error] cannot read file '{path}': {e}");
            std::process::exit(1);
        }
    };
    // Wrap the transform: it does the extraction, the surgical clean and the
    // format-faithful write-back. Only the destination is chosen here.
    let outcome = match clean_file(&bytes, file_format, classes) {
        Ok(outcome) => outcome,
        Err(e) => {
            eprintln!("[error] {e}");
            std::process::exit(1);
        }
    };

    let dest = output.unwrap_or(path);
    let in_place = output.is_none();
    // Write in place only when the clean changed the document; write an explicit
    // output every time, so a requested file is always produced.
    if outcome.altered || !in_place {
        if let Err(e) = std::fs::write(dest, &outcome.bytes) {
            eprintln!("[error] cannot write file '{dest}': {e}");
            std::process::exit(1);
        }
    }

    let text_native = matches!(file_format, FileFormat::Markdown | FileFormat::PlainText);
    match format {
        "json" => {
            let report = serde_json::json!({
                "format": file_format.name(),
                "output_path": dest,
                "written_in_place": in_place,
                "altered": outcome.altered,
                "removed": outcome.removed,
                "residual": outcome.residual,
                "byte_count": outcome.bytes.len(),
                "cleaned_text": if text_native {
                    serde_json::Value::String(outcome.cleaned_text.clone())
                } else {
                    serde_json::Value::Null
                },
            });
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        _ => {
            // The destination path to stdout so it can be captured; the report
            // and the honest residual note to stderr.
            println!("{dest}");
            eprintln!(
                "[info] cleaned {} document {} ({} bytes)",
                file_format.name(),
                if in_place { "written in place" } else { "written to a new file" },
                outcome.bytes.len()
            );
            eprintln!("[info] altered: {}", outcome.altered);
            for removal in &outcome.removed {
                eprintln!("  removed {} ({}): {}", removal.label, removal.id, removal.count);
            }
            eprintln!("[residual] what a native clean does not address:");
            for note in &outcome.residual {
                eprintln!("  - {note}");
            }
        }
    }
}

/// Resolve a text subject from either an inline string or a document file. Exactly
/// one must be given: a file is read and its text extracted, so any read-capable
/// command accepts a real document (docx, odt, html, md, txt and the readable
/// formats) as uniformly as pasted text. Every failure exits by name (invariant 2).
fn resolve_text_subject(text: Option<String>, file: Option<String>, flag: &str) -> String {
    match (text, file) {
        (Some(text), None) => text,
        (None, Some(path)) => extract_text_from_path(std::path::Path::new(&path))
            .unwrap_or_else(|e| {
                eprintln!("[error] cannot read document '{path}': {e}");
                std::process::exit(1);
            })
            .text,
        (Some(_), Some(_)) => {
            eprintln!("[error] supply either --{flag} or --file, not both");
            std::process::exit(1);
        }
        (None, None) => {
            eprintln!("[error] supply --{flag} or --file");
            std::process::exit(1);
        }
    }
}

/// Read a base64 PQC key file (public or secret) into bytes, exiting by name on
/// a read or decode failure. Shared by `encode`/`decode` and the `pqc` command.
fn read_pqc_key_file(path: &str) -> Vec<u8> {
    let b64 = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("[error] cannot read {path}: {e}");
        std::process::exit(1);
    });
    B64.decode(b64.trim()).unwrap_or_else(|_| {
        eprintln!("[error] {path} is not valid base64");
        std::process::exit(1);
    })
}

fn handle_pqc(action: PqcAction) {
    match action {
        PqcAction::Keypair { output } => {
            let keypair = pqc::generate_keypair();
            let public_b64 = B64.encode(&keypair.public);
            let secret_b64 = B64.encode(&keypair.secret);

            let public_path = format!("{output}.pqc-public");
            let secret_path = format!("{output}.pqc-secret");

            std::fs::write(&public_path, &public_b64).unwrap_or_else(|e| {
                eprintln!("[error] cannot write {public_path}: {e}");
                std::process::exit(1);
            });
            std::fs::write(&secret_path, &secret_b64).unwrap_or_else(|e| {
                eprintln!("[error] cannot write {secret_path}: {e}");
                std::process::exit(1);
            });

            eprintln!("[info] Recipient keypair generated:");
            eprintln!("  Public key: {public_path} (hand this to senders)");
            eprintln!("  Secret key: {secret_path} (KEEP SECRET, it opens sealed payloads)");
            println!("{public_b64}");
        }

        PqcAction::Seal { recipient_public_file, text } => {
            let public_b64 = std::fs::read_to_string(&recipient_public_file).unwrap_or_else(|e| {
                eprintln!("[error] cannot read {recipient_public_file}: {e}");
                std::process::exit(1);
            });
            let public = B64.decode(public_b64.trim()).unwrap_or_else(|_| {
                eprintln!("[error] public key file is not valid base64");
                std::process::exit(1);
            });
            match pqc::seal(&public, text.as_bytes()) {
                Ok(sealed) => println!("{}", B64.encode(&sealed)),
                Err(e) => {
                    eprintln!("[error] seal refused: {e}");
                    std::process::exit(1);
                }
            }
        }

        PqcAction::Open { secret_file, sealed } => {
            let secret_b64 = std::fs::read_to_string(&secret_file).unwrap_or_else(|e| {
                eprintln!("[error] cannot read {secret_file}: {e}");
                std::process::exit(1);
            });
            let secret = B64.decode(secret_b64.trim()).unwrap_or_else(|_| {
                eprintln!("[error] secret key file is not valid base64");
                std::process::exit(1);
            });
            let sealed_bytes = B64.decode(sealed.trim()).unwrap_or_else(|_| {
                eprintln!("[error] sealed payload is not valid base64");
                std::process::exit(1);
            });
            match pqc::open(&secret, &sealed_bytes) {
                Ok(plaintext) => match String::from_utf8(plaintext) {
                    Ok(text) => println!("{text}"),
                    Err(e) => {
                        // The payload opened but is not text; hand back its bytes
                        // as base64 rather than lose or mangle them (invariant 2).
                        eprintln!("[info] opened payload is not UTF-8 text, emitting base64");
                        println!("{}", B64.encode(e.as_bytes()));
                    }
                },
                Err(e) => {
                    eprintln!("[error] open refused: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}

fn handle_c2pa(action: C2paAction) {
    match action {
        C2paAction::Inspect { file, format_hint, format } => {
            let bytes = std::fs::read(&file).unwrap_or_else(|e| {
                eprintln!("[error] cannot read file '{file}': {e}");
                std::process::exit(1);
            });
            // With no explicit hint, the file name is passed: the reader reduces
            // it to its extension, and detects from the bytes if that fails.
            let hint = format_hint.as_deref().or(Some(file.as_str()));

            match c2pa_read::inspect_c2pa(&bytes, hint) {
                Ok(report) => match format.as_str() {
                    "json" => println!("{}", serde_json::to_string_pretty(&report).unwrap()),
                    _ => {
                        println!("Present: {}", report.present);
                        println!("Verdict: {:?}", report.verdict);
                        if let Some(state) = &report.validation_state {
                            println!("Validation state: {state}");
                        }
                        println!("Trust anchor established: {}", report.trust_anchor_established);
                        if !report.failures.is_empty() {
                            println!("Failures:");
                            for failure in &report.failures {
                                println!("  {}", failure.code);
                            }
                        }
                        if let Some(manifest) = &report.manifest {
                            println!("Manifest:");
                            if let Some(generator) = &manifest.claim_generator {
                                println!("  claimed by: {generator}");
                            }
                            if let Some(title) = &manifest.title {
                                println!("  title: {title}");
                            }
                            if let Some(ai) = &manifest.ai_generation {
                                println!("  {}", ai.note);
                            }
                        }
                        println!();
                        for line in &report.summary {
                            println!("{line}");
                        }
                    }
                },
                Err(e) => {
                    eprintln!("[error] {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}

// ─── File capabilities (the file layer over the CLI) ────────
//
// Four operations over a real document file: a full analysis of its text, a
// surgical conceal that writes the marked file in its ORIGINAL format, a
// declared-lossy conversion to another format, and a read of its standard
// metadata. Each wraps the file layer's own public API and reimplements nothing.
// Every refusal names the format and the reason and exits non-zero (invariant 2).

/// Build a confidentiality layer from its identifier, exiting by name on an
/// unknown one. Mirrors [`get_stego_method`] for the cipher side.
fn get_crypto_method(name: &str) -> Box<dyn CryptoMethod> {
    match name {
        "chacha20_poly1305" | "chacha" => Box::new(ChaCha20::new()),
        "aes256_gcm" | "aes256" => Box::new(Aes256::new()),
        "aes128_gcm" | "aes128" => Box::new(Aes128::new()),
        "caesar" => Box::new(Caesar::new()),
        "xor" => Box::new(Xor::new()),
        other => {
            eprintln!(
                "[error] unknown cipher '{other}'. Available: chacha20_poly1305, aes256_gcm, aes128_gcm, caesar, xor"
            );
            std::process::exit(1);
        }
    }
}

/// Read a file from disk, exiting by name when it cannot be read.
fn read_file_or_exit(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("[error] cannot read file '{path}': {e}");
        std::process::exit(1);
    })
}

/// Resolve a file's SOURCE format from its path extension, exiting by name.
fn source_format_or_exit(path: &str) -> FileFormat {
    FileFormat::from_path(std::path::Path::new(path)).unwrap_or_else(|e| {
        eprintln!("[error] {e}");
        std::process::exit(1);
    })
}

fn handle_file(action: FileAction) {
    match action {
        FileAction::Analyze { file, format } => {
            let bytes = read_file_or_exit(&file);
            let source = source_format_or_exit(&file);
            // Extract the document's own text, then run the same analysis the
            // text path runs. A format whose text cannot be read names itself.
            let extracted = extract_text(&bytes, source).unwrap_or_else(|e| {
                eprintln!("[error] {e}");
                std::process::exit(1);
            });
            let report = forensic::analyze(&extracted.text);
            match format.as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&report).unwrap()),
                _ => {
                    println!("Format: {}", source.name());
                    for line in &report.summary {
                        println!("{line}");
                    }
                    if !report.unicode_analysis.invisible_breakdown.is_empty() {
                        println!("\nInvisible character breakdown:");
                        let mut entries: Vec<_> =
                            report.unicode_analysis.invisible_breakdown.iter().collect();
                        entries.sort_by(|a, b| b.1.cmp(a.1));
                        for (name, count) in entries {
                            println!("  {count:>4}x {name}");
                        }
                    }
                    println!("\nSuspicion score: {:.0}%", report.suspicion_score * 100.0);
                }
            }
        }

        FileAction::Conceal { file, secret, output, carrier, cipher, passphrase, saturate, format } => {
            let bytes = read_file_or_exit(&file);
            let source = source_format_or_exit(&file);

            // Carriers, defaulting to zero_width when none is named.
            let carrier_ids: Vec<String> = if carrier.is_empty() {
                vec!["zero_width".to_string()]
            } else {
                carrier.clone()
            };
            let built: Vec<Box<dyn StegoMethod>> =
                carrier_ids.iter().map(|id| get_stego_method(id)).collect();
            let carrier_refs: Vec<&dyn StegoMethod> = built.iter().map(|b| b.as_ref()).collect();

            // Optional confidentiality layer. A cipher without a passphrase is
            // refused by name (the engine refuses it too, but naming it here is
            // clearer than an empty-passphrase attempt).
            let cipher_built = cipher.as_deref().map(get_crypto_method);
            let crypto: Option<(&dyn CryptoMethod, &str)> = match (&cipher_built, &passphrase) {
                (Some(_), None) => {
                    eprintln!("[error] --cipher requires --passphrase");
                    std::process::exit(1);
                }
                (Some(method), Some(pass)) => Some((method.as_ref(), pass.as_str())),
                (None, _) => None,
            };

            // Wrap the transform: it places the secret and writes the marked file
            // back in the ORIGINAL format, proving the round-trip internally. A
            // container or markup format is refused by name.
            let outcome = match conceal_file(&bytes, source, &secret, &carrier_refs, crypto, saturate) {
                Ok(outcome) => outcome,
                Err(e) => {
                    eprintln!("[error] {e}");
                    std::process::exit(1);
                }
            };

            let dest = output.as_deref().unwrap_or(file.as_str());
            let in_place = output.is_none();
            if let Err(e) = std::fs::write(dest, &outcome.bytes) {
                eprintln!("[error] cannot write file '{dest}': {e}");
                std::process::exit(1);
            }

            match format.as_str() {
                "json" => {
                    let report = serde_json::json!({
                        "format": outcome.format.name(),
                        "output_path": dest,
                        "written_in_place": in_place,
                        "carriers_used": outcome.carriers,
                        "cipher": outcome.cipher,
                        "secret_bytes": outcome.secret_len,
                        "source_byte_count": outcome.source_len,
                        "byte_count": outcome.marked_len,
                        "round_trip": { "verified": true },
                    });
                    println!("{}", serde_json::to_string_pretty(&report).unwrap());
                }
                _ => {
                    println!("{dest}");
                    eprintln!(
                        "[info] marked {} document {} ({} bytes)",
                        outcome.format.name(),
                        if in_place { "written in place" } else { "written to a new file" },
                        outcome.marked_len
                    );
                    eprintln!("[info] carriers: {:?}", outcome.carriers);
                    if let Some(cipher) = &outcome.cipher {
                        eprintln!("[info] cipher: {cipher}");
                    }
                    eprintln!("[info] the mark was read back before the file was written");
                }
            }
        }

        FileAction::Convert { file, target, output, format } => {
            let bytes = read_file_or_exit(&file);
            let source = source_format_or_exit(&file);

            // Resolve the target from its extension. A target this build cannot
            // write is refused by name rather than attempted.
            let ext = target.rsplit(['.', '/', '\\']).next().unwrap_or(&target).trim();
            let target_format = target_from_extension(ext).unwrap_or_else(|| {
                let names: Vec<&str> = supported_targets().into_iter().map(|f| f.name()).collect();
                eprintln!(
                    "[error] converting to '{ext}' is not a supported conversion target in this build; the supported targets are {}, and pdf when a local browser is available",
                    names.join(", ")
                );
                std::process::exit(1);
            });

            // Wrap the conversion: declared lossy, never marks. A source with no
            // extractable text, or a PDF target with no local browser, is refused
            // by name.
            let converted = match convert_file(&bytes, source, target_format) {
                Ok(converted) => converted,
                Err(e) => {
                    eprintln!("[error] {e}");
                    std::process::exit(1);
                }
            };
            if let Err(e) = std::fs::write(&output, &converted) {
                eprintln!("[error] cannot write file '{output}': {e}");
                std::process::exit(1);
            }

            match format.as_str() {
                "json" => {
                    let report = serde_json::json!({
                        "source_format": source.name(),
                        "target_format": target_format.name(),
                        "output_path": output,
                        "source_byte_count": bytes.len(),
                        "byte_count": converted.len(),
                        "lossy": true,
                    });
                    println!("{}", serde_json::to_string_pretty(&report).unwrap());
                }
                _ => {
                    println!("{output}");
                    eprintln!(
                        "[info] converted {} to {} ({} bytes). Conversion is declared lossy and never places a mark.",
                        source.name(),
                        target_format.name(),
                        converted.len()
                    );
                }
            }
        }

        FileAction::Metadata { file, format } => {
            let bytes = read_file_or_exit(&file);
            let source = source_format_or_exit(&file);
            let value = match source {
                FileFormat::Docx | FileFormat::Odt => match read_native_metadata(&bytes, source) {
                    Ok(native) => serde_json::json!({
                        "format": source.name(),
                        "kind": "document",
                        "native_metadata": native,
                        "embedded_channel": cli_embedded_channel_view(&bytes, source),
                    }),
                    Err(e) => {
                        eprintln!("[error] {e}");
                        std::process::exit(1);
                    }
                },
                FileFormat::Jpeg | FileFormat::Tiff | FileFormat::Png | FileFormat::Webp => {
                    match read_image_metadata(&bytes, source) {
                        Ok(image) => serde_json::json!({
                            "format": source.name(),
                            "kind": "image",
                            "image_metadata": image,
                            "embedded_channel": cli_embedded_channel_view(&bytes, source),
                        }),
                        Err(e) => {
                            eprintln!("[error] {e}");
                            std::process::exit(1);
                        }
                    }
                }
                FileFormat::Svg => serde_json::json!({
                    "format": source.name(),
                    "kind": "vector_image",
                    "embedded_channel": cli_embedded_channel_view(&bytes, source),
                }),
                other => {
                    eprintln!(
                        "[error] the {} format carries no metadata this tool reads; metadata reading serves Office documents (docx, odt), images (jpeg, tiff, png, webp), and svg",
                        other.name()
                    );
                    std::process::exit(1);
                }
            };

            match format.as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
                _ => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
            }
        }

        FileAction::Strip { file, output, format } => {
            let bytes = read_file_or_exit(&file);
            let source = source_format_or_exit(&file);

            // Wrap the file-level strip: metadata (native and our channel) removed,
            // the readable content left byte-identical. A format with no strippable
            // metadata surface is refused by name.
            let outcome = match strip_file(&bytes, source) {
                Ok(outcome) => outcome,
                Err(e) => {
                    eprintln!("[error] {e}");
                    std::process::exit(1);
                }
            };

            let dest = output.as_deref().unwrap_or(file.as_str());
            let in_place = output.is_none();
            // Write in place only when the strip changed the file; always write an
            // explicit output so a requested file is produced.
            if outcome.altered || !in_place {
                if let Err(e) = std::fs::write(dest, &outcome.bytes) {
                    eprintln!("[error] cannot write file '{dest}': {e}");
                    std::process::exit(1);
                }
            }

            match format.as_str() {
                "json" => {
                    let report = serde_json::json!({
                        "format": outcome.format.name(),
                        "output_path": dest,
                        "written_in_place": in_place,
                        "altered": outcome.altered,
                        "content_identical": outcome.content_identical,
                        "byte_count": outcome.bytes.len(),
                    });
                    println!("{}", serde_json::to_string_pretty(&report).unwrap());
                }
                _ => {
                    println!("{dest}");
                    eprintln!(
                        "[info] stripped {} metadata {} ({})",
                        outcome.format.name(),
                        if in_place { "written in place" } else { "written to a new file" },
                        if outcome.altered {
                            "metadata was present and removed"
                        } else {
                            "no strippable metadata was present"
                        }
                    );
                    eprintln!("[info] the document content is byte-identical");
                }
            }
        }

        FileAction::Pristine { file, output, format } => {
            let bytes = read_file_or_exit(&file);
            let source = source_format_or_exit(&file);

            // Wrap the file-level pristine clean: every mark class AND every
            // remaining invisible removed, so the text re-analyses fully clean. A
            // declared opt-in that names its meaning-bearing trade-off. A container
            // or markup format is refused by name.
            let outcome = match pristine_file(&bytes, source) {
                Ok(outcome) => outcome,
                Err(e) => {
                    eprintln!("[error] {e}");
                    std::process::exit(1);
                }
            };

            let dest = output.as_deref().unwrap_or(file.as_str());
            let in_place = output.is_none();
            if outcome.altered || !in_place {
                if let Err(e) = std::fs::write(dest, &outcome.bytes) {
                    eprintln!("[error] cannot write file '{dest}': {e}");
                    std::process::exit(1);
                }
            }

            match format.as_str() {
                "json" => {
                    let report = serde_json::json!({
                        "format": outcome.format.name(),
                        "output_path": dest,
                        "written_in_place": in_place,
                        "altered": outcome.altered,
                        "class_removed": outcome.class_removed,
                        "invisibles_removed": outcome.invisibles_removed,
                        "notes": outcome.notes,
                        "byte_count": outcome.bytes.len(),
                        "cleaned_text": outcome.cleaned_text,
                    });
                    println!("{}", serde_json::to_string_pretty(&report).unwrap());
                }
                _ => {
                    println!("{dest}");
                    eprintln!(
                        "[info] pristine-cleaned {} document {} ({} invisible characters removed beyond the mark classes)",
                        outcome.format.name(),
                        if in_place { "written in place" } else { "written to a new file" },
                        outcome.invisibles_removed
                    );
                    // The honest trade-off notes, never silent (invariant 2).
                    for note in &outcome.notes {
                        eprintln!("[info] {note}");
                    }
                }
            }
        }
    }
}

/// Report the presence of the additive metadata channel for the formats that
/// carry one (DOCX, PNG, SVG); `Null` for a format that has no such channel.
fn cli_embedded_channel_view(bytes: &[u8], format: FileFormat) -> serde_json::Value {
    if !matches!(format, FileFormat::Docx | FileFormat::Png | FileFormat::Svg) {
        return serde_json::Value::Null;
    }
    match recover_metadata(bytes, format) {
        Ok(Some(payload)) => serde_json::json!({ "present": true, "byte_count": payload.len() }),
        Ok(None) => serde_json::json!({ "present": false }),
        Err(e) => serde_json::json!({ "present": false, "unreadable": e.to_string() }),
    }
}

// ─── License helpers ────────────────────────────────────────

fn hex_to_32_bytes(hex: &str) -> [u8; 32] {
    if hex.len() != 64 {
        eprintln!("[error] Key file must contain exactly 64 hex characters (32 bytes), got {}", hex.len());
        std::process::exit(1);
    }
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| {
            eprintln!("[error] Invalid hex in key file at position {}", i * 2);
            std::process::exit(1);
        });
    }
    bytes
}

fn load_public_key(path: &str) -> MasterPublicKey {
    let pub_hex = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("[error] Cannot read public key file '{path}': {e}");
        std::process::exit(1);
    });
    let pub_bytes = hex_to_32_bytes(pub_hex.trim());
    MasterPublicKey::from_bytes(&pub_bytes).unwrap_or_else(|e| {
        eprintln!("[error] Invalid public key: {e}");
        std::process::exit(1);
    })
}

fn format_timestamp(secs: u64) -> String {
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let mut d = days;
    let mut year = 1970u64;
    loop {
        let dy = if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 { 366 } else { 365 };
        if d < dy { break; }
        d -= dy;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let mdays: [u64; 12] = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u64;
    for &md in &mdays {
        if d < md { break; }
        d -= md;
        month += 1;
    }
    let day = d + 1;
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}
