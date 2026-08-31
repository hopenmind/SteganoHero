//! Integration test: the capacity subcommand reports the figure the engine
//! accepts, driven over the real binary and its JSON output.

use std::process::Command;

fn stegano_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_stegano"))
}

fn corpus(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("corpus")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("corpus document {} is missing: {e}", path.display()))
}

/// On technical_markdown.md the substitution carrier once reported sixty bytes
/// of room while the heavy frame accepted none. The light frame default (§3.2)
/// makes the same short cover usable: the subcommand reports a real figure, the
/// encode subcommand places a one byte secret through the carrier, and a secret
/// past the reported figure is refused, so the figure is the one the engine
/// honours.
#[test]
fn capacity_reports_the_figure_the_engine_accepts() {
    let cover = corpus("technical_markdown.md");

    let output = stegano_bin()
        .args([
            "capacity",
            "--cover",
            &cover,
            "--method",
            "homoglyph",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "capacity failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let reports: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("capacity must emit JSON");
    let homoglyph = &reports.as_array().expect("an array of carriers")[0];
    assert_eq!(homoglyph["carrier"], serde_json::json!("homoglyph"));
    let secret_bytes = homoglyph["secret_bytes"].as_u64().unwrap();
    assert!(
        secret_bytes > 0,
        "the light frame default makes this short cover usable, not the heavy zero"
    );
    assert!(
        homoglyph["positions"].as_u64().unwrap() > 8,
        "the cover has raw positions to spare"
    );
    assert_eq!(homoglyph["cover_bounds_writes"], serde_json::json!(true));

    // The encode subcommand now places a one byte secret through the carrier.
    let encode = stegano_bin()
        .args([
            "encode",
            "--cover",
            &cover,
            "--secret",
            "x",
            "--method",
            "homoglyph",
        ])
        .output()
        .unwrap();
    assert!(
        encode.status.success(),
        "the light frame default must place a one byte secret: {}",
        String::from_utf8_lossy(&encode.stderr)
    );

    // A secret past the reported figure is refused by this bounded carrier.
    let too_big = "a".repeat((secret_bytes + 1) as usize);
    let over = stegano_bin()
        .args([
            "encode",
            "--cover",
            &cover,
            "--secret",
            &too_big,
            "--method",
            "homoglyph",
        ])
        .output()
        .unwrap();
    assert!(
        !over.status.success(),
        "one byte past the reported figure must be refused"
    );
}

/// The carrier the cover does not bound is reported as unbounded, so its zero on
/// a tiny cover is never printed as a limit: the reason says the carrier places
/// by extending the document.
#[test]
fn the_unbounded_carrier_is_reported_as_unbounded() {
    let cover = corpus("minimal_tiny.txt");

    let output = stegano_bin()
        .args([
            "capacity",
            "--cover",
            &cover,
            "--method",
            "zero_width",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "capacity failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let reports: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("capacity must emit JSON");
    let zero_width = &reports.as_array().expect("an array of carriers")[0];
    assert_eq!(zero_width["carrier"], serde_json::json!("zero_width"));
    assert_eq!(zero_width["cover_bounds_writes"], serde_json::json!(false));
    assert!(
        zero_width["zero_reason"]
            .as_str()
            .unwrap()
            .contains("does not bound"),
        "the reason must say the cover does not bound this carrier"
    );
}

/// The --robust flag writes the heavy, recovery-robust frame, which reads back,
/// and reports a smaller capacity than the light default on the same cover.
#[test]
fn robust_encode_reads_back_and_reports_less_capacity() {
    let cover = corpus("en_long_article.txt");

    let enc = stegano_bin()
        .args(["encode", "--cover", &cover, "--secret", "robust layer", "--method", "zero_width", "--robust"])
        .output()
        .unwrap();
    assert!(enc.status.success(), "robust encode must succeed: {}", String::from_utf8_lossy(&enc.stderr));
    let stego = String::from_utf8_lossy(&enc.stdout).trim().to_string();

    let dec = stegano_bin()
        .args(["decode", "--text", &stego, "--method", "zero_width"])
        .output()
        .unwrap();
    assert!(dec.status.success(), "the robust frame must read back");
    assert!(String::from_utf8_lossy(&dec.stdout).contains("robust layer"));

    let cap = |robust: bool| -> u64 {
        let mut args = vec!["capacity", "--cover", &cover, "--method", "homoglyph", "--format", "json"];
        if robust {
            args.push("--robust");
        }
        let out = stegano_bin().args(&args).output().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v.as_array().unwrap()[0]["secret_bytes"].as_u64().unwrap()
    };
    assert!(cap(true) < cap(false), "the robust frame reports a smaller capacity");
}

/// The --saturate flag fills the channel with the secret repeated, far denser
/// than a normal encode, and the result still reads back (SAT-E2E, CLI).
#[test]
fn saturate_encode_is_dense_and_reads_back() {
    let cover = corpus("en_long_article.txt");
    let secret = "saturated end to end";
    let count = |s: &str| s.chars().filter(|c| matches!(*c, '\u{200B}' | '\u{200C}')).count();

    let normal = stegano_bin()
        .args(["encode", "--cover", &cover, "--secret", secret, "--method", "zero_width"])
        .output()
        .unwrap();
    let saturated = stegano_bin()
        .args(["encode", "--cover", &cover, "--secret", secret, "--method", "zero_width", "--saturate"])
        .output()
        .unwrap();
    assert!(saturated.status.success(), "saturate encode must succeed");

    let normal_out = String::from_utf8_lossy(&normal.stdout).trim().to_string();
    let saturated_out = String::from_utf8_lossy(&saturated.stdout).trim().to_string();
    assert!(
        count(&saturated_out) >= count(&normal_out) * 2,
        "saturated {} must be at least twice as dense as normal {}",
        count(&saturated_out),
        count(&normal_out)
    );

    let dec = stegano_bin()
        .args(["decode", "--text", &saturated_out, "--method", "zero_width"])
        .output()
        .unwrap();
    assert!(dec.status.success(), "the saturated document must read back");
    assert!(String::from_utf8_lossy(&dec.stdout).contains(secret));
}

/// The recommend subcommand names a carrier and mission that hold the secret,
/// and applying them through encode places it. On the long article a short
/// secret fits and the recommendation is applicable end to end.
#[test]
fn recommend_names_a_setting_that_encode_accepts() {
    let cover = corpus("en_long_article.txt");
    let secret = "rendez-vous porte nord a neuf heures";

    let output = stegano_bin()
        .args([
            "recommend",
            "--cover",
            &cover,
            "--secret",
            secret,
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "recommend failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let rec: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("recommend must emit JSON");
    assert_eq!(rec["fits"], serde_json::json!(true));
    let carrier = rec["carrier"].as_str().expect("a fitting recommendation names a carrier");
    let mission = rec["mission"].as_str().expect("and a mission to apply");
    assert!(["conceal", "sign", "mark"].contains(&mission));

    // Applying the recommended carrier through encode places the secret.
    let encode = stegano_bin()
        .args(["encode", "--cover", &cover, "--secret", secret, "--method", carrier])
        .output()
        .unwrap();
    assert!(
        encode.status.success(),
        "the recommended carrier must accept the secret: {}",
        String::from_utf8_lossy(&encode.stderr)
    );
}
