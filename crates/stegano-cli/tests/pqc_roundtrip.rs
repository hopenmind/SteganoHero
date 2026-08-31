//! Integration test: post-quantum recipient encryption CLI roundtrip
//! keypair -> seal -> open, and a wrong-key open refused by name.

use std::process::Command;

fn stegano_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_stegano"))
}

#[test]
fn pqc_keypair_creates_two_key_files() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("recipient");
    let prefix_str = prefix.to_str().unwrap();

    let output = stegano_bin()
        .args(["pqc", "keypair", "--output", prefix_str])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "keypair failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let public_path = format!("{prefix_str}.pqc-public");
    let secret_path = format!("{prefix_str}.pqc-secret");
    assert!(std::path::Path::new(&public_path).exists(), "public key file not created");
    assert!(std::path::Path::new(&secret_path).exists(), "secret key file not created");

    // Both files hold base64, and the two halves differ.
    let public = std::fs::read_to_string(&public_path).unwrap();
    let secret = std::fs::read_to_string(&secret_path).unwrap();
    assert!(!public.trim().is_empty(), "public key should not be empty");
    assert!(!secret.trim().is_empty(), "secret key should not be empty");
    assert_ne!(public.trim(), secret.trim(), "public and secret halves differ");
}

#[test]
fn pqc_full_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("roundtrip");
    let prefix_str = prefix.to_str().unwrap();

    // Step 1: keypair
    let output = stegano_bin()
        .args(["pqc", "keypair", "--output", prefix_str])
        .output()
        .unwrap();
    assert!(output.status.success(), "keypair failed");
    let public_path = format!("{prefix_str}.pqc-public");
    let secret_path = format!("{prefix_str}.pqc-secret");

    // Step 2: seal a secret to the public key
    let secret_message = "the shipment leaves at midnight, gate 7";
    let seal_output = stegano_bin()
        .args([
            "pqc", "seal",
            "--recipient-public-file", &public_path,
            "--text", secret_message,
        ])
        .output()
        .unwrap();
    assert!(
        seal_output.status.success(),
        "seal failed: {}",
        String::from_utf8_lossy(&seal_output.stderr)
    );
    let sealed = String::from_utf8(seal_output.stdout).unwrap();
    let sealed = sealed.trim();
    assert!(!sealed.is_empty(), "sealed payload should not be empty");
    assert!(!sealed.contains(secret_message), "sealed payload is not the plaintext");

    // Step 3: open with the matching secret key
    let open_output = stegano_bin()
        .args([
            "pqc", "open",
            "--secret-file", &secret_path,
            "--sealed", sealed,
        ])
        .output()
        .unwrap();
    assert!(
        open_output.status.success(),
        "open failed: {}",
        String::from_utf8_lossy(&open_output.stderr)
    );
    let recovered = String::from_utf8(open_output.stdout).unwrap();
    assert_eq!(recovered.trim(), secret_message, "recipient recovers the exact secret");
}

#[test]
fn pqc_open_with_the_wrong_key_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let recipient = dir.path().join("recipient");
    let intruder = dir.path().join("intruder");

    for prefix in [&recipient, &intruder] {
        stegano_bin()
            .args(["pqc", "keypair", "--output", prefix.to_str().unwrap()])
            .output()
            .unwrap();
    }

    // Seal to the recipient's public key.
    let seal_output = stegano_bin()
        .args([
            "pqc", "seal",
            "--recipient-public-file", &format!("{}.pqc-public", recipient.to_str().unwrap()),
            "--text", "for the recipient only",
        ])
        .output()
        .unwrap();
    assert!(seal_output.status.success());
    let sealed = String::from_utf8(seal_output.stdout).unwrap();

    // Open with the intruder's secret key -> refused, not a partial plaintext.
    let open_output = stegano_bin()
        .args([
            "pqc", "open",
            "--secret-file", &format!("{}.pqc-secret", intruder.to_str().unwrap()),
            "--sealed", sealed.trim(),
        ])
        .output()
        .unwrap();
    assert!(!open_output.status.success(), "open with the wrong key must fail");
    let err = String::from_utf8_lossy(&open_output.stderr);
    assert!(err.contains("refused"), "the failure names itself: {err}");
}

#[test]
fn encode_seals_to_a_recipient_and_decode_opens_it() {
    // The headline flow on the CLI: seal a secret to a recipient and hide it in
    // one encode, then reveal and open it in one decode. No shared password.
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("recipient");
    let prefix_str = prefix.to_str().unwrap();

    stegano_bin()
        .args(["pqc", "keypair", "--output", prefix_str])
        .output()
        .unwrap();
    let public_path = format!("{prefix_str}.pqc-public");
    let secret_path = format!("{prefix_str}.pqc-secret");

    let cover = "The quarterly figures look consistent with the earlier projection we discussed.";
    let secret_message = "wire transfer approved, reference 4471";

    let encode_output = stegano_bin()
        .args([
            "encode",
            "--cover", cover,
            "--secret", secret_message,
            "--recipient-public-file", &public_path,
        ])
        .output()
        .unwrap();
    assert!(
        encode_output.status.success(),
        "encode failed: {}",
        String::from_utf8_lossy(&encode_output.stderr)
    );
    let stego = String::from_utf8(encode_output.stdout).unwrap();
    let stego = stego.trim_end_matches('\n');
    assert!(!stego.contains(secret_message), "the secret is not in the clear");

    let decode_output = stegano_bin()
        .args([
            "decode",
            "--text", stego,
            "--recipient-secret-file", &secret_path,
        ])
        .output()
        .unwrap();
    assert!(
        decode_output.status.success(),
        "decode failed: {}",
        String::from_utf8_lossy(&decode_output.stderr)
    );
    let recovered = String::from_utf8(decode_output.stdout).unwrap();
    assert_eq!(recovered.trim_end_matches('\n'), secret_message, "recipient recovers the secret");
}
