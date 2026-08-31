//! Integration test: full license CLI roundtrip
//! keygen → generate → inspect → verify

use std::process::Command;

fn stegano_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_stegano"))
}

#[test]
fn license_keygen_creates_key_files() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("testkey");
    let prefix_str = prefix.to_str().unwrap();

    let output = stegano_bin()
        .args(["license", "keygen", "--output", prefix_str])
        .output()
        .unwrap();

    assert!(output.status.success(), "keygen failed: {}", String::from_utf8_lossy(&output.stderr));

    let key_path = format!("{prefix_str}.key");
    let pub_path = format!("{prefix_str}.pub");

    assert!(std::path::Path::new(&key_path).exists(), ".key file not created");
    assert!(std::path::Path::new(&pub_path).exists(), ".pub file not created");

    // Key files should contain 64 hex chars (32 bytes)
    let key_content = std::fs::read_to_string(&key_path).unwrap();
    let pub_content = std::fs::read_to_string(&pub_path).unwrap();
    assert_eq!(key_content.trim().len(), 64, "private key should be 64 hex chars");
    assert_eq!(pub_content.trim().len(), 64, "public key should be 64 hex chars");
}

#[test]
fn license_full_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("roundtrip");
    let prefix_str = prefix.to_str().unwrap();

    // Step 1: keygen
    let output = stegano_bin()
        .args(["license", "keygen", "--output", prefix_str])
        .output()
        .unwrap();
    assert!(output.status.success(), "keygen failed");

    let key_path = format!("{prefix_str}.key");
    let pub_path = format!("{prefix_str}.pub");

    // Step 2: generate license
    let gen_output = stegano_bin()
        .args([
            "license", "generate",
            "--licensee", "Test Corp",
            "--modules", "canary-trap,anti-detect",
            "--key-file", &key_path,
            "--expires", "2030-12-31T23:59:59Z",
        ])
        .output()
        .unwrap();
    assert!(gen_output.status.success(), "generate failed: {}", String::from_utf8_lossy(&gen_output.stderr));

    let stego_text = String::from_utf8(gen_output.stdout).unwrap();
    assert!(!stego_text.is_empty(), "stego text should not be empty");

    // Step 3: inspect (extract + pretty-print JSON)
    let inspect_output = stegano_bin()
        .args([
            "license", "inspect",
            "--text", &stego_text,
            "--public-key", &pub_path,
        ])
        .output()
        .unwrap();
    assert!(inspect_output.status.success(), "inspect failed: {}", String::from_utf8_lossy(&inspect_output.stderr));

    let json_str = String::from_utf8(inspect_output.stdout).unwrap();
    let json: serde_json::Value = serde_json::from_str(json_str.trim()).unwrap();
    assert_eq!(json["licensee"], "Test Corp");
    assert_eq!(json["modules"], serde_json::json!(["canary-trap", "anti-detect"]));
    assert_eq!(json["expires"], "2030-12-31T23:59:59Z");

    // Step 4: verify
    let verify_output = stegano_bin()
        .args([
            "license", "verify",
            "--text", &stego_text,
            "--public-key", &pub_path,
        ])
        .output()
        .unwrap();
    assert!(verify_output.status.success(), "verify failed: {}", String::from_utf8_lossy(&verify_output.stderr));

    let verify_str = String::from_utf8(verify_output.stdout).unwrap();
    assert!(verify_str.contains("Signature: VALID"), "should show VALID signature");
    assert!(verify_str.contains("Test Corp"), "should show licensee");
}

#[test]
fn license_verify_wrong_key_fails() {
    let dir = tempfile::tempdir().unwrap();

    // Generate two different key pairs
    let prefix1 = dir.path().join("key1");
    let prefix2 = dir.path().join("key2");

    stegano_bin()
        .args(["license", "keygen", "--output", prefix1.to_str().unwrap()])
        .output()
        .unwrap();
    stegano_bin()
        .args(["license", "keygen", "--output", prefix2.to_str().unwrap()])
        .output()
        .unwrap();

    // Generate with key1
    let gen_output = stegano_bin()
        .args([
            "license", "generate",
            "--licensee", "Wrong Key Test",
            "--modules", "x",
            "--key-file", &format!("{}.key", prefix1.to_str().unwrap()),
        ])
        .output()
        .unwrap();
    assert!(gen_output.status.success());
    let stego_text = String::from_utf8(gen_output.stdout).unwrap();

    // Verify with key2 → should fail
    let verify_output = stegano_bin()
        .args([
            "license", "verify",
            "--text", &stego_text,
            "--public-key", &format!("{}.pub", prefix2.to_str().unwrap()),
        ])
        .output()
        .unwrap();

    assert!(!verify_output.status.success(), "verify with wrong key should fail");
    let out = String::from_utf8(verify_output.stdout).unwrap();
    assert!(out.contains("INVALID"), "should show INVALID");
}
