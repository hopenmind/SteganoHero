//! SEC-WM1: exact detection of a public-config green-list watermark, key
//! independence between configs, and honest silence on a secret-key mark.
//!
//! This is the crate's load-bearing promise, written as a test: the tool is
//! CERTAIN where the config is public, and says nothing where it cannot know.

use stegano_wm::{default_registry, detect_z, WmConfig};

/// Build a token sequence that is green at every scored position under
/// `config`: at each position, choose a green vocabulary token given the last
/// `h` tokens. The scan start is rotated by position so the choice is not a pure
/// function of context; a purely greedy "first green" fixture collapses into a
/// short cycle, and a repetitive sequence would create spurious cross-config
/// correlation (a repeated bigram counted many times) that is an artifact of the
/// fixture, not a real mark. This is a TEST FIXTURE only: the product detects
/// real marked text, it never generates text this way.
fn synthesize_green(config: &WmConfig, vocab: &[u32], n: usize, seed_ctx: &[u32]) -> Vec<u32> {
    let mut t = seed_ctx.to_vec();
    while t.len() < n {
        let i = t.len();
        let start = i.saturating_sub(config.h);
        let ctx: Vec<u32> = t[start..i].to_vec();
        let offset = i.wrapping_mul(2_654_435_761) % vocab.len();
        let chosen = (0..vocab.len())
            .map(|k| vocab[(offset + k) % vocab.len()])
            .find(|v| config.is_green(&ctx, *v))
            .unwrap_or(vocab[0]);
        t.push(chosen);
    }
    t
}

#[test]
fn registry_detects_public_config_and_stays_silent_on_secret_key() {
    let reg = default_registry();
    let vocab: Vec<u32> = (1..=256).collect();
    let seed_ctx = vec![7u32; 4];

    // A text marked with a PUBLIC registry config (public-standard-h3).
    let target = reg.entries()[3].clone();
    let marked = synthesize_green(&target, &vocab, 240, &seed_ctx);

    // Exact detection under the marking config is a strong, named hit.
    let z_on = detect_z(&target, &marked);
    assert!(z_on > 10.0, "expected a strong hit under the marking config, got z={z_on}");

    // Key independence: every OTHER registry config stays near zero on the same
    // text, so a hit is specific to the config that actually marked it.
    for (name, z) in reg.sweep(&marked) {
        if name == target.name {
            assert!(z > 10.0, "the marking config should hit: {name} z={z}");
        } else {
            assert!(z.abs() < 5.0, "an unrelated config should be near zero: {name} z={z}");
        }
    }

    // The single named hit is the marking config.
    let (best_name, best_z) = reg.best_hit(&marked, 5.0).expect("a named hit is expected");
    assert_eq!(best_name, target.name);
    assert!(best_z > 10.0);

    // Honesty: a text marked with a SECRET key that is NOT in the registry.
    let secret = WmConfig::new("secret-vendor-key", 0x5EED_5EED_5EED, 0.25, 3);
    let hidden = synthesize_green(&secret, &vocab, 240, &seed_ctx);

    // Ground truth (only because we hold the secret here): the secret key
    // detects its own mark. A real vendor key we would never have.
    assert!(detect_z(&secret, &hidden) > 10.0, "the secret key detects its own mark");

    // But the PUBLIC registry names nothing. This silence is the structural
    // wall stated as a test: without the key, the test has no power.
    assert!(
        reg.best_hit(&hidden, 5.0).is_none(),
        "the public registry must stay silent on a secret-key mark"
    );
}
