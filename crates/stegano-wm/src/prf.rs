//! The keyed pseudo-random function that defines every green-list partition.
//!
//! One primitive, a keyed SHA-256, underlies reading a public mark, writing our
//! own mark, and guiding a scrub. It is post-quantum by construction: the only
//! security assumption is the preimage resistance of the hash.

use sha2::{Digest, Sha256};

/// Keyed PRF over a token context, byte-exact and deterministic.
///
/// Message layout (big-endian concatenation):
/// `key(32) || 0x01 || u32(ctx.len()) || u32(ctx[0]) .. u32(ctx[k-1]) || u32(tok)`.
/// The `0x01` is a domain-separation tag for the "green partition" use. The
/// result is the first eight bytes of the digest read as a big-endian `u64`.
pub(crate) fn prf64(key: &[u8; 32], ctx: &[u32], tok: u32) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update([0x01u8]);
    hasher.update((ctx.len() as u32).to_be_bytes());
    for &c in ctx {
        hasher.update(c.to_be_bytes());
    }
    hasher.update(tok.to_be_bytes());
    let digest = hasher.finalize();
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(head)
}

/// Derive a 32-byte configuration key from a public seed and the config name,
/// so two configs that share a seed but differ in name have independent keys.
pub(crate) fn derive_key(seed: u64, name: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed.to_le_bytes());
    hasher.update(name.as_bytes());
    hasher.finalize().into()
}

/// One keyed pseudo-random bit for `index`, domain-separated from the partition
/// PRF (tag 0x02, the "mark whitening" use). Whitening the payload with this bit
/// means only the key holder can read or forge the mark.
pub(crate) fn prf_bit(key: &[u8; 32], index: u32) -> u8 {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update([0x02u8]);
    hasher.update(index.to_be_bytes());
    hasher.finalize()[0] & 1
}

/// Derive a per-document key from a master key and the document's canonical
/// form (tag 0x03), so the mark is bound to this document yet reproducible from
/// it: the reader canonicalizes the text back to the same basis and recomputes
/// the same key.
pub(crate) fn derive_doc_key(master: &[u8; 32], canonical_text: &str) -> [u8; 32] {
    let doc_hash = Sha256::digest(canonical_text.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update([0x03u8]);
    hasher.update(master);
    hasher.update(doc_hash);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prf_is_deterministic_and_token_sensitive() {
        let key = derive_key(15_485_863, "kgw-hash:transformers-default-h1");
        let ctx = [10u32, 20, 30];
        // Same inputs, same output.
        assert_eq!(prf64(&key, &ctx, 42), prf64(&key, &ctx, 42));
        // A different token changes the value (with overwhelming probability).
        assert_ne!(prf64(&key, &ctx, 42), prf64(&key, &ctx, 43));
        // A different context changes the value.
        assert_ne!(prf64(&key, &ctx, 42), prf64(&key, &[10u32, 20, 31], 42));
    }

    #[test]
    fn derived_keys_separate_on_name() {
        assert_ne!(derive_key(15_485_863, "a"), derive_key(15_485_863, "b"));
    }
}
