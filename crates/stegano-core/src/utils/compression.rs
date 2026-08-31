//! Compression utility — port fidèle du plugin Python SteganoHero-v1.
//!
//! Compresse/décompresse des données avec flate2 (zlib).
//! Essentiel pour l'empilage multi-couche (réduit la taille entre chaque couche).

use crate::error::{Result, SteganoError};
use flate2::read::{ZlibDecoder, ZlibEncoder};
use flate2::Compression as Level;
use std::io::Read;

pub struct Compression;

impl Compression {
    pub fn new() -> Self {
        Self
    }

    /// Compresse des bytes avec zlib (niveau 0-9, défaut 9).
    pub fn compress(&self, data: &[u8], level: u32) -> Result<Vec<u8>> {
        let level = Level::new(level.min(9));
        let mut encoder = ZlibEncoder::new(data, level);
        let mut compressed = Vec::new();
        encoder
            .read_to_end(&mut compressed)
            .map_err(|e| SteganoError::InvalidInput(format!("compression failed: {e}")))?;
        Ok(compressed)
    }

    /// Décompresse des bytes zlib.
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = ZlibDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| SteganoError::InvalidInput(format!("decompression failed: {e}")))?;
        Ok(decompressed)
    }

    /// Compresse un texte UTF-8 → bytes compressés.
    pub fn compress_text(&self, text: &str) -> Result<Vec<u8>> {
        self.compress(text.as_bytes(), 9)
    }

    /// Décompresse des bytes → texte UTF-8.
    pub fn decompress_text(&self, data: &[u8]) -> Result<String> {
        let bytes = self.decompress(data)?;
        String::from_utf8(bytes)
            .map_err(|e| SteganoError::InvalidInput(format!("invalid UTF-8: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_text() {
        let c = Compression::new();
        let text = "Hello SteganoHero! This is a compression test with some repeated text. \
                     Repeated text is good for compression. Repeated text is good for compression.";
        let compressed = c.compress_text(text).unwrap();
        let decompressed = c.decompress_text(&compressed).unwrap();
        assert_eq!(decompressed, text);
        assert!(compressed.len() < text.len(), "compressed should be smaller");
    }

    #[test]
    fn roundtrip_binary() {
        let c = Compression::new();
        let data: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();
        let compressed = c.compress(&data, 9).unwrap();
        let decompressed = c.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn empty_data() {
        let c = Compression::new();
        let compressed = c.compress(b"", 9).unwrap();
        let decompressed = c.decompress(&compressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn compression_ratio() {
        let c = Compression::new();
        // Highly repetitive text should compress well
        let text = "AAAA".repeat(1000);
        let compressed = c.compress_text(&text).unwrap();
        let ratio = compressed.len() as f64 / text.len() as f64;
        assert!(ratio < 0.1, "ratio={ratio}, expected < 0.1 for repetitive text");
    }
}
