//! File embedding utility — port fidèle du plugin Python SteganoHero-v1.
//!
//! Embarque de petits fichiers dans du texte via base64.
//! Format : [FILE:filename|base64data][/FILE]
//! Limite : 100 KB par fichier.

use base64::{engine::general_purpose::STANDARD as B64, Engine};

use crate::error::{Result, SteganoError};

const MARKER_START: &str = "[FILE:";
const MARKER_END: &str = "[/FILE]";
const MAX_FILE_SIZE: usize = 100 * 1024; // 100 KB

pub struct FileEmbed;

/// Un fichier extrait.
#[derive(Debug, Clone)]
pub struct EmbeddedFile {
    pub name: String,
    pub data: Vec<u8>,
}

impl FileEmbed {
    pub fn new() -> Self {
        Self
    }

    /// Embarquer un fichier (nom + bytes) dans du texte.
    pub fn embed(&self, text: &str, filename: &str, data: &[u8]) -> Result<String> {
        if data.len() > MAX_FILE_SIZE {
            return Err(SteganoError::InvalidInput(format!(
                "file too large: {} bytes (max {})",
                data.len(),
                MAX_FILE_SIZE
            )));
        }

        let encoded = B64.encode(data);
        Ok(format!("{text}{MARKER_START}{filename}|{encoded}{MARKER_END}"))
    }

    /// Extraire tous les fichiers embarqués dans du texte.
    pub fn extract(&self, text: &str) -> Vec<EmbeddedFile> {
        let mut files = Vec::new();
        let mut pos = 0;

        while let Some(start) = text[pos..].find(MARKER_START) {
            let abs_start = pos + start + MARKER_START.len();
            if let Some(end) = text[abs_start..].find(MARKER_END) {
                let content = &text[abs_start..abs_start + end];
                if let Some(sep) = content.find('|') {
                    let filename = &content[..sep];
                    let encoded = &content[sep + 1..];
                    if let Ok(data) = B64.decode(encoded) {
                        files.push(EmbeddedFile {
                            name: filename.to_string(),
                            data,
                        });
                    }
                }
                pos = abs_start + end + MARKER_END.len();
            } else {
                break;
            }
        }

        files
    }

    /// Détecter si du texte contient des fichiers embarqués.
    pub fn detect(&self, text: &str) -> bool {
        text.contains(MARKER_START) && text.contains(MARKER_END)
    }

    /// Retirer les fichiers embarqués du texte.
    pub fn strip(&self, text: &str) -> String {
        let mut result = text.to_string();
        while let Some(start) = result.find(MARKER_START) {
            if let Some(end) = result[start..].find(MARKER_END) {
                result.replace_range(start..start + end + MARKER_END.len(), "");
            } else {
                break;
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embed_and_extract() {
        let fe = FileEmbed::new();
        let text = "Hello world";
        let data = b"file content here";
        let embedded = fe.embed(text, "test.txt", data).unwrap();
        let files = fe.extract(&embedded);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "test.txt");
        assert_eq!(files[0].data, data);
    }

    #[test]
    fn multiple_files() {
        let fe = FileEmbed::new();
        let mut text = "Base text".to_string();
        text = fe.embed(&text, "a.txt", b"aaa").unwrap();
        text = fe.embed(&text, "b.bin", b"\x00\x01\x02").unwrap();
        let files = fe.extract(&text);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].name, "a.txt");
        assert_eq!(files[1].name, "b.bin");
        assert_eq!(files[1].data, b"\x00\x01\x02");
    }

    #[test]
    fn detect_works() {
        let fe = FileEmbed::new();
        assert!(!fe.detect("normal text"));
        let embedded = fe.embed("text", "f.txt", b"data").unwrap();
        assert!(fe.detect(&embedded));
    }

    #[test]
    fn strip_removes_files() {
        let fe = FileEmbed::new();
        let embedded = fe.embed("Hello world", "f.txt", b"data").unwrap();
        assert_eq!(fe.strip(&embedded), "Hello world");
    }

    #[test]
    fn file_too_large() {
        let fe = FileEmbed::new();
        let big = vec![0u8; MAX_FILE_SIZE + 1];
        assert!(fe.embed("text", "big.bin", &big).is_err());
    }

    #[test]
    fn no_files_returns_empty() {
        let fe = FileEmbed::new();
        assert!(fe.extract("just text").is_empty());
    }
}
