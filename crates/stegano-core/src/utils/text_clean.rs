//! Text cleaning utility — port fidèle du plugin Python SteganoHero-v1.
//!
//! Normalise et nettoie le texte avant encodage.

use unicode_normalization::UnicodeNormalization;

pub struct TextClean;

#[derive(Default)]
pub struct CleanOptions {
    pub remove_accents: bool,
    pub lowercase: bool,
    pub collapse_whitespace: bool,
    pub remove_punctuation: bool,
    pub normalize_nfc: bool,
}

impl TextClean {
    pub fn new() -> Self {
        Self
    }

    /// Nettoyer le texte selon les options.
    pub fn clean(&self, text: &str, opts: &CleanOptions) -> String {
        let mut result = text.to_string();

        if opts.normalize_nfc {
            result = result.nfc().collect();
        }

        if opts.remove_accents {
            // NFD décompose les accents, puis on retire les marques combinantes
            result = result
                .nfd()
                .filter(|c| !unicode_normalization::char::is_combining_mark(*c))
                .collect();
        }

        if opts.lowercase {
            result = result.to_lowercase();
        }

        if opts.collapse_whitespace {
            let mut prev_space = false;
            result = result
                .chars()
                .filter(|c| {
                    if c.is_whitespace() {
                        if prev_space {
                            return false;
                        }
                        prev_space = true;
                    } else {
                        prev_space = false;
                    }
                    true
                })
                .collect();
            result = result.trim().to_string();
        }

        if opts.remove_punctuation {
            result = result
                .chars()
                .filter(|c| c.is_alphanumeric() || c.is_whitespace())
                .collect();
        }

        result
    }

    /// Strip tous les caractères stéganographiques connus (zero-width, bidi, homoglyphes).
    pub fn strip_all_stego(&self, text: &str) -> String {
        use crate::stego::{Homoglyph, ZeroWidth};
        use crate::traits::StegoMethod;

        let zw = ZeroWidth::new();
        let hg = Homoglyph::new();

        let cleaned = zw.strip(text);
        hg.strip(&cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_accents() {
        let tc = TextClean::new();
        let opts = CleanOptions {
            remove_accents: true,
            ..Default::default()
        };
        assert_eq!(tc.clean("café résumé", &opts), "cafe resume");
    }

    #[test]
    fn lowercase() {
        let tc = TextClean::new();
        let opts = CleanOptions {
            lowercase: true,
            ..Default::default()
        };
        assert_eq!(tc.clean("Hello WORLD", &opts), "hello world");
    }

    #[test]
    fn collapse_whitespace() {
        let tc = TextClean::new();
        let opts = CleanOptions {
            collapse_whitespace: true,
            ..Default::default()
        };
        assert_eq!(tc.clean("  hello   world  ", &opts), "hello world");
    }

    #[test]
    fn remove_punctuation() {
        let tc = TextClean::new();
        let opts = CleanOptions {
            remove_punctuation: true,
            ..Default::default()
        };
        assert_eq!(tc.clean("hello, world! (test)", &opts), "hello world test");
    }

    #[test]
    fn combined_options() {
        let tc = TextClean::new();
        let opts = CleanOptions {
            remove_accents: true,
            lowercase: true,
            collapse_whitespace: true,
            remove_punctuation: true,
            normalize_nfc: false,
        };
        assert_eq!(tc.clean("  Café,  Résumé!  ", &opts), "cafe resume");
    }
}
