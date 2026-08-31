use crate::error::{Result, SteganoError};
use crate::format::PositionChannel;
use crate::stego::recognition::{self, Script};
use crate::traits::StegoMethod;

/// Homoglyph Steganography
///
/// Encodes data by substituting ASCII characters with visually identical
/// Unicode counterparts (primarily Latin → Cyrillic). Each substitutable
/// position can encode 1 bit: original = 0, homoglyph = 1.
///
/// This is the MOST RESILIENT text steganography method because:
/// - Survives copy/paste across ALL platforms
/// - Survives PDF roundtrips
/// - Survives Unicode normalization (NFC, NFD, NFKC, NFKD)
/// - Cannot be detected by visual inspection
/// - Only detectable by comparing Unicode codepoints

/// Mapping: (ASCII char, Cyrillic homoglyph)
const HOMOGLYPH_MAP: &[(char, char)] = &[
    // Lowercase
    ('a', '\u{0430}'), // а Cyrillic Small A
    ('c', '\u{0441}'), // с Cyrillic Small ES
    ('e', '\u{0435}'), // е Cyrillic Small IE
    ('o', '\u{043E}'), // о Cyrillic Small O
    ('p', '\u{0440}'), // р Cyrillic Small ER
    ('x', '\u{0445}'), // х Cyrillic Small HA
    ('y', '\u{0443}'), // у Cyrillic Small U
    ('s', '\u{0455}'), // ѕ Cyrillic Small DZE
    ('i', '\u{0456}'), // і Cyrillic Small Byelorussian-Ukrainian I
    ('j', '\u{0458}'), // ј Cyrillic Small JE
    // Uppercase
    ('A', '\u{0410}'), // А Cyrillic Capital A
    ('B', '\u{0412}'), // В Cyrillic Capital VE
    ('C', '\u{0421}'), // С Cyrillic Capital ES
    ('E', '\u{0415}'), // Е Cyrillic Capital IE
    ('H', '\u{041D}'), // Н Cyrillic Capital EN
    ('K', '\u{041A}'), // К Cyrillic Capital KA
    ('M', '\u{041C}'), // М Cyrillic Capital EM
    ('O', '\u{041E}'), // О Cyrillic Capital O
    ('P', '\u{0420}'), // Р Cyrillic Capital ER
    ('T', '\u{0422}'), // Т Cyrillic Capital TE
    ('X', '\u{0425}'), // Х Cyrillic Capital HA
    ('S', '\u{0405}'), // Ѕ Cyrillic Capital DZE
    ('I', '\u{0406}'), // І Cyrillic Capital Byelorussian-Ukrainian I
    ('J', '\u{0408}'), // Ј Cyrillic Capital JE
];

/// Codepoint alphabet of this carrier (SPEC_CORE_V2 §6.5): both sides of every
/// mapped pair, since an ASCII original reads as bit 0 and its Cyrillic
/// substitute as bit 1. Derived from `HOMOGLYPH_MAP` so the two cannot drift.
const CHANNEL: [char; HOMOGLYPH_MAP.len() * 2] = {
    let mut channel = ['\0'; HOMOGLYPH_MAP.len() * 2];
    let mut i = 0;
    while i < HOMOGLYPH_MAP.len() {
        channel[i * 2] = HOMOGLYPH_MAP[i].0;
        channel[i * 2 + 1] = HOMOGLYPH_MAP[i].1;
        i += 1;
    }
    channel
};

pub struct Homoglyph;

impl Homoglyph {
    pub fn new() -> Self {
        Self
    }

    /// Check if a character has a homoglyph substitute available.
    fn has_substitute(c: char) -> bool {
        HOMOGLYPH_MAP.iter().any(|(ascii, _)| *ascii == c)
    }

    /// Get the homoglyph substitute for an ASCII character.
    fn substitute(c: char) -> Option<char> {
        HOMOGLYPH_MAP
            .iter()
            .find(|(ascii, _)| *ascii == c)
            .map(|(_, cyrillic)| *cyrillic)
    }

    /// Get the ASCII original for a Cyrillic homoglyph.
    fn original(c: char) -> Option<char> {
        HOMOGLYPH_MAP
            .iter()
            .find(|(_, cyrillic)| *cyrillic == c)
            .map(|(ascii, _)| *ascii)
    }

    /// Check if a character is a Cyrillic homoglyph (substituted).
    fn is_homoglyph(c: char) -> bool {
        HOMOGLYPH_MAP.iter().any(|(_, cyrillic)| *cyrillic == c)
    }

    /// Check if a character is a substitutable position (ASCII original OR Cyrillic sub).
    fn is_position(c: char) -> bool {
        Self::has_substitute(c) || Self::is_homoglyph(c)
    }

    // ─── Attribution ───
    //
    // This carrier borrows an alphabet that belongs to a living script, so the
    // presence of its codepoints proves nothing on its own. See
    // `stego/recognition.rs` for the rule these three functions apply.

    /// Which characters of `text` are substitutions this carrier made, one
    /// flag per character in document order.
    ///
    /// Evidence, in order:
    ///
    /// 1. **The word.** A run of letters holding an unambiguous Cyrillic
    ///    letter is a Cyrillic word, so its lookalikes are its own letters. A
    ///    run holding a Latin letter and no unambiguous Cyrillic is a Latin
    ///    word, so a lookalike in it can only be a substitution.
    /// 2. **The document.** A run made entirely of lookalikes offers no
    ///    evidence of its own. This happens on both sides: `оса` is a Russian
    ///    word, and `Access` fully marked is six lookalikes in a row. The
    ///    document's script decides it.
    /// 3. **Neither.** When the document holds both scripts, or neither, the
    ///    run is left unattributed. Nothing is rewritten on a guess.
    ///
    /// Note what this does *not* touch: which positions carry bits. Every
    /// substitutable position still reads in document order, exactly as
    /// `place_bits` wrote it (invariant 4). Attribution decides whether this
    /// carrier has a channel in this text at all, never where the bits sit.
    fn attribute(text: &str) -> Vec<bool> {
        let chars: Vec<char> = text.chars().collect();
        let document = recognition::document_script(&chars, Self::is_homoglyph);
        let mut substitution = vec![false; chars.len()];

        let mut i = 0;
        while i < chars.len() {
            if !chars[i].is_alphabetic() {
                i += 1;
                continue;
            }

            let start = i;
            while i < chars.len() && chars[i].is_alphabetic() {
                i += 1;
            }
            let run = &chars[start..i];

            let mut latin = 0usize;
            let mut cyrillic = 0usize;
            for &c in run {
                if Self::is_homoglyph(c) {
                    continue; // Carries no evidence: it is the question.
                }
                if recognition::is_latin_letter(c) {
                    latin += 1;
                } else if recognition::is_cyrillic_letter(c) {
                    cyrillic += 1;
                }
            }

            let marked = if cyrillic > 0 {
                false // A Cyrillic word. Its letters are its own.
            } else if latin > 0 {
                true // A Latin word. A lookalike in it was put there.
            } else {
                document == Script::Latin
            };

            if marked {
                for (offset, &c) in run.iter().enumerate() {
                    if Self::is_homoglyph(c) {
                        substitution[start + offset] = true;
                    }
                }
            }
        }

        substitution
    }

    /// How many characters of `text` this carrier can show are its own work.
    pub fn substitutions(text: &str) -> usize {
        Self::attribute(text).into_iter().filter(|m| *m).count()
    }

    /// Does this carrier have a channel in this text at all?
    ///
    /// A document written in Cyrillic offers lookalikes by the hundred and not
    /// one of them is a substitution. Reading it returns the alphabet of the
    /// language dressed as bits, which is what made the detector report a
    /// decodable payload in untouched Russian prose (backlog F16). The honest
    /// answer is that there is nothing here to read, and it names why.
    fn check_readable(text: &str) -> Result<()> {
        let lookalikes = text.chars().filter(|c| Self::is_homoglyph(*c)).count();
        if lookalikes == 0 {
            // Either plain Latin, where every position reads as bit 0, or a
            // script this carrier does not touch. Both are readable as they
            // stand.
            return Ok(());
        }
        if Self::substitutions(text) > 0 {
            return Ok(());
        }

        Err(SteganoError::DecodingFailed {
            method: "homoglyph".into(),
            reason: format!(
                "this text is written in Cyrillic script, so its {lookalikes} lookalike \
                 letters are the document's own writing rather than substitutions; there \
                 is no homoglyph channel to read here"
            ),
        })
    }

    /// The bit-placement routine of this carrier, and the only one.
    ///
    /// One bit per substitutable position, in document order: bit 1 substitutes
    /// the Cyrillic lookalike, bit 0 leaves the original standing. Positions
    /// beyond `bits` keep their original form, so they read back as bit 0.
    ///
    /// A letter inside a fenced block or an inline code span is not a position:
    /// substituting it would corrupt a command a reader pastes into a shell,
    /// with nothing on screen to explain the failure (backlog F23). Such letters
    /// are left standing and consume no bit, and `extract_bits` skips them the
    /// same way so the written and read positions stay aligned.
    ///
    /// `encode` and `write_positions` both funnel through here. The framing
    /// layer decides which bits arrive; it never decides where they land
    /// (invariant 4, SPEC_CORE_V2 §5).
    fn place_bits(cover: &str, bits: &[u8]) -> String {
        let chars: Vec<char> = cover.chars().collect();
        let code = crate::stego::placement::code_character_flags(&chars);
        let mut bit_idx = 0;
        let mut result = String::with_capacity(cover.len());

        for (i, &ch) in chars.iter().enumerate() {
            if bit_idx < bits.len() && !code[i] && Self::has_substitute(ch) {
                if bits[bit_idx] == 1 {
                    // Substitute with homoglyph = bit 1
                    result.push(Self::substitute(ch).unwrap());
                } else {
                    // Keep original = bit 0
                    result.push(ch);
                }
                bit_idx += 1;
            } else {
                // Not a substitutable position, inside code, or all bits encoded
                result.push(ch);
            }
        }

        result
    }

    /// The bit-extraction routine of this carrier, and the only one.
    ///
    /// Positions inside machine input are skipped, exactly as `place_bits`
    /// skips them, so a document with code regions reads back the bits it was
    /// written with and no others (backlog F23).
    ///
    /// `decode` and `read_positions` both funnel through here.
    fn extract_bits(stego: &str) -> Vec<u8> {
        let chars: Vec<char> = stego.chars().collect();
        let code = crate::stego::placement::code_character_flags(&chars);
        chars
            .iter()
            .enumerate()
            .filter_map(|(i, ch)| {
                if code[i] {
                    None // Inside machine input: not a channel position
                } else if Self::is_homoglyph(*ch) {
                    Some(1) // Cyrillic substitute = bit 1
                } else if Self::has_substitute(*ch) {
                    Some(0) // ASCII original = bit 0
                } else {
                    None // Not a substitutable position
                }
            })
            .collect()
    }
}

/// The position-addressed view of the same placement routine, SPEC_CORE_V2 §3.
///
/// `StegoMethod` speaks bytes, which cannot express the trailing positions a
/// frame must leave empty when a cover offers a count that is not a multiple
/// of eight. This speaks positions.
impl PositionChannel for Homoglyph {
    fn positions(&self, text: &str) -> usize {
        let chars: Vec<char> = text.chars().collect();
        let code = crate::stego::placement::code_character_flags(&chars);
        chars
            .iter()
            .enumerate()
            .filter(|(i, c)| !code[*i] && Self::is_position(**c))
            .count()
    }

    fn read_positions(&self, text: &str) -> Vec<u8> {
        Self::extract_bits(text)
    }

    /// A cover already holding characters of this carrier's alphabet is
    /// refused by name.
    ///
    /// Reading treats both sides of a substitution as a position; writing can
    /// only act on the Latin side, since turning an existing Cyrillic letter
    /// into its Latin lookalike would rewrite the author's text. On such a
    /// cover the written and read position indices would not line up, and the
    /// document would decode to nothing coherent. Legitimate Cyrillic prose is
    /// the everyday case, so this refuses rather than damages it.
    fn check_writable(&self, cover: &str) -> Result<()> {
        let occupied = cover.chars().filter(|c| Self::is_homoglyph(*c)).count();
        if occupied == 0 {
            return Ok(());
        }
        Err(recognition::cover_already_occupied("homoglyph", occupied))
    }

    fn write_positions(&self, cover: &str, bits: &[u8]) -> Result<String> {
        self.check_writable(cover)?;

        let available = self.positions(cover);
        if bits.len() > available {
            return Err(SteganoError::CapacityExceeded {
                needed: bits.len(),
                available,
            });
        }
        Ok(Self::place_bits(cover, bits))
    }
}

impl StegoMethod for Homoglyph {
    fn id(&self) -> &str {
        "homoglyph"
    }

    fn name(&self) -> &str {
        "Homoglyph Substitution"
    }

    fn encode(&self, cover: &str, payload: &[u8]) -> Result<String> {
        if payload.is_empty() {
            return Err(SteganoError::InvalidInput("empty payload".into()));
        }

        // Backlog F26: the byte path used to skip this, so the same cover was
        // refused by one guard on one path and a different guard on the other.
        self.check_writable(cover)?;

        let cap = self.capacity(cover);
        let needed = payload.len() * 8;
        if needed > cap {
            return Err(SteganoError::CapacityExceeded {
                needed,
                available: cap,
            });
        }

        // Convert payload to bits
        let bits: Vec<u8> = payload
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1))
            .collect();

        Ok(Self::place_bits(cover, &bits))
    }

    fn decode(&self, stego: &str) -> Result<Vec<u8>> {
        // A document whose lookalikes are its own writing offers no channel,
        // and saying so is the answer (backlog F16).
        Self::check_readable(stego)?;

        // Extract bits from substitutable positions
        let bits = Self::extract_bits(stego);

        if bits.is_empty() {
            return Err(SteganoError::NothingDetected);
        }

        // Trim to multiple of 8
        let usable = (bits.len() / 8) * 8;
        if usable == 0 {
            return Err(SteganoError::DecodingFailed {
                method: "homoglyph".into(),
                reason: "not enough substitutable positions for even 1 byte".into(),
            });
        }

        Ok(bits[..usable]
            .chunks_exact(8)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(0u8, |acc, (i, &bit)| acc | (bit << (7 - i)))
            })
            .collect())
    }

    fn capacity(&self, cover: &str) -> usize {
        // 1 bit per substitutable character position, excluding letters inside
        // machine input, which this carrier must leave byte-identical (F23).
        let chars: Vec<char> = cover.chars().collect();
        let code = crate::stego::placement::code_character_flags(&chars);
        chars
            .iter()
            .enumerate()
            .filter(|(i, c)| !code[*i] && Self::has_substitute(**c))
            .count()
    }

    /// Suspicion from substitutions this carrier can attribute, never from the
    /// mere presence of its alphabet.
    ///
    /// Backlog F16: this used to count every Cyrillic lookalike, so ordinary
    /// Russian scored at full confidence and the report escalated to a
    /// confirmed payload. A lookalike inside a Latin word remains as
    /// suspicious as it ever was: one is enough to say so.
    fn detect(&self, text: &str) -> f64 {
        let total_positions = text.chars().filter(|c| Self::is_position(*c)).count();
        if total_positions == 0 {
            return 0.0;
        }

        let substituted = Self::substitutions(text);
        if substituted == 0 {
            return 0.0;
        }

        let ratio = substituted as f64 / total_positions as f64;
        (ratio * 2.0).min(1.0) // Even small ratios are suspicious
    }

    /// Restore only the characters this carrier can show it substituted.
    ///
    /// Backlog F7: this used to rewrite every Cyrillic lookalike to its Latin
    /// twin with nothing gating it, so run on ordinary Russian it rewrote the
    /// writing itself, and `strip_all` inherited that for the stealth salt of
    /// SPEC_CORE_V2 §6.4 and for the document hash a claim is bound to. A
    /// document this carrier never marked comes back byte for byte.
    fn strip(&self, text: &str) -> String {
        let substitution = Self::attribute(text);
        text.chars()
            .enumerate()
            .map(|(i, c)| {
                if substitution[i] {
                    Self::original(c).unwrap_or(c)
                } else {
                    c
                }
            })
            .collect()
    }

    fn channel(&self) -> &'static [char] {
        &CHANNEL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CYRILLIC_RUSSIAN: &str = include_str!("../../../../tests/corpus/cyrillic_russian.txt");
    const EN_LONG_ARTICLE: &str = include_str!("../../../../tests/corpus/en_long_article.txt");

    // ─── Attribution: this carrier's alphabet is not this carrier's work ───

    /// Backlog F7. `strip()` used to rewrite every Cyrillic lookalike to its
    /// Latin twin, so run on ordinary Russian it silently rewrote the writing
    /// itself. A carrier that cannot show its own work leaves the text alone.
    #[test]
    fn strip_leaves_an_unmarked_cyrillic_document_byte_identical() {
        let hg = Homoglyph::new();
        assert_eq!(hg.strip(CYRILLIC_RUSSIAN), CYRILLIC_RUSSIAN);
    }

    /// The other half of F7: attribution must not cost the round trip. A
    /// document this carrier actually marked still strips back to its cover,
    /// character for character, at full load.
    #[test]
    fn strip_still_restores_the_cover_of_a_fully_marked_latin_document() {
        let hg = Homoglyph::new();
        let payload = vec![0xFFu8; hg.capacity(EN_LONG_ARTICLE) / 8];
        let stego = hg.encode(EN_LONG_ARTICLE, &payload).unwrap();

        assert_ne!(stego, EN_LONG_ARTICLE, "the mark must actually be there");
        assert_eq!(hg.strip(&stego), EN_LONG_ARTICLE);
    }

    /// Backlog F16. Detection on monolingual Russian reported a homoglyph
    /// signature at full confidence, because every Cyrillic lookalike read as
    /// a substituted bit. There is no Latin here to substitute into.
    #[test]
    fn detect_is_silent_on_an_unmarked_cyrillic_document() {
        assert_eq!(Homoglyph::new().detect(CYRILLIC_RUSSIAN), 0.0);
    }

    /// Backlog F16, root. `decode` returned Ok on any Cyrillic text, which is
    /// what let the detector claim a decodable payload in ordinary prose. A
    /// carrier with no channel in a document says so and names why.
    #[test]
    fn decode_refuses_a_document_written_in_the_script_it_borrows_from() {
        let message = Homoglyph::new()
            .decode(CYRILLIC_RUSSIAN)
            .expect_err("an unmarked Cyrillic document holds no homoglyph payload")
            .to_string();
        assert!(
            message.to_lowercase().contains("cyrillic"),
            "the refusal must name the script it found: {message}"
        );
    }

    /// A Latin word holding a lookalike is a substitution: no other reading of
    /// it is available. A Cyrillic word holding the same codepoint is a word.
    #[test]
    fn a_lookalike_is_attributed_by_the_script_of_the_word_around_it() {
        let hg = Homoglyph::new();

        // Latin word, one Cyrillic 'o'. The w, r, l and d are the evidence.
        assert_eq!(hg.strip("w\u{043E}rld"), "world");

        // Cyrillic word, same codepoint. The other two letters are the evidence.
        let russian_word = "\u{043C}\u{0438}\u{0440}";
        assert_eq!(hg.strip(russian_word), russian_word);
    }

    /// A document holding both scripts cannot be attributed as a whole, so the
    /// word around each lookalike decides, and a word that offers no evidence
    /// is left alone rather than guessed at.
    #[test]
    fn a_mixed_script_document_is_attributed_word_by_word() {
        let hg = Homoglyph::new();
        let text = "Hello \u{043C}\u{0438}\u{0440} w\u{043E}rld";
        assert_eq!(hg.strip(text), "Hello \u{043C}\u{0438}\u{0440} world");
    }

    #[test]
    fn channel_covers_every_mapped_codepoint() {
        let hg = Homoglyph::new();
        let channel = hg.channel();

        // Both sides of every pair: the carrier reads ASCII originals as bit 0
        // and Cyrillic substitutes as bit 1, so both belong to its alphabet.
        assert_eq!(channel.len(), HOMOGLYPH_MAP.len() * 2);
        for (ascii, cyrillic) in HOMOGLYPH_MAP {
            assert!(channel.contains(ascii), "missing original {ascii:?}");
            assert!(channel.contains(cyrillic), "missing substitute {cyrillic:?}");
        }
    }

    #[test]
    fn roundtrip_short() {
        let hg = Homoglyph::new();
        // Needs lots of substitutable chars (a, c, e, o, p, x, y, s, i, j + uppercase)
        let cover = "Access to the open science project expectations are exceptional in scope and practice";
        let secret = b"Hi";

        let cap = hg.capacity(cover);
        println!("Capacity: {} bits for {} bytes", cap, secret.len());
        assert!(cap >= secret.len() * 8, "Not enough capacity");

        let stego = hg.encode(cover, secret).unwrap();
        let decoded = hg.decode(&stego).unwrap();

        assert_eq!(&decoded[..secret.len()], secret);
    }

    #[test]
    fn visual_similarity() {
        let hg = Homoglyph::new();
        let cover = "The ecosystem operates exceptionally across all possible points of access today";
        let stego = hg.encode(cover, b"\x42").unwrap();

        // To a human, these look identical
        println!("Original: {cover}");
        println!("Stego:    {stego}");

        // But they differ at the byte level
        assert_ne!(cover, stego);

        // Strip should restore the original
        assert_eq!(hg.strip(&stego), cover);
    }

    #[test]
    fn capacity_english_text() {
        let hg = Homoglyph::new();
        // English text has ~40% substitutable characters (a, e, o, i, s, c, p, etc.)
        let text = "The quick brown fox jumps over the lazy dog";
        let cap = hg.capacity(text);

        // "The quick brown fox jumps over the lazy dog"
        // Substitutable: e, o, i, c, o, o, j, p, s, o, e, e, a, y, o
        // That's roughly 15+ positions
        assert!(cap > 10, "Expected >10 bits capacity, got {cap}");
    }

    #[test]
    fn detection_works() {
        let hg = Homoglyph::new();
        let cover = "Open access points are exceptional across every aspect of the core ecosystem today";
        let stego = hg.encode(cover, b"A").unwrap();

        assert!(hg.detect(&stego) > 0.0);
        assert_eq!(hg.detect(cover), 0.0);
    }

    #[test]
    fn survives_nfc_normalization() {
        use unicode_normalization::UnicodeNormalization;

        let hg = Homoglyph::new();
        let cover = "Access points operate exceptionally across every scope of science in practice today";
        let secret = b"OK";

        let stego = hg.encode(cover, secret).unwrap();

        // Apply NFC normalization (what Google Docs does)
        let normalized: String = stego.nfc().collect();

        // Homoglyphs should survive NFC!
        let decoded = hg.decode(&normalized).unwrap();
        assert_eq!(&decoded[..secret.len()], secret);
    }

    #[test]
    fn capacity_exceeded_error() {
        let hg = Homoglyph::new();
        let cover = "xyz"; // Very few substitutable chars
        let secret = b"This is way too long";

        let result = hg.encode(cover, secret);
        assert!(matches!(result, Err(SteganoError::CapacityExceeded { .. })));
    }
}
