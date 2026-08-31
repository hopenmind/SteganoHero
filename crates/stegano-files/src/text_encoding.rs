//! Robust text-file decoding + mojibake repair for import.
//!
//! Provenance: copied verbatim (tests included) from the upstream converter
//! project, `crates/core/src/text_encoding.rs`. Both trees share one owner, so
//! this reuse is deliberate. Kept in sync manually; re-sync from the upstream converter if
//! that tree's copy moves.
//!
//! Two distinct problems are handled here, both in pure Rust (no external crate):
//!
//! 1. **Wrong charset** - a file is UTF-16 (BOM) or legacy Windows-1252, so a
//!    strict `read_to_string` would fail or garble. `decode_bytes` honors a
//!    BOM and falls back to Windows-1252 (which can decode any byte sequence).
//!
//! 2. **Mojibake** - a file is valid UTF-8 but its content was already
//!    double-encoded upstream (UTF-8 bytes interpreted as Windows-1252 and
//!    re-saved), so it literally contains `SchrÃ¶dinger` / `â€"`. `fix_mojibake`
//!    reverses that one corruption step (ftfy-style), guarded so clean text is
//!    never touched.

use std::path::Path;

/// Read a text file as UTF-8, tolerating UTF-16/Windows-1252 and repairing
/// common UTF-8-as-Windows-1252 mojibake.
pub fn read_text(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    Ok(fix_mojibake(&decode_bytes(&bytes)))
}

/// Decode raw bytes to a String: honor a UTF-8/UTF-16 BOM, else try UTF-8, else
/// fall back to Windows-1252 (lossless for any byte sequence).
pub fn decode_bytes(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(rest).into_owned();
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return decode_utf16(rest, false);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return decode_utf16(rest, true);
    }
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => bytes.iter().map(|&b| cp1252_to_char(b)).collect(),
    }
}

fn decode_utf16(bytes: &[u8], big_endian: bool) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| if big_endian { u16::from_be_bytes([c[0], c[1]]) } else { u16::from_le_bytes([c[0], c[1]]) })
        .collect();
    String::from_utf16_lossy(&units)
}

/// Repair one step of UTF-8-as-Windows-1252 mojibake (e.g. `Ã¶` -> `ö`,
/// `â€"` -> em dash). Only applied when the text shows mojibake markers AND the
/// re-decode is valid UTF-8 that strictly reduces those markers, so clean text
/// (including legitimate accented French) passes through untouched.
pub fn fix_mojibake(s: &str) -> String {
    if mojibake_score(s) == 0 {
        return s.to_string();
    }
    // Repair per maximal run of high (> 0x7F) characters, NOT the whole string:
    // a clean accent (e.g. 'é' = U+00E9) re-encodes to a lone 0xE9 byte that is
    // invalid UTF-8, so a whole-string pass would abort on the first clean
    // accent. Real mojibake is a RUN of high chars (`Ã©` -> bytes C3 A9) that
    // re-decodes to FEWER chars (`é`); a lone clean accent does not. That length
    // collapse is the reliable signal, so clean text is left untouched.
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if (chars[i] as u32) <= 0x7F {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && (chars[i] as u32) > 0x7F {
            i += 1;
        }
        let run = &chars[start..i];
        let mut bytes = Vec::with_capacity(run.len());
        let reversible = run.iter().all(|&c| match char_to_cp1252(c) {
            Some(b) => { bytes.push(b); true }
            None => false,
        });
        let fixed = if reversible {
            match String::from_utf8(bytes) {
                // A real multi-byte char was reconstructed (mojibake collapses
                // N source chars into fewer). A lone clean accent would not.
                Ok(dec) if dec.chars().count() < run.len() => Some(dec),
                _ => None,
            }
        } else {
            None
        };
        match fixed {
            Some(dec) => out.push_str(&dec),
            None => out.extend(run.iter()),
        }
    }
    out
}

/// Count telltale mojibake markers (UTF-8 lead bytes mis-decoded to Latin-1
/// uppercase letters followed by a continuation-range glyph).
fn mojibake_score(s: &str) -> usize {
    let mut n = 0;
    let bytes: Vec<char> = s.chars().collect();
    for w in bytes.windows(2) {
        let a = w[0];
        let b = w[1];
        // Ã / Â / Î / â / ï etc. (UTF-8 lead bytes 0xC2..0xEF as Latin-1) followed
        // by a char in the 0x80..0xBF "continuation" visual range or the cp1252
        // special block.
        let lead = matches!(a as u32, 0xC2 | 0xC3 | 0xCE | 0xCF | 0xE2);
        let bu = b as u32;
        let cont = (0x80..=0xBF).contains(&bu)
            // cp1252 special block that UTF-8 continuation bytes 0x80..0x9F decode to
            || matches!(bu, 0x20AC | 0x201A | 0x0192 | 0x201E | 0x2026 | 0x2020 | 0x2021
                          | 0x02C6 | 0x2030 | 0x0160 | 0x2039 | 0x0152 | 0x2018 | 0x2019
                          | 0x201C | 0x201D | 0x2022 | 0x2013 | 0x2014 | 0x2122 | 0x0161
                          | 0x203A | 0x0153);
        if lead && cont {
            n += 1;
        }
    }
    n
}

/// Windows-1252 byte -> Unicode char (0x80..0x9F differ from Latin-1).
fn cp1252_to_char(b: u8) -> char {
    match b {
        0x80 => '\u{20AC}', 0x82 => '\u{201A}', 0x83 => '\u{0192}', 0x84 => '\u{201E}',
        0x85 => '\u{2026}', 0x86 => '\u{2020}', 0x87 => '\u{2021}', 0x88 => '\u{02C6}',
        0x89 => '\u{2030}', 0x8A => '\u{0160}', 0x8B => '\u{2039}', 0x8C => '\u{0152}',
        0x8E => '\u{017D}', 0x91 => '\u{2018}', 0x92 => '\u{2019}', 0x93 => '\u{201C}',
        0x94 => '\u{201D}', 0x95 => '\u{2022}', 0x96 => '\u{2013}', 0x97 => '\u{2014}',
        0x98 => '\u{02DC}', 0x99 => '\u{2122}', 0x9A => '\u{0161}', 0x9B => '\u{203A}',
        0x9C => '\u{0153}', 0x9E => '\u{017E}', 0x9F => '\u{0178}',
        // 0x81,0x8D,0x8F,0x90,0x9D are undefined in cp1252 -> map to the C1 control.
        _ => b as char,
    }
}

/// Inverse of `cp1252_to_char`: Unicode char -> Windows-1252 byte, or None when
/// the char is outside the cp1252 repertoire (so mojibake reversal must abort).
fn char_to_cp1252(c: char) -> Option<u8> {
    let u = c as u32;
    let b = match u {
        0x20AC => 0x80, 0x201A => 0x82, 0x0192 => 0x83, 0x201E => 0x84,
        0x2026 => 0x85, 0x2020 => 0x86, 0x2021 => 0x87, 0x02C6 => 0x88,
        0x2030 => 0x89, 0x0160 => 0x8A, 0x2039 => 0x8B, 0x0152 => 0x8C,
        0x017D => 0x8E, 0x2018 => 0x91, 0x2019 => 0x92, 0x201C => 0x93,
        0x201D => 0x94, 0x2022 => 0x95, 0x2013 => 0x96, 0x2014 => 0x97,
        0x02DC => 0x98, 0x2122 => 0x99, 0x0161 => 0x9A, 0x203A => 0x9B,
        0x0153 => 0x9C, 0x017E => 0x9E, 0x0178 => 0x9F,
        0x00..=0x7F | 0xA0..=0xFF => u as u8,
        _ => return None,
    };
    Some(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    // All non-ASCII written with \u escapes so the test source itself stays
    // pure ASCII (avoids any lexer/encoding ambiguity with smart quotes).
    #[test]
    fn repairs_accent_mojibake() {
        // "Schrodinger" with o-umlaut: U+00F6 (UTF-8 C3 B6) mojibaked -> C3 + B6.
        assert_eq!(fix_mojibake("Schr\u{C3}\u{B6}dinger"), "Schr\u{F6}dinger");
        // "deja" accents: e-acute C3 A9, a-grave C3 A0.
        assert_eq!(fix_mojibake("d\u{C3}\u{A9}j\u{C3}\u{A0}"), "d\u{E9}j\u{E0}");
        assert_eq!(fix_mojibake("\u{C3}\u{A9}quation"), "\u{E9}quation");
    }

    #[test]
    fn repairs_punctuation_mojibake() {
        // Em dash U+2014 (UTF-8 E2 80 94) -> mojibake glyphs U+00E2 U+20AC U+201D.
        assert_eq!(fix_mojibake("a \u{E2}\u{20AC}\u{201D} b"), "a \u{2014} b");
        // Right single quote U+2019 (UTF-8 E2 80 99) -> U+00E2 U+20AC U+2122.
        assert_eq!(fix_mojibake("it\u{E2}\u{20AC}\u{2122}s"), "it\u{2019}s");
    }

    #[test]
    fn fixes_mojibake_amid_clean_accents() {
        // A clean accent (caf-e-acute) and a clean a-grave next to a mojibaked
        // e-acute: only the mojibake is reversed, the clean accents are kept.
        // "caf\u{E9} d<C3><A9>j\u{E0}" -> "caf\u{E9} d\u{E9}j\u{E0}"
        let s = "caf\u{E9} d\u{C3}\u{A9}j\u{E0}";
        assert_eq!(fix_mojibake(s), "caf\u{E9} d\u{E9}j\u{E0}");
    }

    #[test]
    fn leaves_clean_text_untouched() {
        for s in ["caf\u{E9} d\u{E9}j\u{E0} vu", "plain ascii", "na\u{EF}ve No\u{EB}l", "x = y + 1", ""] {
            assert_eq!(fix_mojibake(s), s, "clean text must not change: {s:?}");
        }
    }

    #[test]
    fn decode_bytes_utf8_and_cp1252() {
        assert_eq!(decode_bytes("caf\u{E9}".as_bytes()), "caf\u{E9}");
        // 0x97 is an em dash in cp1252 but invalid UTF-8 -> cp1252 fallback.
        assert_eq!(decode_bytes(&[b'a', 0x97, b'b']), "a\u{2014}b");
        // UTF-8 BOM is stripped.
        assert_eq!(decode_bytes(&[0xEF, 0xBB, 0xBF, b'h', b'i']), "hi");
    }
}
