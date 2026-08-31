# Test corpus

Nine documents covering the cases that break text carriers. Every figure in `manifest.json` is measured, not estimated.

Two uses: fixtures for the unit test suite, and realistic material for exercising the command surface.

## Coverage map

| File | Why it exists |
|---|---|
| `en_long_article.txt` | Happy path. 1130 substitutable positions, ratio 0.413. Long enough to carry a full preamble plus payload plus resync markers. |
| `fr_accented.txt` | Accented Latin. Ratio 0.392, close to English, so the capacity model holds across both. Exercises NFC and NFD stability and forces the n-gram oracle to pick French over English. |
| `technical_markdown.md` | Structured text with fenced code and a table. Substituting inside a code fence would corrupt a shell command, so this is where placement policy needs an opinion. |
| `mixed_multilingual.txt` | Four languages in one document, shaped like a real distribution notice. The n-gram oracle must return low confidence rather than a confident wrong answer. |
| `en_short.txt` | 32 positions, 4 bytes at the Sign ratio. Below the preamble threshold, so standard mode must refuse rather than truncate. A detached signature is the only valid path. |
| `minimal_tiny.txt` | 3 positions, zero effective capacity. Every carrier must raise. |
| `cjk_japanese.txt` | Zero homoglyph capacity on non-Latin script. Invisible-character carriers still work, which proves carrier choice is script-dependent. |
| `cyrillic_russian.txt` | Cyrillic homoglyphs that look like Latin letters. Exercises non-destructive handling of text that was never encoded. |
| `already_carrying.txt` | Carries U+200B, U+200C, U+2060 and U+FEFF before any encoding. Tests false-positive detection and stealth-mode salt derivation. |

## Regenerating the measurements

From `SteganoHero-Rust-v2/`:

```powershell
$c = "tests\corpus"
$hg = 'a','c','e','o','p','x','y','s','i','j','A','B','C','E','H','K','M','O','P','T','X','S','I','J'
$inv = 0x200B,0x200C,0x2060,0xFEFF,0x2063,0x200E,0x200F,0x202C
Get-ChildItem -LiteralPath $c -File | Where-Object { $_.Extension -in '.txt','.md' } | Sort-Object Name | ForEach-Object {
  $t = [System.IO.File]::ReadAllText($_.FullName); $ch = $t.ToCharArray()
  $h = ($ch | Where-Object { $hg -ccontains [string]$_ }).Count
  [PSCustomObject]@{ File=$_.Name; Chars=$ch.Count; HgPos=$h
    Conceal=[math]::Floor($h*0.25/8); Sign=[math]::Floor($h*0.50/8); Mark=[math]::Floor($h*0.85/8)
    Invisible=($ch | Where-Object { $inv -contains [int]$_ }).Count
    Cyrillic=($ch | Where-Object { [int]$_ -ge 0x0400 -and [int]$_ -le 0x04FF }).Count }
} | Format-Table -AutoSize
```

The capacity columns use the per-mission fill ratios. Those defaults are reasoned rather than measured.

## Encoding

All files are UTF-8 without BOM, except `already_carrying.txt` which contains a U+FEFF mid-document on purpose. Do not let an editor normalise these files on save, and do not reflow them: the character counts are fixtures.
