//! The frame: preamble replicas, resync markers and the payload region laid
//! out over a carrier's substitutable positions. SPEC_CORE_V2 §3.
//!
//! The frame is a bit per position, in document order:
//!
//! ```text
//! 0                192                                    W-192          W    N
//! | head preamble  | payload region with resync markers   | tail replica  |....|
//! ```
//!
//! `W = 8 * floor(N / 8)`. A carrier writes whole bytes, so the last `N % 8`
//! positions carry nothing and stay at bit 0. The tail replica is anchored to
//! the end of the written region, not to the end of the document, which is why
//! the reader sweeps eight end offsets when it looks for it.
//!
//! What this fixes. A carrier reading every position it can find returns the
//! payload followed by one zero byte per unused position, and the package
//! parser rejects that as corrupt. The preamble's `payload_bits` field tells
//! the reader how many bits were actually written, so the payload region is
//! read exactly and the rest of the document is left alone.
//!
//! Bit placement itself is untouched: the frame decides *what* bits a carrier
//! receives, never *where* the carrier puts them.

use crate::crypto::keytree::SALT_LEN;
use crate::error::{Result, SteganoError};
use crate::format::preamble::{Flags, Preamble, MAGIC, PREAMBLE_BITS};

/// Resync marker size in bytes: magic, then occurrence index.
pub const MARKER_LEN: usize = 4;
/// Resync marker size in substitutable positions.
pub const MARKER_BITS: usize = MARKER_LEN * 8;

/// Lower bound on marker spacing, SPEC_CORE_V2 §3.2.
pub const MIN_MARKER_SPACING: usize = 64;
/// Upper bound on marker spacing, SPEC_CORE_V2 §3.2.
pub const MAX_MARKER_SPACING: usize = 512;

/// How many end offsets the tail sweep tries. A carrier writes whole bytes, so
/// between zero and seven trailing positions are left unwritten.
pub const TAIL_SWEEP: usize = 8;

/// Largest occurrence index a resync candidate may claim before the scanner
/// treats it as a coincidence in payload bytes rather than a marker.
pub const MAX_OCCURRENCE: u16 = 1024;

/// Marker spacing in substitutable positions: `clamp(N / 8, 64, 512)`.
///
/// Derived from total length alone. It must never derive from the passcode:
/// the reader needs the markers in order to find the salt, and the salt is
/// what the passcode is combined with. Deriving spacing from the passcode
/// would close that loop on itself.
pub fn marker_spacing(positions: usize) -> usize {
    (positions / 8).clamp(MIN_MARKER_SPACING, MAX_MARKER_SPACING)
}

/// Which replica a preamble was recovered from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreambleSource {
    /// The first 192 substitutable positions.
    Head,
    /// The last 192 written positions, bit reversed.
    Tail,
}

/// A resync marker found in a bit stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResyncHit {
    /// Bit offset of the marker inside the stream that was scanned.
    pub bit_offset: usize,
    /// Occurrence index the marker carries.
    pub occurrence: u16,
}

impl ResyncHit {
    /// Where this marker sits in the original document, given that document's
    /// total substitutable position count.
    ///
    /// An excerpt on its own cannot answer this: spacing derives from the
    /// total length, which an excerpt does not know. The marker still says
    /// "this is a v2 document and you are at occurrence N", which is what
    /// §3.2 promises.
    pub fn document_position(&self, positions: usize) -> usize {
        self.occurrence as usize * marker_spacing(positions)
    }
}

/// What a complete frame read yields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameContents {
    pub preamble: Preamble,
    pub payload: Vec<u8>,
}

/// Where every region of a frame sits, for a given position count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    positions: usize,
    written_bits: usize,
    spacing: usize,
    markers: Vec<usize>,
    payload_slots: Vec<(usize, usize)>,
}

impl Layout {
    /// Compute the layout for a cover offering `positions` substitutable slots.
    ///
    /// Raises `CapacityExceeded` when the cover cannot hold two preamble
    /// replicas plus at least one payload byte. It never drops a replica to
    /// make room: a document without both replicas is not a v2 document.
    pub fn for_positions(positions: usize) -> Result<Self> {
        let written_bits = positions - positions % 8;
        let minimum = 2 * PREAMBLE_BITS + 8;
        if written_bits < minimum {
            return Err(SteganoError::CapacityExceeded {
                needed: minimum,
                available: written_bits,
            });
        }

        let spacing = marker_spacing(positions);
        let region_start = PREAMBLE_BITS;
        let region_end = written_bits - PREAMBLE_BITS;

        let mut markers = Vec::new();
        let mut occurrence = 1usize;
        loop {
            let offset = occurrence * spacing;
            if offset + MARKER_BITS > region_end {
                break;
            }
            if offset >= region_start {
                markers.push(offset);
            }
            occurrence += 1;
        }

        let mut payload_slots = Vec::new();
        let mut cursor = region_start;
        for &marker in &markers {
            if marker > cursor {
                payload_slots.push((cursor, marker - cursor));
            }
            cursor = marker + MARKER_BITS;
        }
        if region_end > cursor {
            payload_slots.push((cursor, region_end - cursor));
        }

        Ok(Self {
            positions,
            written_bits,
            spacing,
            markers,
            payload_slots,
        })
    }

    /// Substitutable positions the cover offers.
    pub fn positions(&self) -> usize {
        self.positions
    }

    /// Positions the carrier actually writes: `8 * floor(N / 8)`.
    pub fn written_bits(&self) -> usize {
        self.written_bits
    }

    /// Marker spacing in positions.
    pub fn spacing(&self) -> usize {
        self.spacing
    }

    /// Bit offsets of every resync marker.
    pub fn markers(&self) -> &[usize] {
        &self.markers
    }

    /// Occurrence index of the marker at `bit_offset`.
    fn occurrence_at(&self, bit_offset: usize) -> u16 {
        (bit_offset / self.spacing) as u16
    }

    /// Payload capacity in positions, after both replicas and every marker.
    pub fn payload_capacity_bits(&self) -> usize {
        let free: usize = self.payload_slots.iter().map(|(_, len)| len).sum();
        free - free % 8
    }

    /// Payload capacity in whole bytes.
    pub fn payload_capacity_bytes(&self) -> usize {
        self.payload_capacity_bits() / 8
    }
}

// ─── Bit helpers ───

/// Bytes to bits, most significant bit first. Matches every carrier.
pub fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1))
        .collect()
}

/// Bits to bytes, most significant bit first, discarding a trailing partial byte.
pub fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    bits.chunks_exact(8)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold(0u8, |acc, (i, &bit)| acc | (bit << (7 - i)))
        })
        .collect()
}

fn marker_bytes(occurrence: u16) -> [u8; MARKER_LEN] {
    let mut out = [0u8; MARKER_LEN];
    out[..2].copy_from_slice(&MAGIC.to_be_bytes());
    out[2..].copy_from_slice(&occurrence.to_be_bytes());
    out
}

// ─── Build ───

/// Lay a frame over `positions` substitutable slots.
///
/// Returns one bit per written position, ready for the carrier to place.
/// Raises rather than truncating when the payload does not fit.
pub fn build(
    positions: usize,
    flags: Flags,
    salt: [u8; SALT_LEN],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let layout = Layout::for_positions(positions)?;

    let needed = payload.len() * 8;
    if needed == 0 {
        return Err(SteganoError::InvalidInput(
            "frame: refusing to build an empty payload".into(),
        ));
    }
    if needed > layout.payload_capacity_bits() {
        return Err(SteganoError::CapacityExceeded {
            needed,
            available: layout.payload_capacity_bits(),
        });
    }
    if needed > u16::MAX as usize {
        return Err(SteganoError::CapacityExceeded {
            needed,
            available: u16::MAX as usize,
        });
    }

    let preamble = Preamble::new(flags, salt, needed as u16);
    let preamble_bits = bytes_to_bits(&preamble.to_bytes());

    let mut stream = vec![0u8; layout.written_bits];

    // Head replica, forward.
    stream[..PREAMBLE_BITS].copy_from_slice(&preamble_bits);

    // Tail replica, reversed, anchored to the end of the written region so a
    // scan running backwards from the document end meets it in reading order.
    let tail_start = layout.written_bits - PREAMBLE_BITS;
    for (i, bit) in preamble_bits.iter().rev().enumerate() {
        stream[tail_start + i] = *bit;
    }

    // Resync markers.
    for &offset in &layout.markers {
        let bits = bytes_to_bits(&marker_bytes(layout.occurrence_at(offset)));
        stream[offset..offset + MARKER_BITS].copy_from_slice(&bits);
    }

    // Payload, poured into the free slots in document order.
    let payload_bits = bytes_to_bits(payload);
    let mut written = 0usize;
    for &(start, len) in &layout.payload_slots {
        if written == payload_bits.len() {
            break;
        }
        let take = len.min(payload_bits.len() - written);
        stream[start..start + take].copy_from_slice(&payload_bits[written..written + take]);
        written += take;
    }

    debug_assert_eq!(written, payload_bits.len());
    Ok(stream)
}

// ─── Read ───

/// Read a complete frame from a bit stream covering every position of an
/// intact document.
///
/// Both replicas must be present and identical. A document missing one of
/// them has been truncated or altered, and this raises rather than returning
/// whatever the surviving half suggests.
pub fn read(bits: &[u8]) -> Result<FrameContents> {
    let layout = Layout::for_positions(bits.len())?;

    let head = Preamble::parse(&bits_to_bytes(&bits[..PREAMBLE_BITS])).map_err(|e| {
        SteganoError::DecodingFailed {
            method: "frame".into(),
            reason: format!("no preamble at the head of the document: {e}"),
        }
    })?;

    let tail_start = layout.written_bits - PREAMBLE_BITS;
    let mut tail_bits: Vec<u8> = bits[tail_start..tail_start + PREAMBLE_BITS].to_vec();
    tail_bits.reverse();
    let tail = Preamble::parse(&bits_to_bytes(&tail_bits)).map_err(|e| {
        SteganoError::DecodingFailed {
            method: "frame".into(),
            reason: format!("tail preamble replica missing or damaged: {e}"),
        }
    })?;

    if tail != head {
        return Err(SteganoError::DecodingFailed {
            method: "frame".into(),
            reason: "preamble replicas disagree: the document was altered between them".into(),
        });
    }

    let payload_bits = head.payload_bits as usize;
    if payload_bits % 8 != 0 {
        return Err(SteganoError::DecodingFailed {
            method: "frame".into(),
            reason: format!("payload_bits {payload_bits} is not a whole number of bytes"),
        });
    }
    if payload_bits > layout.payload_capacity_bits() {
        return Err(SteganoError::DecodingFailed {
            method: "frame".into(),
            reason: format!(
                "payload_bits {payload_bits} exceeds the {} this document can hold",
                layout.payload_capacity_bits()
            ),
        });
    }

    // Read exactly payload_bits, never every position that happens to exist.
    let mut collected = Vec::with_capacity(payload_bits);
    for &(start, len) in &layout.payload_slots {
        if collected.len() == payload_bits {
            break;
        }
        let take = len.min(payload_bits - collected.len());
        collected.extend_from_slice(&bits[start..start + take]);
    }

    if collected.len() != payload_bits {
        return Err(SteganoError::DecodingFailed {
            method: "frame".into(),
            reason: format!(
                "payload region holds {} bits, the preamble declared {payload_bits}",
                collected.len()
            ),
        });
    }

    Ok(FrameContents {
        preamble: head,
        payload: bits_to_bytes(&collected),
    })
}

/// Recover a preamble from a possibly truncated document.
///
/// Head first, then the tail replica. The tail sweep tries eight end offsets
/// because a carrier writes whole bytes and leaves up to seven trailing
/// positions untouched, and head truncation shifts which of them survive.
pub fn locate_preamble(bits: &[u8]) -> Result<(Preamble, PreambleSource)> {
    if bits.len() >= PREAMBLE_BITS {
        if let Ok(preamble) = Preamble::parse(&bits_to_bytes(&bits[..PREAMBLE_BITS])) {
            return Ok((preamble, PreambleSource::Head));
        }
    }

    for drop in 0..TAIL_SWEEP {
        if bits.len() < PREAMBLE_BITS + drop {
            break;
        }
        let end = bits.len() - drop;
        let mut window: Vec<u8> = bits[end - PREAMBLE_BITS..end].to_vec();
        window.reverse();
        if let Ok(preamble) = Preamble::parse(&bits_to_bytes(&window)) {
            return Ok((preamble, PreambleSource::Tail));
        }
    }

    Err(SteganoError::DecodingFailed {
        method: "frame".into(),
        reason: "neither preamble replica survived in this text".into(),
    })
}

/// Every resync marker in a bit stream, in stream order.
///
/// Scans at every bit offset, because an excerpt does not begin on a byte
/// boundary of the original document. Candidates that parse as a preamble are
/// skipped: a preamble is a stronger signal and is reported as itself.
///
/// The marker is four bytes with no checksum of its own, so a magic pattern
/// can occur by chance inside payload bytes. The occurrence bound cuts that to
/// roughly one candidate in four million per offset. It is a resynchronisation
/// aid, not an authenticator.
pub fn scan_resync(bits: &[u8]) -> Vec<ResyncHit> {
    let magic_bits = bytes_to_bits(&MAGIC.to_be_bytes());
    let mut hits = Vec::new();

    if bits.len() < MARKER_BITS {
        return hits;
    }

    let mut offset = 0usize;
    while offset + MARKER_BITS <= bits.len() {
        if bits[offset..offset + 16] != magic_bits[..] {
            offset += 1;
            continue;
        }

        // A preamble also opens with the magic. Report it as a preamble, not
        // as a marker with a nonsense occurrence index.
        if offset + PREAMBLE_BITS <= bits.len()
            && Preamble::parse(&bits_to_bytes(&bits[offset..offset + PREAMBLE_BITS])).is_ok()
        {
            offset += PREAMBLE_BITS;
            continue;
        }

        let occurrence_bytes = bits_to_bytes(&bits[offset + 16..offset + MARKER_BITS]);
        let occurrence = u16::from_be_bytes([occurrence_bytes[0], occurrence_bytes[1]]);
        if occurrence >= 1 && occurrence <= MAX_OCCURRENCE {
            hits.push(ResyncHit {
                bit_offset: offset,
                occurrence,
            });
            offset += MARKER_BITS;
            continue;
        }

        offset += 1;
    }

    hits
}

/// The first resync marker in a bit stream, if any.
pub fn locate_resync(bits: &[u8]) -> Option<ResyncHit> {
    scan_resync(bits).into_iter().next()
}

/// Is this bit stream framed at all?
///
/// The v1 to v2 discriminator. It answers a question, it does not decide a
/// fallback: the caller states which format it read.
pub fn is_framed(bits: &[u8]) -> bool {
    if locate_preamble(bits).is_ok() {
        return true;
    }
    // A light frame (SPEC_CORE_V2 §3.2) is framed too: its version byte marks it
    // and its header checksum confirms it, so a coincidental byte is not mistaken
    // for one.
    use crate::format::frame_light;
    if matches!(
        frame_light::peek_version(bits),
        Some(frame_light::VERSION_LIGHT_PLAIN | frame_light::VERSION_LIGHT_SEALED)
    ) && frame_light::read_light(bits).is_ok()
    {
        return true;
    }
    // A saturated or excerpted light channel carries a whole frame somewhere past
    // the start of the stream; identifying it is what lets a saturated document
    // recover from a fragment (SPEC_SATURATE, SAT-CORE-2).
    frame_light::scan_light(bits).is_some()
}

/// Payload capacity in bytes for a cover offering `positions` slots.
pub fn payload_capacity_bytes(positions: usize) -> Result<usize> {
    Ok(Layout::for_positions(positions)?.payload_capacity_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; SALT_LEN] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];

    // ─── Bit helpers ───

    #[test]
    fn bit_conversion_round_trips_and_matches_carrier_order() {
        let bytes = [0b1000_0001u8, 0x00, 0xFF, 0x5A];
        let bits = bytes_to_bits(&bytes);
        assert_eq!(bits.len(), 32);
        assert_eq!(&bits[..8], &[1, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(bits_to_bytes(&bits), bytes);
    }

    // ─── Layout ───

    #[test]
    fn spacing_follows_the_specified_formula() {
        assert_eq!(marker_spacing(0), MIN_MARKER_SPACING);
        assert_eq!(marker_spacing(512), MIN_MARKER_SPACING, "clamped below");
        assert_eq!(marker_spacing(1130), 141, "the long article");
        assert_eq!(marker_spacing(4096), MAX_MARKER_SPACING, "clamped above");
        assert_eq!(marker_spacing(100_000), MAX_MARKER_SPACING);
    }

    #[test]
    fn spacing_never_depends_on_anything_but_length() {
        // The salt bootstrap is circular if spacing derives from the passcode:
        // the markers are how a reader finds the salt in the first place.
        for positions in [600usize, 1130, 4096] {
            assert_eq!(marker_spacing(positions), marker_spacing(positions));
        }
    }

    #[test]
    fn a_cover_too_small_for_two_replicas_raises() {
        // minimal_tiny.txt offers three positions.
        match Layout::for_positions(3) {
            Err(SteganoError::CapacityExceeded { needed, available }) => {
                assert_eq!(needed, 2 * PREAMBLE_BITS + 8);
                assert_eq!(available, 0);
            }
            other => panic!("expected CapacityExceeded, got {other:?}"),
        }
    }

    #[test]
    fn a_cover_with_no_positions_raises_rather_than_producing_a_frame() {
        // cjk_japanese.txt and cyrillic_russian.txt both land here.
        assert!(matches!(
            Layout::for_positions(0),
            Err(SteganoError::CapacityExceeded { available: 0, .. })
        ));
    }

    #[test]
    fn the_smallest_legal_cover_is_exactly_two_replicas_plus_one_byte() {
        assert!(Layout::for_positions(2 * PREAMBLE_BITS + 7).is_err());
        let layout = Layout::for_positions(2 * PREAMBLE_BITS + 8).unwrap();
        assert_eq!(layout.payload_capacity_bytes(), 1);
    }

    #[test]
    fn markers_never_overlap_a_replica_or_each_other() {
        for positions in [400usize, 1130, 2260, 9000] {
            let layout = Layout::for_positions(positions).unwrap();
            let mut previous_end = PREAMBLE_BITS;
            for &offset in layout.markers() {
                assert!(offset >= previous_end, "marker at {offset} overlaps");
                assert!(
                    offset + MARKER_BITS <= layout.written_bits() - PREAMBLE_BITS,
                    "marker at {offset} runs into the tail replica"
                );
                previous_end = offset + MARKER_BITS;
            }
        }
    }

    #[test]
    fn the_long_article_geometry_is_what_the_corpus_manifest_implies() {
        // 1130 substitutable positions, measured, in tests/corpus/manifest.json.
        let layout = Layout::for_positions(1130).unwrap();
        assert_eq!(layout.written_bits(), 1128);
        assert_eq!(layout.spacing(), 141);
        assert_eq!(layout.markers(), &[282, 423, 564, 705, 846]);
        assert_eq!(layout.payload_capacity_bytes(), 73);
    }

    // ─── Build and read ───

    #[test]
    fn a_frame_round_trips_its_payload_exactly() {
        let payload = b"two";
        let bits = build(1130, Flags::conceal(), SALT, payload).unwrap();
        let contents = read(&bits).unwrap();

        assert_eq!(contents.payload, payload);
        assert_eq!(contents.preamble.salt, SALT);
        assert_eq!(contents.preamble.payload_bits, 24);
    }

    /// The regression guard for the live defect.
    #[test]
    fn a_payload_far_smaller_than_the_cover_reads_back_without_trailing_zeros() {
        let payload = b"Hi";
        let bits = build(1130, Flags::conceal(), SALT, payload).unwrap();
        let contents = read(&bits).unwrap();

        assert_eq!(
            contents.payload.len(),
            2,
            "the reader must stop at payload_bits, not consume every position"
        );
        assert_eq!(contents.payload, payload);
        assert!(
            !contents.payload.iter().any(|b| *b == 0),
            "no trailing zero byte may reach the parser"
        );
    }

    #[test]
    fn a_payload_filling_the_capacity_exactly_round_trips() {
        let capacity = payload_capacity_bytes(1130).unwrap();
        let payload: Vec<u8> = (0..capacity).map(|i| (i % 251) as u8).collect();
        let bits = build(1130, Flags::conceal(), SALT, &payload).unwrap();
        assert_eq!(read(&bits).unwrap().payload, payload);
    }

    #[test]
    fn a_payload_one_byte_over_capacity_raises_and_never_truncates() {
        let capacity = payload_capacity_bytes(1130).unwrap();
        let payload = vec![0xAAu8; capacity + 1];
        match build(1130, Flags::conceal(), SALT, &payload) {
            Err(SteganoError::CapacityExceeded { needed, available }) => {
                assert_eq!(needed, (capacity + 1) * 8);
                assert_eq!(available, capacity * 8);
            }
            other => panic!("expected CapacityExceeded, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_payload_is_refused() {
        assert!(matches!(
            build(1130, Flags::conceal(), SALT, b""),
            Err(SteganoError::InvalidInput(_))
        ));
    }

    #[test]
    fn payload_bits_records_the_written_length() {
        for length in [1usize, 2, 17, 73] {
            let payload = vec![0x5Au8; length];
            let bits = build(1130, Flags::conceal(), SALT, &payload).unwrap();
            let (preamble, source) = locate_preamble(&bits).unwrap();
            assert_eq!(source, PreambleSource::Head);
            assert_eq!(preamble.payload_bits as usize, length * 8);
        }
    }

    #[test]
    fn both_replicas_carry_the_same_preamble() {
        let bits = build(1130, Flags::conceal(), SALT, b"replicated").unwrap();
        let layout = Layout::for_positions(1130).unwrap();

        let head = Preamble::parse(&bits_to_bytes(&bits[..PREAMBLE_BITS])).unwrap();

        let tail_start = layout.written_bits() - PREAMBLE_BITS;
        let mut tail: Vec<u8> = bits[tail_start..tail_start + PREAMBLE_BITS].to_vec();
        tail.reverse();
        let tail = Preamble::parse(&bits_to_bytes(&tail)).unwrap();

        assert_eq!(head, tail);
    }

    // ─── Truncation ───

    #[test]
    fn a_head_truncated_document_still_finds_the_tail_replica() {
        let bits = build(1130, Flags::conceal(), SALT, b"survives a cut").unwrap();

        // Cut deep enough to destroy the head replica entirely.
        for cut in [193usize, 250, 400, 600] {
            let truncated = &bits[cut..];
            let (preamble, source) = locate_preamble(truncated)
                .unwrap_or_else(|e| panic!("cut of {cut} lost both replicas: {e}"));
            assert_eq!(source, PreambleSource::Tail);
            assert_eq!(preamble.salt, SALT);
        }
    }

    #[test]
    fn a_tail_truncated_document_still_finds_the_head_replica() {
        let bits = build(1130, Flags::conceal(), SALT, b"survives a cut").unwrap();

        for keep in [PREAMBLE_BITS, 300usize, 700, 1000] {
            let truncated = &bits[..keep];
            let (preamble, source) = locate_preamble(truncated)
                .unwrap_or_else(|e| panic!("keeping {keep} lost both replicas: {e}"));
            assert_eq!(source, PreambleSource::Head);
            assert_eq!(preamble.salt, SALT);
        }
    }

    #[test]
    fn a_truncated_document_refuses_to_yield_a_payload() {
        // Metadata survives truncation, the payload does not. Saying so is the
        // point: no partial payload is ever returned as if it were whole.
        let bits = build(1130, Flags::conceal(), SALT, b"not recoverable").unwrap();
        let truncated = &bits[..900];

        assert!(locate_preamble(truncated).is_ok());
        match read(truncated) {
            Err(SteganoError::DecodingFailed { method, reason }) => {
                assert_eq!(method, "frame");
                assert!(!reason.is_empty());
            }
            other => panic!("expected a named refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_document_with_neither_replica_is_named_as_such() {
        let noise = vec![0u8; 1130];
        match locate_preamble(&noise) {
            Err(SteganoError::DecodingFailed { method, reason }) => {
                assert_eq!(method, "frame");
                assert!(reason.contains("replica"), "reason was: {reason}");
            }
            other => panic!("expected a named failure, got {other:?}"),
        }
        assert!(!is_framed(&noise));
    }

    // ─── Resync markers ───

    #[test]
    fn every_marker_the_layout_places_is_found_by_a_scan() {
        let bits = build(1130, Flags::conceal(), SALT, b"markers everywhere").unwrap();
        let layout = Layout::for_positions(1130).unwrap();

        let hits = scan_resync(&bits);
        let offsets: Vec<usize> = hits.iter().map(|h| h.bit_offset).collect();

        for &expected in layout.markers() {
            assert!(
                offsets.contains(&expected),
                "marker at {expected} was not found, hits: {offsets:?}"
            );
        }
    }

    #[test]
    fn a_marker_reports_its_position_in_the_document() {
        let bits = build(1130, Flags::conceal(), SALT, b"where am i").unwrap();
        let hit = locate_resync(&bits).expect("the document carries markers");
        assert_eq!(hit.occurrence, 2, "the first marker clear of the head replica");
        assert_eq!(hit.document_position(1130), 282);
        assert_eq!(hit.bit_offset, 282);
    }

    #[test]
    fn a_window_of_one_spacing_plus_one_marker_always_locates_a_marker() {
        // The real guarantee. SPEC_CORE_V2 §3.2 also claims an excerpt of about
        // 160 characters suffices, which the k formula does not deliver: see
        // the carrier level test in format::mod for the measured window.
        let bits = build(2260, Flags::conceal(), SALT, b"resynchronise me").unwrap();
        let layout = Layout::for_positions(2260).unwrap();
        let window = layout.spacing() + MARKER_BITS;

        let first = *layout.markers().first().unwrap();
        let last = *layout.markers().last().unwrap();

        for start in (first..last.saturating_sub(window)).step_by(7) {
            let excerpt = &bits[start..start + window];
            assert!(
                locate_resync(excerpt).is_some(),
                "a {window} bit window at {start} found no marker"
            );
        }
    }

    #[test]
    fn a_scan_at_an_arbitrary_bit_offset_still_finds_a_marker() {
        // An excerpt does not begin on a byte boundary of the original.
        let bits = build(2260, Flags::conceal(), SALT, b"unaligned excerpt").unwrap();
        let layout = Layout::for_positions(2260).unwrap();
        let marker = layout.markers()[2];

        for shift in 0..8 {
            let start = marker - 5 - shift;
            let excerpt = &bits[start..start + MARKER_BITS + 16];
            let hit = locate_resync(excerpt).expect("marker inside the window");
            assert_eq!(hit.bit_offset, 5 + shift);
            assert_eq!(hit.occurrence as usize, marker / layout.spacing());
        }
    }

    #[test]
    fn the_head_replica_is_not_reported_as_a_marker() {
        let bits = build(1130, Flags::conceal(), SALT, b"not a marker").unwrap();
        let hits = scan_resync(&bits);
        assert!(
            !hits.iter().any(|h| h.bit_offset == 0),
            "the preamble opens with the same magic and must not be mistaken for a marker"
        );
    }

    #[test]
    fn a_text_with_no_frame_yields_no_markers() {
        let bits = vec![0u8; 2000];
        assert!(locate_resync(&bits).is_none());
    }
}
