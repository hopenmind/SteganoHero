//! The envelope, SPEC_CORE_V2 §4.
//!
//! ```text
//! { v: 2, chain: [ {id, state}, ... ], payload: <bytes> }
//! ```
//!
//! Serialised with postcard. The preamble already carries the version, so a
//! self-describing encoding would buy nothing and cost bytes on a channel
//! measured in substitutable positions.
//!
//! Carriers are deliberately absent from `chain`. They transport the envelope;
//! they are not steps inside it. `chain` holds the reversible transforms the
//! decoder must replay in strict reverse order, and `state` holds what
//! `revert` needs and the caller cannot recompute: nonces, per-step parameters.
//! The salt is not here either. It lives in the preamble, because it is needed
//! before the envelope can be read at all.

use serde::{Deserialize, Serialize};

use crate::error::{Result, SteganoError};

/// The envelope version this build writes and reads.
pub const ENVELOPE_VERSION: u8 = 2;

/// One replayable step of the transform chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainStep {
    /// Transform identifier, matching the transform's own `id()`.
    pub id: String,
    /// Everything `revert` needs that the caller cannot recompute.
    pub state: Vec<u8>,
}

impl ChainStep {
    pub fn new(id: impl Into<String>, state: Vec<u8>) -> Self {
        Self {
            id: id.into(),
            state,
        }
    }
}

/// The postcard-serialised payload container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Format version, always `ENVELOPE_VERSION` on write.
    pub v: u8,
    /// Transform steps, in the order they were applied.
    pub chain: Vec<ChainStep>,
    /// The bytes the last transform produced.
    pub payload: Vec<u8>,
}

impl Envelope {
    /// Build a v2 envelope.
    pub fn new(chain: Vec<ChainStep>, payload: Vec<u8>) -> Self {
        Self {
            v: ENVELOPE_VERSION,
            chain,
            payload,
        }
    }

    /// Serialise with postcard.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|e| SteganoError::EncodingFailed {
            method: "envelope".into(),
            reason: format!("postcard serialisation failed: {e}"),
        })
    }

    /// Parse a postcard buffer, then check the version.
    ///
    /// A version this build does not write is refused by name rather than
    /// interpreted optimistically.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let envelope: Self =
            postcard::from_bytes(bytes).map_err(|e| SteganoError::DecodingFailed {
                method: "envelope".into(),
                reason: format!("postcard deserialisation failed: {e}"),
            })?;

        if envelope.v != ENVELOPE_VERSION {
            return Err(SteganoError::DecodingFailed {
                method: "envelope".into(),
                reason: format!(
                    "unsupported envelope version {}, this build reads {ENVELOPE_VERSION}",
                    envelope.v
                ),
            });
        }

        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_chain_round_trips() {
        let envelope = Envelope::new(Vec::new(), b"raw secret".to_vec());
        let parsed = Envelope::parse(&envelope.to_bytes().unwrap()).unwrap();
        assert_eq!(parsed, envelope);
        assert_eq!(parsed.v, 2);
    }

    #[test]
    fn a_multi_step_chain_round_trips_in_order() {
        let envelope = Envelope::new(
            vec![
                ChainStep::new("deflate", vec![]),
                ChainStep::new("chacha20_poly1305", vec![1, 2, 3, 4, 5, 6, 7, 8]),
            ],
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        );

        let parsed = Envelope::parse(&envelope.to_bytes().unwrap()).unwrap();
        assert_eq!(parsed, envelope);
        assert_eq!(
            parsed.chain.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            vec!["deflate", "chacha20_poly1305"],
            "chain order is the encode order, the decoder reverses it"
        );
    }

    #[test]
    fn the_envelope_costs_few_bytes_over_its_payload() {
        // The channel is measured in substitutable positions, so overhead is
        // not cosmetic. An empty chain must stay in single digits.
        let payload = vec![0u8; 64];
        let encoded = Envelope::new(Vec::new(), payload.clone())
            .to_bytes()
            .unwrap();
        assert!(
            encoded.len() < payload.len() + 8,
            "envelope overhead was {} bytes",
            encoded.len() - payload.len()
        );
    }

    #[test]
    fn an_empty_payload_round_trips() {
        let envelope = Envelope::new(vec![ChainStep::new("xor", vec![9])], Vec::new());
        assert_eq!(Envelope::parse(&envelope.to_bytes().unwrap()).unwrap(), envelope);
    }

    #[test]
    fn a_foreign_version_is_named_not_reinterpreted() {
        let mut envelope = Envelope::new(Vec::new(), vec![1, 2, 3]);
        envelope.v = 7;
        let bytes = postcard::to_allocvec(&envelope).unwrap();

        match Envelope::parse(&bytes) {
            Err(SteganoError::DecodingFailed { method, reason }) => {
                assert_eq!(method, "envelope");
                assert!(reason.contains("version"), "reason was: {reason}");
            }
            other => panic!("expected a version rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_buffer_is_refused_rather_than_half_read() {
        let bytes = Envelope::new(
            vec![ChainStep::new("aes256_gcm", vec![0; 12])],
            vec![0xAB; 40],
        )
        .to_bytes()
        .unwrap();

        let result = Envelope::parse(&bytes[..bytes.len() / 2]);
        assert!(
            matches!(result, Err(SteganoError::DecodingFailed { .. })),
            "a half envelope must raise, not return a partial chain"
        );
    }

    #[test]
    fn random_bytes_do_not_parse_as_an_envelope() {
        // Not a proof, a guard: the frame must not hand a v1 document to the
        // envelope parser and receive a plausible looking result.
        let noise: Vec<u8> = (0u8..=255).collect();
        let result = Envelope::parse(&noise);
        assert!(result.is_err(), "arbitrary bytes parsed as an envelope");
    }
}
