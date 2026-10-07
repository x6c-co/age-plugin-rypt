//! Bech32 encodings of a rypt key id as an age recipient and an age identity.
//!
//! Both strings carry the same payload, the 16 raw bytes of the key's UUID.
//! Neither is secret: the identity only says which rypt key to ask for, and
//! the rypt API token is what authorizes the request.

use std::fmt;

use age_core::primitives::{bech32_decode, bech32_encode};
use bech32::Hrp;
use uuid::Uuid;

/// The plugin name. age maps `age1rypt` and `AGE-PLUGIN-RYPT-` to the binary
/// `age-plugin-rypt`.
pub const PLUGIN_NAME: &str = "rypt";

const RECIPIENT_HRP: &str = "age1rypt";
const IDENTITY_HRP: &str = "AGE-PLUGIN-RYPT-";

/// Why a recipient, identity or raw payload was not a rypt key id.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    /// Not valid Bech32.
    Encoding,
    /// Valid Bech32, but for another recipient or identity type.
    Hrp,
    /// The payload is not exactly 16 bytes.
    Length(usize),
    /// An identity in lowercase, which age clients do not accept.
    Lowercase,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Encoding => f.write_str("invalid Bech32 encoding"),
            KeyError::Hrp => f.write_str("not a rypt recipient or identity"),
            KeyError::Length(n) => write!(f, "key id must be 16 bytes, got {n}"),
            KeyError::Lowercase => f.write_str("identity must be uppercase"),
        }
    }
}

/// Encodes a key id as an `age1rypt1...` recipient.
pub fn encode_recipient(key: Uuid) -> String {
    bech32_encode(Hrp::parse_unchecked(RECIPIENT_HRP), key.as_bytes())
}

/// Encodes a key id as an `AGE-PLUGIN-RYPT-1...` identity.
pub fn encode_identity(key: Uuid) -> String {
    bech32_encode(Hrp::parse_unchecked(IDENTITY_HRP), key.as_bytes()).to_uppercase()
}

/// Decodes an `age1rypt1...` recipient to its key id.
#[cfg(test)]
pub fn decode_recipient(s: &str) -> Result<Uuid, KeyError> {
    decode(s, RECIPIENT_HRP)
}

/// Decodes an `AGE-PLUGIN-RYPT-1...` identity to its key id.
pub fn decode_identity(s: &str) -> Result<Uuid, KeyError> {
    // Bech32 itself also allows all-lowercase, but age clients and the
    // age-plugin crate only recognize plugin identities in uppercase.
    if s.bytes().any(|b| b.is_ascii_lowercase()) {
        return Err(KeyError::Lowercase);
    }
    decode(s, IDENTITY_HRP)
}

/// Reads a key id from a decoded Bech32 payload.
pub fn key_from_payload(bytes: &[u8]) -> Result<Uuid, KeyError> {
    Uuid::from_slice(bytes).map_err(|_| KeyError::Length(bytes.len()))
}

fn decode(s: &str, expected_hrp: &str) -> Result<Uuid, KeyError> {
    bech32_decode(
        s,
        |_| KeyError::Encoding,
        |hrp| {
            if hrp.as_str().eq_ignore_ascii_case(expected_hrp) {
                Ok(())
            } else {
                Err(KeyError::Hrp)
            }
        },
        |_, bytes| key_from_payload(&bytes.collect::<Vec<u8>>()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: Uuid = Uuid::from_u128(0x3f2a9c1e_7b4d_4e2a_9f10_6c8d5a2b1e47);

    fn encode_raw(hrp: &str, payload: &[u8]) -> String {
        bech32_encode(Hrp::parse_unchecked(hrp), payload)
    }

    #[test]
    fn recipient_round_trips() {
        let recipient = encode_recipient(KEY);
        assert!(recipient.starts_with("age1rypt1"), "{recipient}");
        assert_eq!(recipient, recipient.to_lowercase());
        assert_eq!(decode_recipient(&recipient), Ok(KEY));
    }

    #[test]
    fn identity_round_trips() {
        let identity = encode_identity(KEY);
        assert!(identity.starts_with("AGE-PLUGIN-RYPT-1"), "{identity}");
        assert_eq!(identity, identity.to_uppercase());
        assert_eq!(decode_identity(&identity), Ok(KEY));
    }

    #[test]
    fn identity_must_be_uppercase() {
        let identity = encode_identity(KEY);
        assert_eq!(
            decode_identity(&identity.to_lowercase()),
            Err(KeyError::Lowercase)
        );
        // Mixed case is not even valid Bech32.
        let mixed = identity.replacen("AGE", "age", 1);
        assert!(decode_identity(&mixed).is_err());
    }

    #[test]
    fn recipient_and_identity_carry_the_same_payload() {
        let r = encode_recipient(KEY);
        let i = encode_identity(KEY).to_lowercase();
        let (_, r_data) = r.split_once("age1rypt1").unwrap();
        let (_, i_data) = i.split_once("age-plugin-rypt-1").unwrap();
        // Same bytes, different checksum: only the six checksum characters differ.
        assert_eq!(r_data[..r_data.len() - 6], i_data[..i_data.len() - 6]);
    }

    #[test]
    fn wrong_length_payloads_are_rejected() {
        for len in [0, 1, 15, 17, 32] {
            let payload = vec![0x42; len];
            assert_eq!(
                decode_recipient(&encode_raw(RECIPIENT_HRP, &payload)),
                Err(KeyError::Length(len))
            );
            assert_eq!(
                decode_identity(&encode_raw(IDENTITY_HRP, &payload).to_uppercase()),
                Err(KeyError::Length(len))
            );
            assert_eq!(key_from_payload(&payload), Err(KeyError::Length(len)));
        }
    }

    #[test]
    fn other_types_are_rejected() {
        let recipient = encode_recipient(KEY);
        let identity = encode_identity(KEY);
        assert_eq!(
            decode_identity(&recipient.to_uppercase()),
            Err(KeyError::Hrp)
        );
        assert_eq!(decode_recipient(&identity), Err(KeyError::Hrp));
        let other = encode_raw("age1yubikey", KEY.as_bytes());
        assert_eq!(decode_recipient(&other), Err(KeyError::Hrp));
    }

    #[test]
    fn corrupt_strings_are_rejected() {
        let mut recipient = encode_recipient(KEY);
        let last = recipient.pop().unwrap();
        recipient.push(if last == 'q' { 'p' } else { 'q' });
        assert_eq!(decode_recipient(&recipient), Err(KeyError::Encoding));
        assert_eq!(decode_recipient("age1rypt"), Err(KeyError::Encoding));
        assert_eq!(decode_recipient(""), Err(KeyError::Encoding));
    }
}
