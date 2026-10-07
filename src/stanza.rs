//! The `rypt` recipient stanza.
//!
//! ```text
//! -> rypt 3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47
//! <the rypt ciphertext of the file key>
//! ```

use age_core::format::Stanza;
use uuid::Uuid;

/// The stanza tag.
pub const TAG: &str = "rypt";

/// What a stanza in an age header is, as far as this plugin is concerned.
#[derive(Debug, PartialEq, Eq)]
pub enum Kind {
    /// Another type of stanza, to be ignored.
    Other,
    /// A `rypt` stanza that does not follow the format, which makes the
    /// whole header invalid.
    Malformed,
    /// A `rypt` stanza made under this key.
    Rypt(Uuid),
}

/// Builds the stanza for a file key encrypted under `key`.
pub fn build(key: Uuid, ciphertext: Vec<u8>) -> Stanza {
    Stanza {
        tag: TAG.to_owned(),
        args: vec![key.hyphenated().to_string()],
        body: ciphertext,
    }
}

/// Classifies a stanza. A `rypt` stanza must have exactly one argument, the
/// key UUID in canonical hyphenated lowercase form, and a body, since rypt
/// never returns an empty ciphertext.
pub fn parse(stanza: &Stanza) -> Kind {
    if stanza.tag != TAG {
        return Kind::Other;
    }
    match stanza.args.as_slice() {
        [arg] if !stanza.body.is_empty() => match Uuid::try_parse(arg) {
            Ok(key) if key.hyphenated().to_string() == *arg => Kind::Rypt(key),
            _ => Kind::Malformed,
        },
        _ => Kind::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use age_core::format::read;
    use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};

    use super::*;

    const KEY: Uuid = Uuid::from_u128(0x3f2a9c1e_7b4d_4e2a_9f10_6c8d5a2b1e47);

    fn stanza(tag: &str, args: &[&str]) -> Stanza {
        Stanza {
            tag: tag.to_owned(),
            args: args.iter().map(|s| s.to_string()).collect(),
            body: vec![1, 2, 3],
        }
    }

    #[test]
    fn build_encodes_the_key_in_canonical_form() {
        let s = build(KEY, b"ciphertext".to_vec());
        assert_eq!(s.tag, "rypt");
        assert_eq!(s.args, ["3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47"]);
        assert_eq!(s.body, b"ciphertext");
        assert_eq!(
            format!("-> {} {}", s.tag, s.args.join(" ")),
            "-> rypt 3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47"
        );
    }

    #[test]
    fn built_stanza_parses_back() {
        assert_eq!(parse(&build(KEY, vec![0; 40])), Kind::Rypt(KEY));
    }

    #[test]
    fn parses_from_the_age_header_wire_format() {
        // A body long enough to wrap: 134 base64 characters over three lines.
        let body: Vec<u8> = (0..=99).collect();
        let encoded = BASE64_STANDARD_NO_PAD.encode(&body);
        let lines: Vec<&str> = encoded
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 3);
        let wire = format!(
            "-> rypt 3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47\n{}\n",
            lines.join("\n")
        );
        let (rest, parsed) = read::age_stanza(wire.as_bytes()).unwrap();
        assert!(rest.is_empty());
        let parsed = Stanza::from(parsed);
        assert_eq!(parsed, build(KEY, body));
        assert_eq!(parse(&parsed), Kind::Rypt(KEY));
    }

    #[test]
    fn other_tags_are_other() {
        let key = KEY.hyphenated().to_string();
        assert_eq!(parse(&stanza("X25519", &[&key])), Kind::Other);
        // Stanza tags are case-sensitive.
        assert_eq!(parse(&stanza("RYPT", &[&key])), Kind::Other);
    }

    #[test]
    fn rypt_stanzas_off_the_format_are_malformed() {
        let key = KEY.hyphenated().to_string();
        assert_eq!(parse(&stanza("rypt", &[])), Kind::Malformed);
        assert_eq!(parse(&stanza("rypt", &[&key, "extra"])), Kind::Malformed);
        assert_eq!(parse(&stanza("rypt", &["not-a-uuid"])), Kind::Malformed);
        // Valid UUIDs, but not the canonical lowercase hyphenated form.
        assert_eq!(
            parse(&stanza("rypt", &[&key.to_uppercase()])),
            Kind::Malformed
        );
        assert_eq!(
            parse(&stanza("rypt", &[&KEY.simple().to_string()])),
            Kind::Malformed
        );
        assert_eq!(
            parse(&stanza("rypt", &[&KEY.braced().to_string()])),
            Kind::Malformed
        );
        assert_eq!(parse(&build(KEY, Vec::new())), Kind::Malformed);
    }
}
