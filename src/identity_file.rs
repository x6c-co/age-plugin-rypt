//! The identity file `new` writes and `recipient` reads.

use uuid::Uuid;

use crate::key;

/// Renders an identity file for `key`. `created` is an RFC 3339 timestamp.
pub fn render(key: Uuid, created: &str) -> String {
    format!(
        "# created: {created}\n# key: {}\n{}\n",
        key.hyphenated(),
        key::encode_identity(key)
    )
}

/// The Bech32 prefix of every rypt identity.
const IDENTITY_HRP: &str = "AGE-PLUGIN-RYPT-";

/// Returns the recipient for every rypt identity in an identity file.
///
/// Comments, blank lines and identities of other types are skipped. It is an
/// error for a rypt identity not to decode or to be one age would refuse, and
/// for the file to hold no rypt identity at all.
pub fn recipients(identity_file: &str) -> Result<Vec<String>, String> {
    let mut recipients = Vec::new();
    // Split as Go age does: one carriage return ends a line before its
    // newline, and also a last line without one. `str::lines` would leave the
    // latter and strip a second carriage return, as in "\r\r\n", age keeps.
    for (number, line) in identity_file.split_terminator('\n').enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        // Look at the line in place: other lines may be secret keys, and
        // copying them would leave copies behind.
        let trimmed = line.trim();
        if !is_rypt_identity(trimmed) {
            continue;
        }
        let error = |e: &dyn std::fmt::Display| format!("line {}: {e}", number + 1);
        if trimmed.len() != line.len() {
            return Err(error(
                &"identity has surrounding whitespace, which age does not accept",
            ));
        }
        let key = key::decode_identity(line).map_err(|e| error(&e))?;
        recipients.push(key::encode_recipient(key));
    }
    if recipients.is_empty() {
        return Err("no rypt identity found".to_owned());
    }
    Ok(recipients)
}

/// Whether a line is meant as a rypt identity: its Bech32 prefix, everything
/// before the last `1`, is that of a rypt identity, in either case.
fn is_rypt_identity(line: &str) -> bool {
    line.rsplit_once('1')
        .is_some_and(|(hrp, _)| hrp.eq_ignore_ascii_case(IDENTITY_HRP))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: Uuid = Uuid::from_u128(0x3f2a9c1e_7b4d_4e2a_9f10_6c8d5a2b1e47);
    const OTHER: Uuid = Uuid::from_u128(0x0f1e2d3c_4b5a_6978_8796_a5b4c3d2e1f0);

    #[test]
    fn render_writes_the_three_lines() {
        let file = render(KEY, "2026-09-29T20:32:00-05:00");
        let lines: Vec<&str> = file.lines().collect();
        assert_eq!(
            lines,
            [
                "# created: 2026-09-29T20:32:00-05:00",
                "# key: 3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47",
                key::encode_identity(KEY).as_str(),
            ]
        );
        assert!(file.ends_with('\n'));
    }

    #[test]
    fn recipients_reads_a_rendered_file() {
        let file = render(KEY, "2026-09-29T20:32:00Z");
        assert_eq!(recipients(&file), Ok(vec![key::encode_recipient(KEY)]));
    }

    #[test]
    fn recipients_reads_every_rypt_identity_and_skips_others() {
        let file = format!(
            "# a comment 1\n\n{}\r\nAGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\nAGE-PLUGIN-RYPT-1FOO-1QQQQQQQQQQ\n{}\r",
            key::encode_identity(KEY),
            key::encode_identity(OTHER),
        );
        assert_eq!(
            recipients(&file),
            Ok(vec![
                key::encode_recipient(KEY),
                key::encode_recipient(OTHER)
            ])
        );
    }

    #[test]
    fn recipients_rejects_a_corrupt_rypt_identity() {
        let mut identity = key::encode_identity(KEY);
        identity.pop();
        let file = format!("# key: {KEY}\n{identity}\n");
        assert_eq!(
            recipients(&file),
            Err("line 2: invalid Bech32 encoding".into())
        );
    }

    #[test]
    fn recipients_rejects_a_padded_rypt_identity() {
        for padded in [" {}", "{} ", "\t{}"] {
            let file = format!(
                "# key: {KEY}\n{}\n",
                padded.replace("{}", &key::encode_identity(KEY))
            );
            assert_eq!(
                recipients(&file),
                Err(
                    "line 2: identity has surrounding whitespace, which age does not accept".into()
                ),
                "{padded:?}"
            );
        }
    }

    #[test]
    fn recipients_strips_only_one_carriage_return() {
        let identity = key::encode_identity(KEY);
        assert_eq!(
            recipients(&format!("{identity}\r")),
            Ok(vec![key::encode_recipient(KEY)])
        );
        assert_eq!(
            recipients(&format!("# key\n{identity}\r\r\n")),
            Err("line 2: identity has surrounding whitespace, which age does not accept".into())
        );
    }

    #[test]
    fn recipients_rejects_a_lowercase_rypt_identity() {
        let file = format!(
            "# key: {KEY}\n{}\n",
            key::encode_identity(KEY).to_lowercase()
        );
        assert_eq!(
            recipients(&file),
            Err("line 2: identity must be uppercase".into())
        );
    }

    #[test]
    fn recipients_requires_a_rypt_identity() {
        assert_eq!(recipients(""), Err("no rypt identity found".into()));
        assert_eq!(
            recipients("# only a comment\nAGE-SECRET-KEY-1QQQQ\n"),
            Err("no rypt identity found".into())
        );
    }
}
