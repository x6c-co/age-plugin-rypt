//! The plugin protocol end to end against a mock rypt API.
//!
//! Every run also checks, in `common`, that the plugin wrote nothing to
//! stderr and leaked no token, file key, ciphertext or response body.

mod common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use common::*;
use uuid::Uuid;

const FILE_KEY: [u8; 16] = *b"0123456789abcdef";
const OTHER_FILE_KEY: [u8; 16] = *b"fedcba9876543210";
const KEY_A: Uuid = Uuid::from_u128(0x3f2a9c1e_7b4d_4e2a_9f10_6c8d5a2b1e47);
const KEY_B: Uuid = Uuid::from_u128(0x0f1e2d3c_4b5a_6978_8796_a5b4c3d2e1f0);

const STATUS_CASES: &[(u16, &str)] = &[
    (201, "rypt: 201"),
    (204, "rypt: 204"),
    (301, "rypt: 301"),
    (302, "rypt: 302"),
    (307, "rypt: 307"),
    (308, "rypt: 308"),
    (400, "rypt: 400"),
    (401, "rypt: unauthorized"),
    (402, "rypt: 402"),
    (403, "rypt: unauthorized"),
    (404, "rypt: key not found"),
    (409, "rypt: 409"),
    (429, "rypt: rate limit or op cap reached"),
    (500, "rypt: 500"),
    (503, "rypt: 503"),
];

const INVALID_RESPONSE_KEYS: [Uuid; 4] = [
    NOT_JSON_KEY,
    MISSING_FIELD_KEY,
    BAD_BASE64_KEY,
    OVERSIZED_KEY,
];

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn error(args: &[&str], message: &str) -> (Vec<String>, String) {
    (strs(args), message.to_owned())
}

/// Wraps `FILE_KEY` to `key` and returns the file's stanzas.
fn wrapped_to(env: &Env, key: Uuid) -> Vec<Stanza> {
    let outcome = wrap(env, &[recipient(key)], &[], &[FILE_KEY]);
    assert_eq!(outcome.errors(), []);
    outcome.stanzas(0)
}

/// A key in uppercase: a valid UUID, but not the stanza's canonical form.
fn uppercase(key: Uuid) -> String {
    key.hyphenated().to_string().to_uppercase()
}

/// A port nothing listens on.
fn closed_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn wraps_and_unwraps_a_file_key() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);

    let wrapped = wrap(&env, &[recipient(KEY_A)], &[], &[FILE_KEY]);
    assert_eq!(wrapped.errors(), []);
    let stanzas = wrapped.stanzas(0);
    assert_eq!(stanzas.len(), 1);
    assert_eq!(stanzas[0].tag, "rypt");
    assert_eq!(stanzas[0].args, ["3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47"]);
    // The body is the raw ciphertext rypt returned, nothing more.
    assert_eq!(stanzas[0].body, toy_seal(KEY_A, &FILE_KEY));

    let unwrapped = unwrap(&env, &[identity(KEY_A)], &[stanzas]);
    assert_eq!(unwrapped.errors(), []);
    assert_eq!(
        unwrapped.file_keys(),
        HashMap::from([(0, FILE_KEY.to_vec())])
    );
    assert_eq!((mock.encrypt_calls(), mock.decrypt_calls()), (1, 1));
}

#[test]
fn wraps_to_identities_too() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);

    let wrapped = wrap(&env, &[], &[identity(KEY_B)], &[FILE_KEY]);
    assert_eq!(wrapped.errors(), []);
    let stanzas = wrapped.stanzas(0);
    assert_eq!(stanzas.len(), 1);
    assert_eq!(stanzas[0].args, [KEY_B.to_string()]);

    let unwrapped = unwrap(&env, &[identity(KEY_B)], &[stanzas]);
    assert_eq!(
        unwrapped.file_keys(),
        HashMap::from([(0, FILE_KEY.to_vec())])
    );
}

#[test]
fn wraps_every_file_key_to_every_recipient_and_identity() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);

    let wrapped = wrap(
        &env,
        &[recipient(KEY_A)],
        &[identity(KEY_B)],
        &[FILE_KEY, OTHER_FILE_KEY],
    );
    assert_eq!(wrapped.errors(), []);
    assert_eq!(mock.encrypt_calls(), 4);
    let files = [wrapped.stanzas(0), wrapped.stanzas(1)];
    for stanzas in &files {
        let keys: Vec<&str> = stanzas.iter().map(|s| s.args[0].as_str()).collect();
        assert_eq!(keys, [KEY_A.to_string(), KEY_B.to_string()]);
    }

    // Either key alone unwraps both files.
    for key in [KEY_A, KEY_B] {
        let unwrapped = unwrap(&env, &[identity(key)], &files);
        assert_eq!(unwrapped.errors(), []);
        assert_eq!(
            unwrapped.file_keys(),
            HashMap::from([(0, FILE_KEY.to_vec()), (1, OTHER_FILE_KEY.to_vec())])
        );
    }
}

#[test]
fn ignores_stanzas_for_other_keys_and_types() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);
    let mut file = vec![
        Stanza::new("X25519", &["abc"], &[1; 32]),
        // Stanza tags are case-sensitive: this is not a rypt stanza.
        Stanza::new("RYPT", &[&uppercase(KEY_A)], &[1; 8]),
    ];
    file.extend(wrapped_to(&env, KEY_B));
    let calls_before = mock.decrypt_calls();

    let unwrapped = unwrap(&env, &[identity(KEY_A)], &[file]);
    assert_eq!(unwrapped.commands, []);
    assert_eq!(mock.decrypt_calls(), calls_before);
}

#[test]
fn a_malformed_rypt_stanza_is_an_error_and_blocks_the_file() {
    let mock = MockRypt::start();
    let good = wrapped_to(&Env::for_mock(&mock), KEY_A);
    // No token: a malformed header is reported before anything needs one.
    let env = Env::for_mock(&mock).without_token();
    let key = KEY_A.hyphenated().to_string();
    let malformed = [
        Stanza::new("rypt", &[], &[1; 8]),
        Stanza::new("rypt", &[&key, "extra"], &[1; 8]),
        Stanza::new("rypt", &["not-a-uuid"], &[1; 8]),
        Stanza::new("rypt", &[&uppercase(KEY_A)], &[1; 8]),
        Stanza::new("rypt", &[&KEY_A.simple().to_string()], &[1; 8]),
        Stanza::new("rypt", &[&KEY_A.braced().to_string()], &[1; 8]),
        Stanza::new("rypt", &[&key], &[]),
        // Malformed even though it names a key that is not loaded.
        Stanza::new("rypt", &[&uppercase(KEY_B)], &[1; 8]),
    ];
    for bad in malformed {
        // A valid stanza for the loaded key, before and after the bad one.
        let file = vec![
            good[0].clone(),
            Stanza::new("X25519", &["abc"], &[1; 32]),
            bad.clone(),
            good[0].clone(),
        ];
        let outcome = unwrap(&env, &[identity(KEY_A)], &[file]);
        assert_eq!(outcome.file_keys(), HashMap::new(), "{bad:?}");
        assert_eq!(
            outcome.errors(),
            [error(&["stanza", "0", "2"], "rypt: invalid stanza")],
            "{bad:?}"
        );
    }
    assert_eq!(mock.decrypt_calls(), 0);
}

#[test]
fn every_malformed_rypt_stanza_is_reported_for_its_own_file() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);
    let files = [
        vec![
            Stanza::new("rypt", &[], &[1; 8]),
            Stanza::new("X25519", &["abc"], &[1; 32]),
            Stanza::new("rypt", &["x", "y"], &[1; 8]),
        ],
        wrapped_to(&env, KEY_A),
    ];
    let outcome = unwrap(&env, &[identity(KEY_A)], &files);
    // The second file is unaffected.
    assert_eq!(outcome.file_keys(), HashMap::from([(1, FILE_KEY.to_vec())]));
    assert_eq!(
        outcome.errors(),
        [
            error(&["stanza", "0", "0"], "rypt: invalid stanza"),
            error(&["stanza", "0", "2"], "rypt: invalid stanza"),
        ]
    );
}

#[test]
fn a_failed_stanza_does_not_stop_the_next_one() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);
    let failing = status_key(500);

    let mut file = vec![Stanza::new("rypt", &[&failing.to_string()], &[9; 40])];
    file.extend(wrapped_to(&env, KEY_A));

    let unwrapped = unwrap(&env, &[identity(failing), identity(KEY_A)], &[file]);
    assert_eq!(unwrapped.errors(), []);
    assert_eq!(
        unwrapped.file_keys(),
        HashMap::from([(0, FILE_KEY.to_vec())])
    );
    assert_eq!(mock.decrypt_calls(), 2);
}

#[test]
fn stops_at_the_first_stanza_that_unwraps() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);
    let mut file = wrapped_to(&env, KEY_A);
    file.extend(wrapped_to(&env, KEY_B));

    let unwrapped = unwrap(&env, &[identity(KEY_A), identity(KEY_B)], &[file]);
    assert_eq!(
        unwrapped.file_keys(),
        HashMap::from([(0, FILE_KEY.to_vec())])
    );
    assert_eq!(mock.decrypt_calls(), 1);
}

#[test]
fn failed_stanzas_are_reported_as_stanza_errors() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);
    let missing = status_key(404);
    let limited = status_key(429);

    // Two files. Stanza indexes count every stanza in the file, including
    // ones of other types.
    let files = [
        vec![
            Stanza::new("X25519", &["abc"], &[1; 32]),
            Stanza::new("rypt", &[&missing.to_string()], &[9; 40]),
        ],
        vec![
            Stanza::new("rypt", &[&limited.to_string()], &[9; 40]),
            Stanza::new("rypt", &[&missing.to_string()], &[9; 40]),
        ],
    ];

    let unwrapped = unwrap(&env, &[identity(missing), identity(limited)], &files);
    assert_eq!(unwrapped.file_keys(), HashMap::new());
    // Files are reported in no particular order.
    let mut errors = unwrapped.errors();
    errors.sort();
    assert_eq!(
        errors,
        [
            error(&["stanza", "0", "1"], "rypt: key not found"),
            error(&["stanza", "1", "0"], "rypt: rate limit or op cap reached"),
            error(&["stanza", "1", "1"], "rypt: key not found"),
        ]
    );
}

#[test]
fn a_stanza_error_in_one_file_does_not_affect_another() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);
    let failing = status_key(503);
    let files = [
        vec![Stanza::new("rypt", &[&failing.to_string()], &[9; 40])],
        wrapped_to(&env, KEY_A),
    ];

    let unwrapped = unwrap(&env, &[identity(failing), identity(KEY_A)], &files);
    assert_eq!(
        unwrapped.file_keys(),
        HashMap::from([(1, FILE_KEY.to_vec())])
    );
    assert_eq!(
        unwrapped.errors(),
        [error(&["stanza", "0", "0"], "rypt: 503")]
    );
}

#[test]
fn maps_http_errors_when_wrapping() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);
    for &(status, message) in STATUS_CASES {
        let key = status_key(status);

        let outcome = wrap(&env, &[recipient(key)], &[], &[FILE_KEY]);
        assert_eq!(outcome.stanzas(0), []);
        assert_eq!(
            outcome.errors(),
            [error(&["recipient", "0"], message)],
            "status {status}"
        );

        // A failing identity is named by its own index.
        let outcome = wrap(
            &env,
            &[recipient(KEY_A)],
            &[identity(KEY_B), identity(key)],
            &[FILE_KEY],
        );
        assert_eq!(outcome.stanzas(0), []);
        assert_eq!(
            outcome.errors(),
            [error(&["identity", "1"], message)],
            "status {status}"
        );
    }
}

#[test]
fn stops_wrapping_at_the_first_failure() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);

    let outcome = wrap(
        &env,
        &[recipient(status_key(404)), recipient(KEY_A)],
        &[],
        &[FILE_KEY],
    );
    assert_eq!(
        outcome.errors(),
        [error(&["recipient", "0"], "rypt: key not found")]
    );
    assert_eq!(mock.encrypt_calls(), 1);

    let outcome = wrap(
        &env,
        &[recipient(status_key(404)), recipient(status_key(500))],
        &[],
        &[FILE_KEY, OTHER_FILE_KEY],
    );
    assert_eq!(
        outcome.errors(),
        [error(&["recipient", "0"], "rypt: key not found")]
    );
    assert_eq!(mock.encrypt_calls(), 2);
}

#[test]
fn maps_http_errors_when_unwrapping() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);
    for &(status, message) in STATUS_CASES {
        let key = status_key(status);
        let file = vec![Stanza::new("rypt", &[&key.to_string()], &[9; 40])];

        let outcome = unwrap(&env, &[identity(key)], &[file]);
        assert_eq!(outcome.file_keys(), HashMap::new());
        assert_eq!(
            outcome.errors(),
            [error(&["stanza", "0", "0"], message)],
            "status {status}"
        );
    }
}

#[test]
fn reports_an_unusable_answer_as_an_invalid_response() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);
    for key in INVALID_RESPONSE_KEYS
        .into_iter()
        .chain([EMPTY_CIPHERTEXT_KEY])
    {
        let outcome = wrap(&env, &[recipient(key)], &[], &[FILE_KEY]);
        assert_eq!(
            outcome.errors(),
            [error(&["recipient", "0"], "rypt: invalid response")],
            "{key}"
        );
    }
    for key in INVALID_RESPONSE_KEYS {
        let file = vec![Stanza::new(
            "rypt",
            &[&key.to_string()],
            &toy_seal(key, &FILE_KEY),
        )];
        let outcome = unwrap(&env, &[identity(key)], &[file]);
        assert_eq!(outcome.file_keys(), HashMap::new());
        assert_eq!(
            outcome.errors(),
            [error(&["stanza", "0", "0"], "rypt: invalid response")],
            "{key}"
        );
    }
}

#[test]
fn a_wrong_token_is_unauthorized() {
    let mock = MockRypt::start();
    let good = Env::for_mock(&mock);
    let bad = good
        .clone()
        .with_token("ry_Wrong000_abcdefghijklmnopqrstuvwxyz012345");

    let outcome = wrap(&bad, &[recipient(KEY_A)], &[], &[FILE_KEY]);
    assert_eq!(
        outcome.errors(),
        [error(&["recipient", "0"], "rypt: unauthorized")]
    );

    let file = wrapped_to(&good, KEY_A);
    let outcome = unwrap(&bad, &[identity(KEY_A)], &[file]);
    assert_eq!(
        outcome.errors(),
        [error(&["stanza", "0", "0"], "rypt: unauthorized")]
    );
}

#[test]
fn a_missing_empty_or_blank_token_fails_wrapping() {
    let mock = MockRypt::start();
    for env in [
        Env::for_mock(&mock).without_token(),
        Env::for_mock(&mock).with_token(""),
        Env::for_mock(&mock).with_token(" \n"),
    ] {
        let outcome = wrap(&env, &[recipient(KEY_A)], &[], &[FILE_KEY]);
        assert_eq!(outcome.stanzas(0), []);
        assert_eq!(
            outcome.errors(),
            [error(&["internal"], "RYPT_TOKEN is not set")]
        );
    }
    assert_eq!(mock.encrypt_calls(), 0);
}

#[test]
fn the_token_is_trimmed_and_checked() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);

    // A token read from a file, newline and all.
    let trimmed = env.clone().with_token(&format!("{TOKEN}\n"));
    assert_eq!(
        wrap(&trimmed, &[recipient(KEY_A)], &[], &[FILE_KEY]).errors(),
        []
    );

    let spaced = env
        .clone()
        .with_token("ry_Test1234 abcdefghijklmnopqrstuvwxyz012345");
    assert_eq!(
        wrap(&spaced, &[recipient(KEY_A)], &[], &[FILE_KEY]).errors(),
        [error(
            &["internal"],
            "RYPT_TOKEN contains invalid characters"
        )]
    );

    #[cfg(unix)]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let not_unicode = env.with_var("RYPT_TOKEN", OsStr::from_bytes(b"ry_\xff_abc"));
        assert_eq!(
            wrap(&not_unicode, &[recipient(KEY_A)], &[], &[FILE_KEY]).errors(),
            [error(&["internal"], "RYPT_TOKEN is not valid UTF-8")]
        );
    }
    assert_eq!(mock.encrypt_calls(), 1);
}

#[test]
fn a_missing_token_fails_unwrapping_only_when_a_stanza_matches() {
    let mock = MockRypt::start();
    let file = wrapped_to(&Env::for_mock(&mock), KEY_A);
    let env = Env::for_mock(&mock).without_token();

    let outcome = unwrap(&env, &[identity(KEY_A)], std::slice::from_ref(&file));
    assert_eq!(outcome.file_keys(), HashMap::new());
    assert_eq!(
        outcome.errors(),
        [error(&["internal"], "RYPT_TOKEN is not set")]
    );

    // Once per file, however many of its stanzas match.
    let doubled: Vec<Stanza> = file.iter().chain(&file).cloned().collect();
    let outcome = unwrap(&env, &[identity(KEY_A)], &[doubled.clone(), doubled]);
    assert_eq!(
        outcome.errors(),
        [
            error(&["internal"], "RYPT_TOKEN is not set"),
            error(&["internal"], "RYPT_TOKEN is not set"),
        ]
    );

    // No stanza for a loaded key: nothing to do, so no token needed.
    let outcome = unwrap(&env, &[identity(KEY_B)], &[file]);
    assert_eq!(outcome.commands, []);
    assert_eq!(mock.decrypt_calls(), 0);
}

#[test]
fn rejects_a_decrypted_file_key_that_is_not_16_bytes() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);
    let file = wrapped_to(&env, SHORT_KEY);

    let outcome = unwrap(&env, &[identity(SHORT_KEY)], &[file]);
    assert_eq!(outcome.file_keys(), HashMap::new());
    assert_eq!(
        outcome.errors(),
        [error(
            &["stanza", "0", "0"],
            "rypt: decrypted file key is not 16 bytes"
        )]
    );
}

#[test]
fn a_ciphertext_for_another_key_is_refused_by_rypt() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);
    let mut stanza = wrapped_to(&env, KEY_B).remove(0);
    stanza.args = vec![KEY_A.to_string()];

    let outcome = unwrap(&env, &[identity(KEY_A)], &[vec![stanza]]);
    assert_eq!(
        outcome.errors(),
        [error(&["stanza", "0", "0"], "rypt: 400")]
    );
}

#[test]
fn rejects_recipients_and_identities_that_are_not_16_bytes() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);

    let outcome = wrap(
        &env,
        &[
            recipient(KEY_A),
            raw_recipient(&[7; 15]),
            raw_recipient(&[7; 17]),
        ],
        &[identity(KEY_B), raw_identity(&[7; 15]), raw_identity(&[])],
        &[FILE_KEY],
    );
    assert_eq!(outcome.stanzas(0), []);
    assert_eq!(
        outcome.errors(),
        [
            error(&["recipient", "1"], "key id must be 16 bytes, got 15"),
            error(&["recipient", "2"], "key id must be 16 bytes, got 17"),
            error(&["identity", "1"], "key id must be 16 bytes, got 15"),
            // What `age -j rypt` sends.
            error(
                &["identity", "2"],
                "rypt has no default identity: use -i with a file from age-plugin-rypt new"
            ),
        ]
    );
    assert_eq!(mock.encrypt_calls(), 0);

    let file = wrapped_to(&env, KEY_A);
    let outcome = unwrap(
        &env,
        &[identity(KEY_A), raw_identity(&[7; 17]), raw_identity(&[])],
        &[file],
    );
    assert_eq!(outcome.file_keys(), HashMap::new());
    assert_eq!(
        outcome.errors(),
        [
            error(&["identity", "1"], "key id must be 16 bytes, got 17"),
            error(
                &["identity", "2"],
                "rypt has no default identity: use -i with a file from age-plugin-rypt new"
            ),
        ]
    );
    assert_eq!(mock.decrypt_calls(), 0);
}

#[test]
fn reports_an_unreachable_api() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock).with_api_url(&format!("http://127.0.0.1:{}", closed_port()));
    let outcome = wrap(&env, &[recipient(KEY_A)], &[], &[FILE_KEY]);
    assert_eq!(
        outcome.errors(),
        [error(&["recipient", "0"], "rypt: connection failed")]
    );
}

/// A server that answers anything with a plain-HTTP error, as a web server
/// does when it is spoken TLS to.
fn plain_http_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let _ = stream.read(&mut [0; 1024]);
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
        }
    });
    port
}

#[test]
fn speaks_tls_to_an_https_url() {
    // The server speaks plain HTTP, so the TLS handshake fails.
    let mock = MockRypt::start();
    let env =
        Env::for_mock(&mock).with_api_url(&format!("https://127.0.0.1:{}", plain_http_server()));
    let outcome = wrap(&env, &[recipient(KEY_A)], &[], &[FILE_KEY]);
    assert_eq!(
        outcome.errors(),
        [error(&["recipient", "0"], "rypt: TLS error")]
    );
}

#[test]
fn refuses_an_api_url_that_is_not_https_beyond_this_machine() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);
    let cases = [
        ("http://rypt.invalid", "RYPT_API_URL must use https"),
        ("http://10.0.0.1:8080", "RYPT_API_URL must use https"),
        (
            "https://rypt.invalid/?key=1",
            "RYPT_API_URL is not a valid URL",
        ),
        ("rypt.invalid", "RYPT_API_URL is not a valid URL"),
    ];
    for (url, message) in cases {
        let outcome = wrap(
            &env.clone().with_api_url(url),
            &[recipient(KEY_A)],
            &[],
            &[FILE_KEY],
        );
        assert_eq!(outcome.errors(), [error(&["internal"], message)], "{url}");
    }

    // Decrypting reports it once a stanza needs the API.
    let file = wrapped_to(&env, KEY_A);
    let outcome = unwrap(
        &env.clone().with_api_url("http://rypt.invalid"),
        &[identity(KEY_A)],
        &[file],
    );
    assert_eq!(
        outcome.errors(),
        [error(&["internal"], "RYPT_API_URL must use https")]
    );

    #[cfg(unix)]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let not_unicode = env.with_var("RYPT_API_URL", OsStr::from_bytes(b"https://\xff"));
        assert_eq!(
            wrap(&not_unicode, &[recipient(KEY_A)], &[], &[FILE_KEY]).errors(),
            [error(&["internal"], "RYPT_API_URL is not a valid URL")]
        );
    }
}

#[test]
fn a_server_on_this_machine_bypasses_proxies() {
    let mock = MockRypt::start();
    let dead_proxy = format!("http://127.0.0.1:{}", closed_port());
    let mut env = Env::for_mock(&mock);
    for name in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
        env = env.with_var(name, &dead_proxy);
    }
    assert_eq!(
        wrap(&env, &[recipient(KEY_A)], &[], &[FILE_KEY]).errors(),
        []
    );
}

#[test]
fn refuses_a_socks_proxy_it_would_bypass() {
    let mock = MockRypt::start();
    for (name, proxy) in [
        ("ALL_PROXY", "socks5://127.0.0.1:9"),
        ("all_proxy", "socks5h://127.0.0.1:9"),
        ("HTTPS_PROXY", "socks4://127.0.0.1:9"),
    ] {
        let env = Env::for_mock(&mock)
            .with_api_url("https://rypt.invalid")
            .with_var(name, proxy);
        assert_eq!(
            wrap(&env, &[recipient(KEY_A)], &[], &[FILE_KEY]).errors(),
            [error(&["internal"], "SOCKS proxies are not supported")],
            "{name}={proxy}"
        );
    }
}

#[test]
fn rejects_an_untrusted_certificate() {
    let env = Env::default()
        .with_token(TOKEN)
        .with_api_url(&format!("https://127.0.0.1:{}", untrusted_tls_server()));
    let outcome = wrap(&env, &[recipient(KEY_A)], &[], &[FILE_KEY]);
    assert_eq!(
        outcome.errors(),
        [error(&["recipient", "0"], "rypt: TLS certificate rejected")]
    );
}

/// A proxy that records the first request it gets and refuses it.
fn recording_proxy() -> (u16, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            // The whole request head, which may arrive in pieces.
            let mut request = Vec::new();
            let mut byte = [0; 1];
            while !request.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                request.push(byte[0]);
            }
            let _ = sender.send(String::from_utf8_lossy(&request).into_owned());
            let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        }
    });
    (port, receiver)
}

#[test]
fn a_remote_api_is_reached_through_the_proxy() {
    let (port, requests) = recording_proxy();
    let env = Env::default()
        .with_token(TOKEN)
        .with_api_url("https://rypt.invalid")
        .with_var("HTTPS_PROXY", format!("http://127.0.0.1:{port}"));
    // The proxy refuses the tunnel.
    let outcome = wrap(&env, &[recipient(KEY_A)], &[], &[FILE_KEY]);
    assert_eq!(
        outcome.errors(),
        [error(&["recipient", "0"], "rypt: connection failed")]
    );
    let request = requests.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(request.starts_with("CONNECT rypt.invalid:443"), "{request}");
}

#[test]
fn no_proxy_exempts_a_host_from_the_socks_refusal() {
    // Not refused, so the plugin connects directly, and the name does not
    // resolve.
    let env = Env::default()
        .with_token(TOKEN)
        .with_api_url("https://rypt.invalid")
        .with_var("ALL_PROXY", "socks5://127.0.0.1:9")
        .with_var("NO_PROXY", "rypt.invalid");
    let outcome = wrap(&env, &[recipient(KEY_A)], &[], &[FILE_KEY]);
    assert_eq!(
        outcome.errors(),
        [error(&["recipient", "0"], "rypt: connection failed")]
    );
}

#[test]
fn refuses_a_proxy_setting_it_cannot_parse() {
    for (name, value) in [
        ("ALL_PROXY", "socks5h://127.0.0.1:9 "),
        ("HTTPS_PROXY", "http://127.0.0.1:1 "),
        ("http_proxy", "socks4h://127.0.0.1:9"),
    ] {
        let env = Env::default()
            .with_token(TOKEN)
            .with_api_url("https://rypt.invalid")
            .with_var(name, value);
        assert_eq!(
            wrap(&env, &[recipient(KEY_A)], &[], &[FILE_KEY]).errors(),
            [error(
                &["internal"],
                &format!("{name} is not a valid proxy URL")
            )],
            "{name}={value:?}"
        );
    }

    #[cfg(unix)]
    {
        // ureq would skip it and connect directly, so it is refused.
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let env = Env::default()
            .with_token(TOKEN)
            .with_api_url("https://rypt.invalid")
            .with_var("ALL_PROXY", OsStr::from_bytes(b"http://127.0.0.1:\xff"));
        assert_eq!(
            wrap(&env, &[recipient(KEY_A)], &[], &[FILE_KEY]).errors(),
            [error(&["internal"], "ALL_PROXY is not a valid proxy URL")]
        );
    }

    // An empty variable counts as unset, as it does for ureq.
    let (port, requests) = recording_proxy();
    let env = Env::default()
        .with_token(TOKEN)
        .with_api_url("https://rypt.invalid")
        .with_var("ALL_PROXY", "")
        .with_var("HTTPS_PROXY", format!("http://127.0.0.1:{port}"));
    assert_eq!(
        wrap(&env, &[recipient(KEY_A)], &[], &[FILE_KEY]).errors(),
        [error(&["recipient", "0"], "rypt: connection failed")]
    );
    let request = requests.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(request.starts_with("CONNECT rypt.invalid:443"), "{request}");

    // Only the variable that would be used is checked: ALL_PROXY comes first.
    let (port, requests) = recording_proxy();
    let env = Env::default()
        .with_token(TOKEN)
        .with_api_url("https://rypt.invalid")
        .with_var("ALL_PROXY", format!("http://127.0.0.1:{port}"))
        .with_var("HTTPS_PROXY", "not a url");
    assert_eq!(
        wrap(&env, &[recipient(KEY_A)], &[], &[FILE_KEY]).errors(),
        [error(&["recipient", "0"], "rypt: connection failed")]
    );
    let request = requests.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(request.starts_with("CONNECT rypt.invalid:443"), "{request}");
}
