//! Shared test support: a mock rypt API and a minimal age plugin client.
//!
//! The client speaks the plugin protocol to the built binary over its
//! stdin/stdout. It is deliberately independent of the plugin's own code, and
//! sets the plugin's environment per process, so tests can run in parallel
//! with different tokens and servers.

#![allow(dead_code)]

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use age_core::primitives::bech32_encode;
use base64::{
    Engine,
    prelude::{BASE64_STANDARD, BASE64_STANDARD_NO_PAD, BASE64_URL_SAFE_NO_PAD},
};
use bech32::Hrp;
use serde_json::{Value, json};
use uuid::Uuid;

/// The plugin binary under test.
pub const BIN: &str = env!("CARGO_BIN_EXE_age-plugin-rypt");

/// The only token the mock accepts. Shaped like a real rypt API key.
pub const TOKEN: &str = "ry_Test1234_abcdefghijklmnopqrstuvwxyz012345";

/// Text in every body the mock sends that is not a successful answer, so tests
/// can check the plugin never repeats a response body.
pub const MOCK_BODY_MARKER: &str = "mock-body-marker";

/// A key whose `decrypt` returns one byte short of what was encrypted.
pub const SHORT_KEY: Uuid = Uuid::from_u128(0x5a5a5a5a_0000_4000_8000_000000000015);
/// A key for which the mock answers 200 with a body that is not JSON.
pub const NOT_JSON_KEY: Uuid = Uuid::from_u128(0x5a5a5a5a_0000_4000_8000_0000000000a1);
/// A key for which the mock answers 200 with JSON missing the expected field.
pub const MISSING_FIELD_KEY: Uuid = Uuid::from_u128(0x5a5a5a5a_0000_4000_8000_0000000000a2);
/// A key for which the mock answers 200 with a field that is not valid
/// base64: the correct answer's base64 with a stray character after it.
pub const BAD_BASE64_KEY: Uuid = Uuid::from_u128(0x5a5a5a5a_0000_4000_8000_0000000000a3);
/// A key whose `encrypt` returns an empty ciphertext.
pub const EMPTY_CIPHERTEXT_KEY: Uuid = Uuid::from_u128(0x5a5a5a5a_0000_4000_8000_0000000000a4);
/// A key for which the mock answers 200 with valid JSON larger than 64 KiB.
pub const OVERSIZED_KEY: Uuid = Uuid::from_u128(0x5a5a5a5a_0000_4000_8000_0000000000a5);

/// A key for which the mock answers every request with `status`.
///
/// `status_key(404)` is `00000000-0000-0000-0000-000000000404`.
pub fn status_key(status: u16) -> Uuid {
    Uuid::parse_str(&format!("00000000-0000-0000-0000-{status:012}")).unwrap()
}

fn forced_status(key: Uuid) -> Option<u16> {
    let key = key.hyphenated().to_string();
    let digits = key.strip_prefix("00000000-0000-0000-0000-")?;
    digits.parse().ok()
}

/// Encodes a key as an age recipient, independently of the plugin's code.
pub fn recipient(key: Uuid) -> String {
    bech32_encode(Hrp::parse_unchecked("age1rypt"), key.as_bytes())
}

/// Encodes a key as an age identity, independently of the plugin's code.
pub fn identity(key: Uuid) -> String {
    raw_identity(key.as_bytes())
}

/// A recipient string with an arbitrary payload, for testing rejection.
pub fn raw_recipient(payload: &[u8]) -> String {
    bech32_encode(Hrp::parse_unchecked("age1rypt"), payload)
}

/// An identity string with an arbitrary payload, for testing rejection.
pub fn raw_identity(payload: &[u8]) -> String {
    bech32_encode(Hrp::parse_unchecked("AGE-PLUGIN-RYPT-"), payload).to_uppercase()
}

// ---------------------------------------------------------------------------
// Mock rypt API

/// A rypt API on a random local port.
///
/// It implements `POST /v1/keys/{id}/encrypt` and `/decrypt` with a
/// reversible toy cipher that binds the ciphertext to the key, checks the
/// bearer token, the content type and the padded base64 as rypt does, and
/// counts requests.
pub struct MockRypt {
    pub url: String,
    pub port: u16,
    server: Arc<tiny_http::Server>,
    encrypts: Arc<AtomicUsize>,
    decrypts: Arc<AtomicUsize>,
}

impl MockRypt {
    pub fn start() -> Self {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let address = server.server_addr().to_ip().unwrap();
        let encrypts = Arc::new(AtomicUsize::new(0));
        let decrypts = Arc::new(AtomicUsize::new(0));
        {
            let server = server.clone();
            let encrypts = encrypts.clone();
            let decrypts = decrypts.clone();
            thread::spawn(move || {
                for request in server.incoming_requests() {
                    handle(request, &encrypts, &decrypts);
                }
            });
        }
        MockRypt {
            url: format!("http://{address}"),
            port: address.port(),
            server,
            encrypts,
            decrypts,
        }
    }

    /// Requests to any `encrypt` path, whatever their outcome.
    pub fn encrypt_calls(&self) -> usize {
        self.encrypts.load(Ordering::SeqCst)
    }

    /// Requests to any `decrypt` path, whatever their outcome.
    pub fn decrypt_calls(&self) -> usize {
        self.decrypts.load(Ordering::SeqCst)
    }
}

impl Drop for MockRypt {
    fn drop(&mut self) {
        self.server.unblock();
    }
}

struct Reply {
    status: u16,
    body: String,
}

fn reply(status: u16, body: Value) -> Reply {
    Reply {
        status,
        body: body.to_string(),
    }
}

fn error(status: u16, code: &str) -> Reply {
    reply(
        status,
        json!({"error": code, "message": MOCK_BODY_MARKER, "request_id": "req_mock"}),
    )
}

fn handle(mut request: tiny_http::Request, encrypts: &AtomicUsize, decrypts: &AtomicUsize) {
    let Reply { status, body } = respond(&mut request, encrypts, decrypts);
    let mut response = tiny_http::Response::from_string(body)
        .with_status_code(status)
        .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap());
    // A plugin that followed a redirect would get a different error.
    if (300..400).contains(&status) {
        response.add_header(tiny_http::Header::from_bytes("Location", "/redirected").unwrap());
    }
    let _ = request.respond(response);
}

fn respond(
    request: &mut tiny_http::Request,
    encrypts: &AtomicUsize,
    decrypts: &AtomicUsize,
) -> Reply {
    let url = request.url().to_owned();
    let segments: Vec<&str> = url.trim_start_matches('/').split('/').collect();
    let (key, operation) = match segments.as_slice() {
        ["v1", "keys", id, operation @ ("encrypt" | "decrypt")] => (*id, *operation),
        _ => return error(404, "not_found"),
    };
    match operation {
        "encrypt" => encrypts.fetch_add(1, Ordering::SeqCst),
        _ => decrypts.fetch_add(1, Ordering::SeqCst),
    };

    let header = |name: &'static str| {
        request
            .headers()
            .iter()
            .find(|h| h.field.equiv(name))
            .map(|h| h.value.as_str().to_owned())
    };
    if header("Authorization") != Some(format!("Bearer {TOKEN}")) {
        return error(401, "unauthorized");
    }
    if *request.method() != tiny_http::Method::Post {
        return error(405, "method_not_allowed");
    }
    if !header("Content-Type").is_some_and(|v| v.starts_with("application/json")) {
        return error(415, "unsupported_media_type");
    }
    // The plugin is built without decompression, which would let a response
    // grow past its size limit; offering gzip would mean that came back.
    if header("Accept-Encoding").is_some_and(|v| v.to_ascii_lowercase().contains("gzip")) {
        return error(400, "unexpected_accept_encoding");
    }
    let Ok(key) = Uuid::try_parse(key) else {
        return error(400, "invalid_request");
    };
    if let Some(status) = forced_status(key) {
        return error(status, "forced");
    }
    match key {
        NOT_JSON_KEY => {
            return Reply {
                status: 200,
                body: format!("not json {MOCK_BODY_MARKER}"),
            };
        }
        MISSING_FIELD_KEY => return reply(200, json!({"result": MOCK_BODY_MARKER})),
        OVERSIZED_KEY => {
            let padding = BASE64_STANDARD.encode(vec![0; 70_000]);
            return reply(200, json!({"ciphertext": padding, "plaintext": padding}));
        }
        _ => {}
    }

    let mut body = String::new();
    if request.as_reader().read_to_string(&mut body).is_err() {
        return error(400, "invalid_request");
    }
    let Ok(body) = serde_json::from_str::<Value>(&body) else {
        return error(400, "invalid_request");
    };
    let (field, answer_field) = match operation {
        "encrypt" => ("plaintext", "ciphertext"),
        _ => ("ciphertext", "plaintext"),
    };
    // Like rypt, only padded standard base64.
    let Some(input) = body[field]
        .as_str()
        .and_then(|s| BASE64_STANDARD.decode(s).ok())
    else {
        return error(400, "invalid_base64");
    };

    let answer = if operation == "encrypt" {
        if key == EMPTY_CIPHERTEXT_KEY {
            Vec::new()
        } else {
            toy_seal(key, &input)
        }
    } else {
        match toy_open(key, &input) {
            Some(mut plaintext) => {
                if key == SHORT_KEY {
                    plaintext.pop();
                }
                plaintext
            }
            None => return error(400, "invalid_ciphertext"),
        }
    };
    let mut encoded = BASE64_STANDARD.encode(answer);
    if key == BAD_BASE64_KEY {
        encoded.push('!');
    }
    reply(200, json!({ answer_field: encoded }))
}

/// Starts the toy ciphertext. Its length makes every toy ciphertext of a
/// 16-byte file key 41 bytes, so its base64 needs padding.
const TOY_MAGIC: &[u8] = b"mock-rypt";

/// The mock's ciphertext of `plaintext` under `key`.
pub fn toy_seal(key: Uuid, plaintext: &[u8]) -> Vec<u8> {
    let mut out = TOY_MAGIC.to_vec();
    out.extend_from_slice(key.as_bytes());
    out.extend(plaintext.iter().map(|b| b ^ 0x5a));
    out
}

fn toy_open(key: Uuid, ciphertext: &[u8]) -> Option<Vec<u8>> {
    let rest = ciphertext.strip_prefix(TOY_MAGIC)?;
    let rest = rest.strip_prefix(key.as_bytes().as_slice())?;
    Some(rest.iter().map(|b| b ^ 0x5a).collect())
}

/// The plaintext of a toy ciphertext under whatever key it names.
fn toy_open_any(ciphertext: &[u8]) -> Option<Vec<u8>> {
    let rest = ciphertext.strip_prefix(TOY_MAGIC)?;
    let key = Uuid::from_slice(rest.get(..16)?).ok()?;
    toy_open(key, ciphertext)
}

// ---------------------------------------------------------------------------
// Plugin protocol client

/// An age stanza or plugin protocol command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stanza {
    pub tag: String,
    pub args: Vec<String>,
    pub body: Vec<u8>,
}

impl Stanza {
    pub fn new(tag: &str, args: &[&str], body: &[u8]) -> Self {
        Stanza {
            tag: tag.to_owned(),
            args: args.iter().map(|s| s.to_string()).collect(),
            body: body.to_vec(),
        }
    }
}

pub fn write_stanza(w: &mut impl Write, tag: &str, args: &[&str], body: &[u8]) -> io::Result<()> {
    let mut header = format!("-> {tag}");
    for arg in args {
        header.push(' ');
        header.push_str(arg);
    }
    writeln!(w, "{header}")?;
    let encoded = BASE64_STANDARD_NO_PAD.encode(body);
    let mut rest = encoded.as_str();
    while rest.len() >= 64 {
        let (line, tail) = rest.split_at(64);
        writeln!(w, "{line}")?;
        rest = tail;
    }
    // The last body line is always short, and empty if it has to be.
    writeln!(w, "{rest}")?;
    w.flush()
}

pub fn read_stanza(r: &mut impl BufRead) -> io::Result<Stanza> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let header = line
        .strip_suffix('\n')
        .and_then(|l| l.strip_prefix("-> "))
        .ok_or_else(|| io::Error::other(format!("bad stanza header: {line:?}")))?;
    let mut words = header.split(' ').map(str::to_owned);
    let tag = words.next().unwrap_or_default();
    let args = words.collect();

    let mut encoded = String::new();
    loop {
        line.clear();
        if r.read_line(&mut line)? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let chunk = line.trim_end_matches('\n');
        encoded.push_str(chunk);
        if chunk.len() < 64 {
            break;
        }
    }
    let body = BASE64_STANDARD_NO_PAD
        .decode(&encoded)
        .map_err(io::Error::other)?;
    Ok(Stanza { tag, args, body })
}

/// Environment variables that would send the plugin's requests elsewhere.
const PROXY_VARIABLES: [&str; 8] = [
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// The environment a plugin process runs with.
#[derive(Clone)]
pub struct Env {
    pub token: Option<String>,
    pub api_url: String,
    /// Further variables, applied last: a value to set, or `None` to unset.
    pub vars: Vec<(String, Option<OsString>)>,
}

impl Default for Env {
    /// No token, and an API URL nothing listens on, so a command run with it
    /// can never reach a real rypt deployment.
    fn default() -> Self {
        Env {
            token: None,
            api_url: "http://127.0.0.1:1".to_owned(),
            vars: Vec::new(),
        }
    }
}

impl Env {
    pub fn for_mock(mock: &MockRypt) -> Self {
        Env {
            token: Some(TOKEN.to_owned()),
            api_url: mock.url.clone(),
            vars: Vec::new(),
        }
    }

    pub fn without_token(mut self) -> Self {
        self.token = None;
        self
    }

    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_owned());
        self
    }

    pub fn with_api_url(mut self, url: &str) -> Self {
        self.api_url = url.to_owned();
        self
    }

    pub fn with_var(mut self, name: &str, value: impl Into<OsString>) -> Self {
        self.vars.push((name.to_owned(), Some(value.into())));
        self
    }

    /// Applies this environment to a command, clearing anything in the test's
    /// own environment that would change where requests go.
    pub fn apply(&self, command: &mut Command) {
        for proxy in PROXY_VARIABLES {
            command.env_remove(proxy);
        }
        command.env("RYPT_API_URL", &self.api_url);
        match &self.token {
            Some(token) => command.env("RYPT_TOKEN", token),
            None => command.env_remove("RYPT_TOKEN"),
        };
        for (name, value) in &self.vars {
            match value {
                Some(value) => command.env(name, value),
                None => command.env_remove(name),
            };
        }
    }

    /// The tokens this environment holds, as secrets to check for.
    fn tokens(&self) -> Vec<Vec<u8>> {
        let mut tokens = vec![TOKEN.as_bytes().to_vec()];
        if let Some(token) = &self.token {
            tokens.push(token.trim().as_bytes().to_vec());
        }
        tokens
    }
}

/// Everything the plugin sent during phase 2, except `done` and grease.
#[derive(Debug)]
pub struct Outcome {
    pub commands: Vec<Stanza>,
    pub stderr: String,
    /// Every command the plugin sent, grease and unknown ones included, for
    /// the leak checks.
    all: Vec<Stanza>,
}

impl Outcome {
    /// The recipient stanzas for one file, as they would appear in its header.
    pub fn stanzas(&self, file_index: usize) -> Vec<Stanza> {
        let file_index = file_index.to_string();
        self.commands
            .iter()
            .filter(|c| c.tag == "recipient-stanza" && c.args[0] == file_index)
            .map(|c| Stanza {
                tag: c.args[1].clone(),
                args: c.args[2..].to_vec(),
                body: c.body.clone(),
            })
            .collect()
    }

    /// Each `error` command as its metadata and message.
    pub fn errors(&self) -> Vec<(Vec<String>, String)> {
        self.commands
            .iter()
            .filter(|c| c.tag == "error")
            .map(|c| (c.args.clone(), String::from_utf8(c.body.clone()).unwrap()))
            .collect()
    }

    /// Each unwrapped file key by file index.
    pub fn file_keys(&self) -> HashMap<usize, Vec<u8>> {
        self.commands
            .iter()
            .filter(|c| c.tag == "file-key")
            .map(|c| (c.args[0].parse().unwrap(), c.body.clone()))
            .collect()
    }
}

/// The forms a secret could leak in.
fn leak_forms(secret: &[u8]) -> Vec<Vec<u8>> {
    let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
    vec![
        secret.to_vec(),
        hex.as_bytes().to_vec(),
        hex.to_uppercase().into_bytes(),
        BASE64_STANDARD_NO_PAD.encode(secret).into_bytes(),
        BASE64_URL_SAFE_NO_PAD.encode(secret).into_bytes(),
        // How Rust's `{:?}` shows bytes: "[48, 49, 50, ...]".
        format!("{secret:?}").into_bytes(),
    ]
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Checks a plugin run leaked nothing: no output on stderr; no token or file
/// key in any command except the `file-key` command meant to carry one; and no
/// ciphertext or mock response body in anything an age client shows the user.
fn assert_no_leaks(outcome: &Outcome, secrets: &[Vec<u8>], ciphertexts: &[Vec<u8>]) {
    assert_eq!(outcome.stderr, "", "the plugin must not write to stderr");
    for command in &outcome.all {
        let mut text = command.args.join(" ").into_bytes();
        let shown_to_user = matches!(
            command.tag.as_str(),
            "error" | "msg" | "confirm" | "request-public" | "request-secret"
        );
        if command.tag != "file-key" {
            text.extend_from_slice(&command.body);
        }
        for secret in secrets.iter().filter(|s| s.len() >= 8) {
            for form in leak_forms(secret) {
                assert!(!contains(&text, &form), "{command:?} leaks a secret");
            }
        }
        if shown_to_user {
            assert!(
                !contains(&command.body, MOCK_BODY_MARKER.as_bytes()),
                "{command:?} repeats a response body"
            );
            for ciphertext in ciphertexts {
                for form in leak_forms(ciphertext) {
                    assert!(
                        !contains(&command.body, &form),
                        "{command:?} leaks a ciphertext"
                    );
                }
            }
        }
    }
}

fn spawn(env: &Env, state_machine: &str) -> Child {
    let mut command = Command::new(BIN);
    command
        .arg(format!("--age-plugin={state_machine}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    env.apply(&mut command);
    command.spawn().unwrap()
}

/// Runs phase 2 as the age client: acknowledges `known` commands, answers
/// anything else (grease) with `unsupported`, and stops at `done`. Returns the
/// known commands and every command.
fn serve(
    stdin: &mut ChildStdin,
    stdout: &mut impl BufRead,
    known: &[&str],
) -> (Vec<Stanza>, Vec<Stanza>) {
    let mut commands = Vec::new();
    let mut all = Vec::new();
    loop {
        let command = read_stanza(stdout).unwrap();
        if command.tag == "done" {
            return (commands, all);
        }
        all.push(command.clone());
        if known.contains(&command.tag.as_str()) {
            write_stanza(stdin, "ok", &[], &[]).unwrap();
            commands.push(command);
        } else {
            write_stanza(stdin, "unsupported", &[], &[]).unwrap();
        }
    }
}

fn finish(
    mut child: Child,
    stdin: ChildStdin,
    (commands, all): (Vec<Stanza>, Vec<Stanza>),
) -> Outcome {
    drop(stdin);
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let status = child.wait().unwrap();
    assert!(status.success(), "plugin exited with {status}: {stderr}");
    Outcome {
        commands,
        stderr,
        all,
    }
}

/// Runs `recipient-v1`: wraps each file key to the recipients and identities.
pub fn wrap(
    env: &Env,
    recipients: &[String],
    identities: &[String],
    file_keys: &[[u8; 16]],
) -> Outcome {
    let mut child = spawn(env, "recipient-v1");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    for r in recipients {
        write_stanza(&mut stdin, "add-recipient", &[r], &[]).unwrap();
    }
    for i in identities {
        write_stanza(&mut stdin, "add-identity", &[i], &[]).unwrap();
    }
    for file_key in file_keys {
        write_stanza(&mut stdin, "wrap-file-key", &[], file_key).unwrap();
    }
    write_stanza(&mut stdin, "extension-labels", &[], &[]).unwrap();
    write_stanza(&mut stdin, "done", &[], &[]).unwrap();

    let commands = serve(
        &mut stdin,
        &mut stdout,
        &["labels", "recipient-stanza", "error", "msg"],
    );
    let outcome = finish(child, stdin, commands);

    let mut secrets = env.tokens();
    secrets.extend(file_keys.iter().map(|k| k.to_vec()));
    let ciphertexts: Vec<Vec<u8>> = outcome
        .commands
        .iter()
        .filter(|c| c.tag == "recipient-stanza")
        .map(|c| c.body.clone())
        .collect();
    assert_no_leaks(&outcome, &secrets, &ciphertexts);
    outcome
}

/// Runs `identity-v1`: tries to unwrap each file's stanzas with the identities.
pub fn unwrap(env: &Env, identities: &[String], files: &[Vec<Stanza>]) -> Outcome {
    let mut child = spawn(env, "identity-v1");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    for i in identities {
        write_stanza(&mut stdin, "add-identity", &[i], &[]).unwrap();
    }
    for (file_index, stanzas) in files.iter().enumerate() {
        let file_index = file_index.to_string();
        for stanza in stanzas {
            let mut args = vec![file_index.as_str(), stanza.tag.as_str()];
            args.extend(stanza.args.iter().map(String::as_str));
            write_stanza(&mut stdin, "recipient-stanza", &args, &stanza.body).unwrap();
        }
    }
    write_stanza(&mut stdin, "done", &[], &[]).unwrap();

    let commands = serve(&mut stdin, &mut stdout, &["file-key", "error", "msg"]);
    let outcome = finish(child, stdin, commands);

    let bodies = files.iter().flatten().map(|s| s.body.clone());
    let ciphertexts: Vec<Vec<u8>> = bodies.filter(|b| b.len() >= 8).collect();
    let mut secrets = env.tokens();
    secrets.extend(ciphertexts.iter().filter_map(|c| toy_open_any(c)));
    assert_no_leaks(&outcome, &secrets, &ciphertexts);
    outcome
}

/// How a run of the binary ended.
pub struct CliRun {
    /// The exit code, or `None` if a signal ended the process.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Runs the binary with arguments, optional stdin and an optional plugin
/// environment.
pub fn run_cli_raw(args: &[&str], stdin: Option<&[u8]>, env: Option<&Env>) -> CliRun {
    let mut command = Command::new(BIN);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(env) = env {
        env.apply(&mut command);
    }
    let mut child = command.spawn().unwrap();
    {
        let mut child_stdin = child.stdin.take().unwrap();
        if let Some(input) = stdin {
            // The binary may stop reading early, as it does past its size limit.
            let _ = child_stdin.write_all(input);
        }
    }
    let output = child.wait_with_output().unwrap();
    CliRun {
        code: output.status.code(),
        stdout: String::from_utf8(output.stdout).unwrap(),
        stderr: String::from_utf8(output.stderr).unwrap(),
    }
}

/// Runs the binary like `run_cli_raw`, returning `(success, stdout, stderr)`.
pub fn run_cli(args: &[&str], stdin: Option<&str>, env: Option<&Env>) -> (bool, String, String) {
    let run = run_cli_raw(args, stdin.map(str::as_bytes), env);
    (run.code == Some(0), run.stdout, run.stderr)
}

/// A self-signed certificate for 127.0.0.1, valid until 2126, that no client
/// trusts, and its private key. A test fixture only.
const UNTRUSTED_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBpjCCAUygAwIBAgIUPTs3yVWxuUyWtvgtuEFqwoC6H8QwCgYIKoZIzj0EAwIw
HzEdMBsGA1UEAwwUYWdlLXBsdWdpbi1yeXB0LXRlc3QwIBcNMjYxMDAxMTQxMjAz
WhgPMjEyNjA5MDcxNDEyMDNaMB8xHTAbBgNVBAMMFGFnZS1wbHVnaW4tcnlwdC10
ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8Nk5w/jnDa51nlA9SrRD0w14
ErbKxlaJcLaYlBVgpSF+auqXjD26d1ZJK3Jl5vgsscgOse4uqA0dCfYLGbVeCqNk
MGIwHQYDVR0OBBYEFDGcfiGuURhKmdeIBkPAHmYxn0QCMB8GA1UdIwQYMBaAFDGc
fiGuURhKmdeIBkPAHmYxn0QCMA8GA1UdEwEB/wQFMAMBAf8wDwYDVR0RBAgwBocE
fwAAATAKBggqhkjOPQQDAgNIADBFAiEA3ErWhJ0kqkHSCdAu8GAp+ko6vHbT5KlO
VDYZYRYMhvwCIHtkjJNJw0amJq2aRDSJSsUd9LGqVqEch+TfQNL4ZV4e
-----END CERTIFICATE-----
";
const UNTRUSTED_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjXz5iqZt5n4x8RGP
I7H7XkuyfKB+LkUTq/Q9WMXM0NahRANCAATw2TnD+OcNrnWeUD1KtEPTDXgStsrG
VolwtpiUFWClIX5q6peMPbp3VkkrcmXm+CyxyA6x7i6oDR0J9gsZtV4K
-----END PRIVATE KEY-----
";

/// A TLS server on 127.0.0.1 with a certificate no client trusts. Returns its
/// port.
pub fn untrusted_tls_server() -> u16 {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let cert = CertificateDer::from_pem_slice(UNTRUSTED_CERT.as_bytes()).unwrap();
    let key = PrivateKeyDer::from_pem_slice(UNTRUSTED_KEY.as_bytes()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut connection = rustls::ServerConnection::new(config.clone()).unwrap();
            // Until the client gives up on the certificate.
            while connection.is_handshaking() {
                if connection.complete_io(&mut stream).is_err() {
                    break;
                }
            }
        }
    });
    port
}
