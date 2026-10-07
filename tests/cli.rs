//! The user-facing subcommands.

mod common;

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use common::*;
use uuid::Uuid;

const KEY: &str = "3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47";

fn key() -> Uuid {
    Uuid::parse_str(KEY).unwrap()
}

#[test]
fn new_prints_an_identity_file() {
    let (ok, stdout, stderr) = run_cli(&["new", "--key", KEY], None, None);
    assert!(ok, "{stderr}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "{stdout}");

    let created = lines[0].strip_prefix("# created: ").unwrap();
    chrono::DateTime::parse_from_rfc3339(created).unwrap();
    assert_eq!(lines[1], format!("# key: {KEY}"));
    assert_eq!(lines[2], identity(key()));
    assert!(lines[2].starts_with("AGE-PLUGIN-RYPT-1"));
}

#[test]
fn new_stamps_the_local_time() {
    // A POSIX TZ string, so no time zone database is needed.
    let env = Env::default().with_var("TZ", "<-05>5");
    let (ok, stdout, stderr) = run_cli(&["new", "--key", KEY], None, Some(&env));
    assert!(ok, "{stderr}");
    let created = stdout
        .lines()
        .next()
        .unwrap()
        .strip_prefix("# created: ")
        .unwrap();
    assert!(created.ends_with("-05:00"), "{created}");
    let created = chrono::DateTime::parse_from_rfc3339(created).unwrap();
    let skew = chrono::Utc::now()
        .signed_duration_since(created)
        .num_seconds()
        .abs();
    assert!(skew < 60, "{created} is {skew} s from now");
}

#[test]
fn new_canonicalizes_the_key() {
    for form in [KEY.to_uppercase(), key().simple().to_string()] {
        let (ok, stdout, stderr) = run_cli(&["new", "--key", &form], None, None);
        assert!(ok, "{stderr}");
        assert!(stdout.contains(&format!("\n# key: {KEY}\n")), "{stdout}");
    }
}

#[test]
fn new_does_not_call_the_api() {
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);
    let (ok, _, stderr) = run_cli(&["new", "--key", KEY], None, Some(&env));
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = run_cli(&["new", "--key", KEY], None, Some(&env.without_token()));
    assert!(ok, "{stderr}");
    assert_eq!((mock.encrypt_calls(), mock.decrypt_calls()), (0, 0));
}

#[test]
fn new_rejects_a_bad_key() {
    let (ok, stdout, stderr) = run_cli(&["new", "--key", "not-a-uuid"], None, None);
    assert!(!ok);
    assert_eq!(stdout, "");
    assert!(stderr.contains("--key"), "{stderr}");

    let (ok, _, _) = run_cli(&["new"], None, None);
    assert!(!ok);
}

#[test]
fn recipient_reads_standard_input() {
    let (_, identity_file, _) = run_cli(&["new", "--key", KEY], None, None);
    let expected = format!("{}\n", recipient(key()));

    let (ok, stdout, stderr) = run_cli(&["recipient"], Some(&identity_file), None);
    assert!(ok, "{stderr}");
    assert_eq!(stdout, expected);

    let (ok, stdout, stderr) = run_cli(&["recipient", "-"], Some(&identity_file), None);
    assert!(ok, "{stderr}");
    assert_eq!(stdout, expected);
}

#[test]
fn recipient_reads_a_path() {
    let (_, identity_file, _) = run_cli(&["new", "--key", KEY], None, None);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.txt");
    std::fs::write(&path, identity_file).unwrap();

    let (ok, stdout, stderr) = run_cli(&["recipient", path.to_str().unwrap()], None, None);
    assert!(ok, "{stderr}");
    assert_eq!(stdout, format!("{}\n", recipient(key())));
    assert!(stdout.starts_with("age1rypt1"));
}

#[test]
fn recipient_prints_one_line_per_rypt_identity() {
    let other = Uuid::from_u128(0x0f1e2d3c_4b5a_6978_8796_a5b4c3d2e1f0);
    let file = format!("# two keys\n{}\n{}\n", identity(key()), identity(other));
    let (ok, stdout, stderr) = run_cli(&["recipient"], Some(&file), None);
    assert!(ok, "{stderr}");
    assert_eq!(
        stdout,
        format!("{}\n{}\n", recipient(key()), recipient(other))
    );
}

#[test]
fn recipient_fails_without_a_rypt_identity() {
    let (ok, stdout, stderr) = run_cli(&["recipient"], Some("# nothing here\n"), None);
    assert!(!ok);
    assert_eq!(stdout, "");
    assert_eq!(stderr, "age-plugin-rypt: no rypt identity found\n");
}

#[test]
fn recipient_rejects_a_lowercase_identity() {
    let file = format!("{}\n", identity(key()).to_lowercase());
    let (ok, stdout, stderr) = run_cli(&["recipient"], Some(&file), None);
    assert!(!ok);
    assert_eq!(stdout, "");
    assert_eq!(
        stderr,
        "age-plugin-rypt: line 1: identity must be uppercase\n"
    );
}

#[test]
fn recipient_names_the_file_it_cannot_read() {
    let (ok, _, stderr) = run_cli(&["recipient", "/nonexistent/identity.txt"], None, None);
    assert!(!ok);
    assert!(
        stderr.starts_with("age-plugin-rypt: /nonexistent/identity.txt: "),
        "{stderr}"
    );

    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path().to_str().unwrap();
    let (ok, _, stderr) = run_cli(&["recipient", dir], None, None);
    assert!(!ok);
    assert!(
        stderr.starts_with(&format!("age-plugin-rypt: {dir}: ")),
        "{stderr}"
    );
}

#[test]
fn recipient_refuses_a_huge_input() {
    let mut file = format!("{}\n", identity(key()));
    file.push_str(&"#".repeat(1 << 20));
    let (ok, stdout, stderr) = run_cli(&["recipient"], Some(&file), None);
    assert!(!ok);
    assert_eq!(stdout, "");
    assert_eq!(
        stderr,
        "age-plugin-rypt: standard input: larger than 1 MiB\n"
    );
}

#[test]
fn no_arguments_prints_help_to_stderr() {
    let run = run_cli_raw(&[], None, None);
    assert_eq!(run.code, Some(2));
    assert_eq!(run.stdout, "");
    assert!(run.stderr.contains("Usage:"), "{}", run.stderr);
}

#[test]
fn recipient_rejects_a_padded_identity() {
    let file = format!("  {}\n", identity(key()));
    let (ok, stdout, stderr) = run_cli(&["recipient"], Some(&file), None);
    assert!(!ok);
    assert_eq!(stdout, "");
    assert_eq!(
        stderr,
        "age-plugin-rypt: line 1: identity has surrounding whitespace, which age does not accept\n"
    );
}

#[test]
fn recipient_requires_utf8() {
    let mut file = b"# caf\xe9\n".to_vec();
    file.extend_from_slice(identity(key()).as_bytes());
    let run = run_cli_raw(&["recipient"], Some(&file), None);
    assert_eq!(run.code, Some(1));
    assert_eq!(
        run.stderr,
        "age-plugin-rypt: standard input: not valid UTF-8\n"
    );
}

#[cfg(unix)]
#[test]
fn recipient_stops_reading_at_the_size_limit() {
    // An endless input: only a capped read ever finishes.
    let mut child = Command::new(BIN)
        .args(["recipient", "/dev/zero"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > Duration::from_secs(20) {
            child.kill().unwrap();
            panic!("recipient kept reading /dev/zero");
        }
        thread::sleep(Duration::from_millis(20));
    }
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert_eq!(stderr, "age-plugin-rypt: /dev/zero: larger than 1 MiB\n");
}

#[test]
fn a_closed_stdout_is_an_error_not_a_panic() {
    let mut child = Command::new(BIN)
        .arg("recipient")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Close our end of stdout before the binary writes to it.
    drop(child.stdout.take());
    child
        .stdin
        .take()
        .unwrap()
        .write_all(identity(key()).as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    // A panic would exit with 101.
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.starts_with("age-plugin-rypt: Broken pipe"),
        "{stderr}"
    );
}

#[test]
fn prints_the_version() {
    let (ok, stdout, _) = run_cli(&["--version"], None, None);
    assert!(ok);
    assert_eq!(
        stdout,
        format!("age-plugin-rypt {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn rejects_an_unknown_state_machine() {
    let (ok, stdout, stderr) = run_cli(&["--age-plugin=bogus-v1"], None, None);
    assert!(!ok);
    assert_eq!(stdout, "");
    assert!(stderr.contains("unknown plugin state machine"), "{stderr}");
}
