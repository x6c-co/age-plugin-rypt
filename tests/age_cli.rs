//! The plugin under a real age client: the `age` CLI (the Go reference
//! implementation) or `rage`, whichever is on `PATH`.
//!
//! Skipped when neither is, unless `AGE_PLUGIN_RYPT_REQUIRE_CLI` is set, as it
//! should be in CI, where a skip would hide that these tests never ran.

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::*;

const KEY: &str = "3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47";

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    path.is_file()
}

/// The first `name` on `PATH` that can run, as a shell would find it.
fn find_on_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|path| is_executable(path))
}

/// The age client to test with, or `None` (after saying so) to skip.
fn age_client() -> Option<PathBuf> {
    let client = find_on_path("age").or_else(|| find_on_path("rage"));
    if client.is_none() {
        assert!(
            std::env::var_os("AGE_PLUGIN_RYPT_REQUIRE_CLI").is_none(),
            "AGE_PLUGIN_RYPT_REQUIRE_CLI is set, but neither `age` nor `rage` is on PATH"
        );
        // Straight to stderr, which the test harness does not capture.
        let _ = std::io::stderr()
            .write_all(b"age_cli: skipping, neither `age` nor `rage` is on PATH\n");
    }
    client
}

/// Runs the age client with the plugin binary first on `PATH`.
fn run_age(client: &Path, env: &Env, args: &[&str]) -> Output {
    let bin_dir = Path::new(BIN).parent().unwrap().to_owned();
    let path = std::env::join_paths(std::iter::once(bin_dir).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .unwrap();
    let mut command = Command::new(client);
    command.args(args).env("PATH", path);
    env.apply(&mut command);
    command.output().unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "age failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct Files {
    dir: tempfile::TempDir,
    plaintext: Vec<u8>,
}

impl Files {
    /// An identity file from `new`, and a plaintext spanning several payload
    /// chunks.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (ok, identity_file, stderr) = run_cli(&["new", "--key", KEY], None, None);
        assert!(ok, "{stderr}");
        std::fs::write(dir.path().join("identity.txt"), identity_file).unwrap();
        let plaintext: Vec<u8> = (0..200_000u32).map(|i| (i * 7919 % 251) as u8).collect();
        std::fs::write(dir.path().join("plain.bin"), &plaintext).unwrap();
        Files { dir, plaintext }
    }

    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).to_str().unwrap().to_owned()
    }

    fn recipient(&self) -> String {
        let (ok, stdout, stderr) = run_cli(&["recipient", &self.path("identity.txt")], None, None);
        assert!(ok, "{stderr}");
        stdout.trim().to_owned()
    }

    fn assert_rypt_header(&self, name: &str) {
        let ciphertext = std::fs::read(self.path(name)).unwrap();
        let text = String::from_utf8_lossy(&ciphertext);
        assert!(text.starts_with("age-encryption.org/v1\n"));
        assert!(
            text.contains(&format!("\n-> rypt {KEY}\n")),
            "no rypt stanza"
        );
    }

    fn assert_decrypts(&self, client: &Path, env: &Env, name: &str) {
        let out = format!("{name}.out");
        assert_success(&run_age(
            client,
            env,
            &[
                "-d",
                "-i",
                &self.path("identity.txt"),
                "-o",
                &self.path(&out),
                &self.path(name),
            ],
        ));
        assert_eq!(std::fs::read(self.path(&out)).unwrap(), self.plaintext);
    }
}

#[test]
fn encrypts_to_a_recipient_and_decrypts() {
    let Some(client) = age_client() else { return };
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);
    let files = Files::new();

    assert_success(&run_age(
        &client,
        &env,
        &[
            "-e",
            "-r",
            &files.recipient(),
            "-o",
            &files.path("r.age"),
            &files.path("plain.bin"),
        ],
    ));
    files.assert_rypt_header("r.age");
    files.assert_decrypts(&client, &env, "r.age");
    assert_eq!((mock.encrypt_calls(), mock.decrypt_calls()), (1, 1));
}

#[test]
fn encrypts_to_an_identity_file_and_decrypts() {
    let Some(client) = age_client() else { return };
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);
    let files = Files::new();

    assert_success(&run_age(
        &client,
        &env,
        &[
            "-e",
            "-i",
            &files.path("identity.txt"),
            "-o",
            &files.path("i.age"),
            &files.path("plain.bin"),
        ],
    ));
    files.assert_rypt_header("i.age");
    files.assert_decrypts(&client, &env, "i.age");
}

#[test]
fn reports_plugin_errors() {
    let Some(client) = age_client() else { return };
    let mock = MockRypt::start();
    let env = Env::for_mock(&mock);
    let files = Files::new();

    // Encrypting to a key rypt does not have.
    let output = run_age(
        &client,
        &env,
        &[
            "-e",
            "-r",
            &recipient(status_key(404)),
            "-o",
            &files.path("missing.age"),
            &files.path("plain.bin"),
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("rypt: key not found"), "{stderr}");
    assert!(!stderr.contains(TOKEN), "{stderr}");

    // Decrypting without a token.
    assert_success(&run_age(
        &client,
        &env,
        &[
            "-e",
            "-r",
            &files.recipient(),
            "-o",
            &files.path("r.age"),
            &files.path("plain.bin"),
        ],
    ));
    let output = run_age(
        &client,
        &env.clone().without_token(),
        &[
            "-d",
            "-i",
            &files.path("identity.txt"),
            &files.path("r.age"),
        ],
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("RYPT_TOKEN is not set"), "{stderr}");
}
