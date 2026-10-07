//! Whole files encrypted and decrypted by the `age` library, which finds the
//! plugin on `PATH` and drives it over the plugin protocol just as rage does.
//!
//! The library gives the plugin this process's environment, so this binary
//! holds a single test that sets the environment once.

mod common;

use std::io::{Read, Write};
use std::path::Path;

use age::plugin::{Identity, IdentityPluginV1, Recipient, RecipientPluginV1};
use age::secrecy::SecretString;
use age::{Callbacks, DecryptError, Decryptor, Encryptor};
use common::*;
use uuid::Uuid;

const KEY_A: Uuid = Uuid::from_u128(0x3f2a9c1e_7b4d_4e2a_9f10_6c8d5a2b1e47);
const KEY_B: Uuid = Uuid::from_u128(0x0f1e2d3c_4b5a_6978_8796_a5b4c3d2e1f0);
const KEY_C: Uuid = Uuid::from_u128(0x11111111_2222_4333_8444_555555555555);

#[derive(Clone)]
struct NoUi;

impl Callbacks for NoUi {
    fn display_message(&self, _: &str) {}
    fn confirm(&self, _: &str, _: &str, _: Option<&str>) -> Option<bool> {
        None
    }
    fn request_public_string(&self, _: &str) -> Option<String> {
        None
    }
    fn request_passphrase(&self, _: &str) -> Option<SecretString> {
        None
    }
}

fn encrypt(recipients: &[Uuid], identities: &[Uuid], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let recipients: Vec<Recipient> = recipients
        .iter()
        .map(|k| recipient(*k).parse().unwrap())
        .collect();
    let identities: Vec<Identity> = identities
        .iter()
        .map(|k| identity(*k).parse().unwrap())
        .collect();
    let plugin = RecipientPluginV1::new("rypt", &recipients, &identities, NoUi).unwrap();
    let encryptor = Encryptor::with_recipients(std::iter::once(&plugin as &dyn age::Recipient))
        .map_err(|e| e.to_string())?;
    let mut ciphertext = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    Ok(ciphertext)
}

fn decrypt(identities: &[Uuid], ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let identities: Vec<Identity> = identities
        .iter()
        .map(|k| identity(*k).parse().unwrap())
        .collect();
    let plugin = IdentityPluginV1::new("rypt", &identities, NoUi).unwrap();
    let mut reader =
        Decryptor::new(ciphertext)?.decrypt(std::iter::once(&plugin as &dyn age::Identity))?;
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    Ok(plaintext)
}

fn header(ciphertext: &[u8]) -> String {
    let end = ciphertext
        .windows(4)
        .position(|w| w == b"\n---")
        .expect("age header");
    String::from_utf8(ciphertext[..end].to_vec()).unwrap()
}

#[test]
fn encrypts_and_decrypts_files() {
    let mock = MockRypt::start();
    let bin_dir = Path::new(BIN).parent().unwrap().to_owned();
    let path = std::env::join_paths(std::iter::once(bin_dir).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .unwrap();
    // SAFETY: this is the only test in this binary, and nothing else running
    // in the process (the test harness, the mock server) reads or writes the
    // environment concurrently.
    unsafe {
        std::env::set_var("PATH", path);
        std::env::set_var("RYPT_TOKEN", TOKEN);
        std::env::set_var("RYPT_API_URL", &mock.url);
        for proxy in [
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
        ] {
            std::env::remove_var(proxy);
        }
    }

    // Three 64 KiB payload chunks and a partial one.
    let plaintext: Vec<u8> = (0..200_000u32).map(|i| (i * 7919 % 251) as u8).collect();

    // To a recipient.
    let ciphertext = encrypt(&[KEY_A], &[], &plaintext).unwrap();
    let header_text = header(&ciphertext);
    assert!(header_text.starts_with("age-encryption.org/v1\n"));
    assert!(
        header_text.contains(&format!("\n-> rypt {KEY_A}\n")),
        "{header_text}"
    );
    assert_eq!(decrypt(&[KEY_A], &ciphertext).unwrap(), plaintext);

    // To a recipient and an identity: either one decrypts.
    let ciphertext = encrypt(&[KEY_A], &[KEY_B], &plaintext).unwrap();
    let header_text = header(&ciphertext);
    assert!(header_text.contains(&format!("\n-> rypt {KEY_A}\n")));
    assert!(header_text.contains(&format!("\n-> rypt {KEY_B}\n")));
    assert_eq!(decrypt(&[KEY_B], &ciphertext).unwrap(), plaintext);
    assert_eq!(decrypt(&[KEY_C, KEY_A], &ciphertext).unwrap(), plaintext);

    // An identity for another key does not match.
    assert!(matches!(
        decrypt(&[KEY_C], &ciphertext),
        Err(DecryptError::NoMatchingKeys)
    ));

    // A key rypt does not have.
    let error = encrypt(&[status_key(404)], &[], &plaintext).unwrap_err();
    assert!(error.contains("rypt: key not found"), "{error}");

    // One rypt operation per stanza wrapped (the refused one included) and per
    // stanza tried: none for the non-matching identity.
    assert_eq!(mock.encrypt_calls(), 4);
    assert_eq!(mock.decrypt_calls(), 3);

    // Alongside a native X25519 recipient: either identity decrypts, and the
    // X25519 one needs no rypt call.
    let x25519 = age::x25519::Identity::generate();
    let rypt_recipient: Recipient = recipient(KEY_A).parse().unwrap();
    let plugin = RecipientPluginV1::new("rypt", &[rypt_recipient], &[], NoUi).unwrap();
    let x25519_recipient = x25519.to_public();
    let encryptor = Encryptor::with_recipients(
        [
            &plugin as &dyn age::Recipient,
            &x25519_recipient as &dyn age::Recipient,
        ]
        .into_iter(),
    )
    .unwrap();
    let mut ciphertext = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
    writer.write_all(&plaintext).unwrap();
    writer.finish().unwrap();
    let header_text = header(&ciphertext);
    assert!(header_text.contains("\n-> X25519 "));
    assert!(header_text.contains(&format!("\n-> rypt {KEY_A}\n")));

    let mut reader = Decryptor::new(&ciphertext[..])
        .unwrap()
        .decrypt(std::iter::once(&x25519 as &dyn age::Identity))
        .unwrap();
    let mut decrypted = Vec::new();
    reader.read_to_end(&mut decrypted).unwrap();
    assert_eq!(decrypted, plaintext);
    assert_eq!(mock.decrypt_calls(), 3);

    assert_eq!(decrypt(&[KEY_A], &ciphertext).unwrap(), plaintext);
    assert_eq!(mock.decrypt_calls(), 4);
}
