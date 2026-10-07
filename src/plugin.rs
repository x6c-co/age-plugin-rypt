//! The `recipient-v1` and `identity-v1` state machines.

use std::collections::{HashMap, HashSet};
use std::io;

use age_core::format::{FileKey, Stanza};
use age_core::secrecy::ExposeSecret;
use age_plugin::{
    Callbacks, PluginHandler,
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::api::Client;
use crate::key::{PLUGIN_NAME, key_from_payload};
use crate::stanza::{self, Kind};

/// The error for a `rypt` stanza that does not follow the format.
const INVALID_STANZA: &str = "rypt: invalid stanza";

/// The error for the identity with no data that `age -j rypt` passes.
const NO_DEFAULT_IDENTITY: &str =
    "rypt has no default identity: use -i with a file from age-plugin-rypt new";

pub struct Handler;

impl PluginHandler for Handler {
    type RecipientV1 = RecipientPlugin;
    type IdentityV1 = IdentityPlugin;

    fn recipient_v1(self) -> io::Result<Self::RecipientV1> {
        Ok(RecipientPlugin::default())
    }

    fn identity_v1(self) -> io::Result<Self::IdentityV1> {
        Ok(IdentityPlugin::default())
    }
}

fn parse_key(plugin_name: &str, bytes: &[u8]) -> Result<Uuid, String> {
    if !plugin_name.eq_ignore_ascii_case(PLUGIN_NAME) {
        return Err(format!("unsupported plugin name: {plugin_name}"));
    }
    key_from_payload(bytes).map_err(|e| e.to_string())
}

fn parse_identity(plugin_name: &str, bytes: &[u8]) -> Result<Uuid, String> {
    if bytes.is_empty() && plugin_name.eq_ignore_ascii_case(PLUGIN_NAME) {
        return Err(NO_DEFAULT_IDENTITY.to_owned());
    }
    parse_key(plugin_name, bytes)
}

/// Where a key came from, so an encrypt failure can name its recipient or
/// identity.
enum Source {
    Recipient(usize),
    Identity(usize),
}

impl Source {
    fn error(&self, message: String) -> recipient::Error {
        match *self {
            Source::Recipient(index) => recipient::Error::Recipient { index, message },
            Source::Identity(index) => recipient::Error::Identity { index, message },
        }
    }
}

#[derive(Default)]
pub struct RecipientPlugin {
    keys: Vec<(Source, Uuid)>,
}

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        let key = parse_key(plugin_name, bytes)
            .map_err(|message| recipient::Error::Recipient { index, message })?;
        self.keys.push((Source::Recipient(index), key));
        Ok(())
    }

    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        let key = parse_identity(plugin_name, bytes)
            .map_err(|message| recipient::Error::Identity { index, message })?;
        self.keys.push((Source::Identity(index), key));
        Ok(())
    }

    fn labels(&mut self) -> HashSet<String> {
        HashSet::new()
    }

    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        _callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        let client = match Client::from_env() {
            Ok(client) => client,
            Err(message) => return Ok(Err(vec![recipient::Error::Internal { message }])),
        };

        // `FileKey` zeroizes its buffer when dropped.
        let mut files = Vec::with_capacity(file_keys.len());
        for file_key in &file_keys {
            let mut stanzas = Vec::with_capacity(self.keys.len());
            for (source, key) in &self.keys {
                // The state machine requires a stanza for every recipient and
                // identity, so any failure fails the whole wrap.
                match client.encrypt(*key, file_key.expose_secret()) {
                    Ok(ciphertext) => stanzas.push(stanza::build(*key, ciphertext)),
                    Err(message) => return Ok(Err(vec![source.error(message)])),
                }
            }
            files.push(stanzas);
        }
        Ok(Ok(files))
    }
}

#[derive(Default)]
pub struct IdentityPlugin {
    keys: Vec<Uuid>,
}

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        let key = parse_identity(plugin_name, bytes)
            .map_err(|message| identity::Error::Identity { index, message })?;
        self.keys.push(key);
        Ok(())
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        _callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        // Built on first use, so a file with no stanza for our keys never
        // needs a token.
        let mut client = None;
        let mut results = HashMap::new();
        for (file_index, stanzas) in files.iter().enumerate() {
            if let Some(result) = self.unwrap_file(&mut client, file_index, stanzas) {
                results.insert(file_index, result);
            }
        }
        Ok(results)
    }
}

impl IdentityPlugin {
    /// Tries each `rypt` stanza for a loaded key in turn and returns the first
    /// file key recovered, the errors if none was, or `None` if no stanza was
    /// for a loaded key.
    fn unwrap_file(
        &self,
        client: &mut Option<Result<Client, String>>,
        file_index: usize,
        stanzas: &[Stanza],
    ) -> Option<Result<FileKey, Vec<identity::Error>>> {
        // Stanza errors name the stanza's position among all of the file's
        // stanzas, so enumerate before filtering.

        // A malformed `rypt` stanza makes the header invalid. The plugin
        // protocol requires an error for it, and nothing unwrapped from the
        // file, even by another stanza.
        let malformed: Vec<_> = stanzas
            .iter()
            .enumerate()
            .filter(|(_, stanza)| stanza::parse(stanza) == Kind::Malformed)
            .map(|(stanza_index, _)| identity::Error::Stanza {
                file_index,
                stanza_index,
                message: INVALID_STANZA.to_owned(),
            })
            .collect();
        if !malformed.is_empty() {
            return Some(Err(malformed));
        }

        let mut errors = Vec::new();
        for (stanza_index, stanza) in stanzas.iter().enumerate() {
            let Kind::Rypt(key) = stanza::parse(stanza) else {
                continue;
            };
            if !self.keys.contains(&key) {
                continue;
            }
            let client = match client.get_or_insert_with(Client::from_env) {
                Ok(client) => client,
                Err(message) => {
                    return Some(Err(vec![identity::Error::Internal {
                        message: message.clone(),
                    }]));
                }
            };
            match client.decrypt(key, &stanza.body).and_then(file_key_from) {
                Ok(file_key) => return Some(Ok(file_key)),
                Err(message) => errors.push(identity::Error::Stanza {
                    file_index,
                    stanza_index,
                    message,
                }),
            }
        }
        (!errors.is_empty()).then_some(Err(errors))
    }
}

fn file_key_from(plaintext: Zeroizing<Vec<u8>>) -> Result<FileKey, String> {
    FileKey::try_init_with_mut(|file_key| {
        if plaintext.len() == file_key.len() {
            file_key.copy_from_slice(&plaintext);
            Ok(())
        } else {
            Err("rypt: decrypted file key is not 16 bytes".to_owned())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_key_accepts_16_bytes_for_this_plugin() {
        let key = Uuid::from_u128(0x3f2a9c1e_7b4d_4e2a_9f10_6c8d5a2b1e47);
        assert_eq!(parse_key("rypt", key.as_bytes()), Ok(key));
        assert_eq!(parse_key("RYPT", key.as_bytes()), Ok(key));
    }

    #[test]
    fn parse_key_rejects_other_plugins_and_lengths() {
        assert!(parse_key("yubikey", &[0; 16]).is_err());
        assert_eq!(
            parse_key("rypt", &[0; 15]).unwrap_err(),
            "key id must be 16 bytes, got 15"
        );
        assert_eq!(
            parse_key("rypt", &[0; 17]).unwrap_err(),
            "key id must be 16 bytes, got 17"
        );
    }

    #[test]
    fn parse_identity_explains_an_empty_identity() {
        assert_eq!(
            parse_identity("rypt", &[]).unwrap_err(),
            "rypt has no default identity: use -i with a file from age-plugin-rypt new"
        );
        assert_eq!(
            parse_identity("rypt", &[0; 15]).unwrap_err(),
            "key id must be 16 bytes, got 15"
        );
        let key = Uuid::from_u128(0x3f2a9c1e_7b4d_4e2a_9f10_6c8d5a2b1e47);
        assert_eq!(parse_identity("rypt", key.as_bytes()), Ok(key));
    }

    #[test]
    fn file_key_must_be_16_bytes() {
        let key = file_key_from(Zeroizing::new(vec![7; 16])).unwrap();
        assert_eq!(key.expose_secret(), &[7; 16]);
        for len in [0, 15, 17, 32] {
            assert_eq!(
                file_key_from(Zeroizing::new(vec![7; len])).err().unwrap(),
                "rypt: decrypted file key is not 16 bytes"
            );
        }
    }
}
