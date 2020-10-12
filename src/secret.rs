use std::fs::File;
use std::path::PathBuf;

use protobuf;
use simple_error::{bail, require_with, try_with, SimpleError};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::utils::memzero;

use crate::proto::entry::Entry;
use crate::proto::key::{Key, Key_oneof_key, SecretboxKey};

// Vault represents a passphrase-locked "vault" of secret data. Before data
// can be accessed, the vault must be unlocked.
pub trait Vault {
	// Attempts to open the vault. On success, a Store instance is returned.
	fn unlock(&self, passphrase: &str) -> Result<Box<dyn Store>, SimpleError>;
}

// Store represents a serialized store of key-value entries. The keys can be
// thought of as a service name (e.g. "My Bank"), while the values are some
// content about the corresponding service which should be kept secret (e.g.
// username, password, security questions, etc).
//
// Entries are named with absolute slash-separated paths, for example
// "/path/to/entry-name". There is no restriction on what can be stored as
// content. Store implementations will always store entry content securely
// (i.e. secretly), but may choose not to store entry names securely.
pub trait Store {
	// Retrieves all of the entries in the Store.
	fn list(&self) -> Result<Vec<String>, SimpleError>;

	// Gets an entry's contents given its name.
	fn get(&self, entry: &str) -> Result<String, SimpleError>;

	// Updates an entry's contents to the given value, or creates a new entry.
	fn put(&self, entry: &str, content: &str) -> Result<(), SimpleError>;

	// Removes an entry by name.
	fn delete(&self, entry: &str) -> Result<(), SimpleError>;
}

pub fn new_vault(location: &str, key: Key) -> Result<Box<dyn Vault>, SimpleError> {
	match key.key {
		None => bail!("empty key"),
		Some(Key_oneof_key::secretbox_key(sbox_key)) => Ok(Box::new(SecretboxVault {
			location: location.to_string(),
			key: sbox_key,
		})),
		Some(Key_oneof_key::pgp_key(..)) => bail!("PGP key unimplemented"),
		_ => bail!("unknown key type"),
	}
}

struct SecretboxVault {
	location: String,
	key: SecretboxKey,
}

impl Vault for SecretboxVault {
	fn unlock(&self, passphrase: &str) -> Result<Box<dyn Store>, SimpleError> {
		// Derive the key-encryption key (KEK).
		let mut kek_bytes: [u8; secretbox::KEYBYTES] = [0; secretbox::KEYBYTES];
		let log2_n = (self.key.n as f64).log2() as u8; // TODO: check that N is a power of 2 before applying log_2.
		let params = match scrypt::ScryptParams::new(log2_n, self.key.r as u32, self.key.p as u32) {
			Ok(params) => params,
			Err(_) => bail!("invalid scrypt parameters in key"),
		};
		if scrypt::scrypt(
			passphrase.as_bytes(),
			&self.key.salt,
			&params,
			&mut kek_bytes,
		)
		.is_err()
		{
			bail!("invalid scrypt output length");
		}
		let kek = require_with!(
			secretbox::Key::from_slice(&kek_bytes),
			"key-encryption key was not KEYBYTES long"
		);
		memzero(&mut kek_bytes);

		// Decrypt the encryption key (EK) using the derived KEK.
		let nonce = require_with!(
			secretbox::Nonce::from_slice(&self.key.encrypted_key_nonce),
			"secretbox encrypted-key nonce was not NONCEBYTES long"
		);
		let mut ek_bytes = match secretbox::open(&self.key.encrypted_key, &nonce, &kek) {
			Ok(ek_bytes) => ek_bytes,
			Err(_) => bail!("incorrect passphrase"),
		};
		let key = require_with!(
			secretbox::Key::from_slice(&ek_bytes),
			"secretbox encrypted key was not KEYBYTES long"
		);
		memzero(&mut ek_bytes);

		Ok(Box::new(SecretboxStore {
			location: self.location.clone(),
			key: key,
		}))
	}
}

struct SecretboxStore {
	location: String,
	key: secretbox::Key,
}

impl Store for SecretboxStore {
	fn list(&self) -> Result<Vec<String>, SimpleError> {
		bail!("unimplemented");
	}

	fn get(&self, entry: &str) -> Result<String, SimpleError> {
		// Read entry content from disk.
		let e: Entry = {
			let filename = self.filename_for_entry(entry);
			let mut f = try_with!(File::open(filename), "entry {} couldn't be opened", entry);
			try_with!(
				protobuf::parse_from_reader(&mut f),
				"entry {} couldn't be parsed",
				entry
			)
		};

		// Decrypt content and return.
		let nonce = require_with!(
			secretbox::Nonce::from_slice(&e.nonce),
			"entry {} has incorrectly-sized nonce",
			entry
		);
		let content_bytes = match secretbox::open(&e.encrypted_content, &nonce, &self.key) {
			Ok(content_bytes) => content_bytes,
			Err(_) => bail!("entry {} couldn't be decrypted", entry),
		};
		Ok(try_with!(
			String::from_utf8(content_bytes),
			"entry {} has non-UTF8 contents",
			entry
		))
	}

	fn put(&self, entry: &str, content: &str) -> Result<(), SimpleError> {
		bail!("unimplemented");
	}

	fn delete(&self, entry: &str) -> Result<(), SimpleError> {
		bail!("unimplemented");
	}
}

impl SecretboxStore {
	fn filename_for_entry(&self, entry: &str) -> PathBuf {
		// TODO: protect against path traversal
		let mut pb = PathBuf::from(&self.location).join(entry);
		pb.set_extension("harp");
		pb
	}
}
