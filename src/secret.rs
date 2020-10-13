use std::fs::{create_dir_all, remove_dir, remove_file, File};
use std::path::{Component, Path, PathBuf};

use protobuf;
use protobuf::Message;
use simple_error::{bail, require_with, SimpleError};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::utils::memzero;
use tempfile;
use walkdir::WalkDir;

use crate::proto::entry::Entry;
use crate::proto::key::{Key, Key_oneof_key, SecretboxKey};

const FILE_EXTENSION: &str = "harp";

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

// Creates a new Vault with the given (locked) `key`, using (encrypted) entry
// data from the given `location`.
pub fn new_vault<P: AsRef<Path>>(location: P, key: Key) -> Result<Box<dyn Vault>, SimpleError> {
	let loc = match PathBuf::from(location.as_ref()).canonicalize() {
		Ok(loc) => loc,
		Err(err) => bail!("bad location: {}", err),
	};
	match key.key {
		None => bail!("empty key"),
		Some(Key_oneof_key::secretbox_key(sbox_key)) => Ok(Box::new(SecretboxVault {
			location: loc,
			key: sbox_key,
		})),
		_ => bail!("unimplemented key type"),
	}
}

struct SecretboxVault {
	location: PathBuf,
	key: SecretboxKey,
}

impl Vault for SecretboxVault {
	fn unlock(&self, passphrase: &str) -> Result<Box<dyn Store>, SimpleError> {
		// Derive the key-encryption key (KEK).
		let mut kek_bytes: [u8; secretbox::KEYBYTES] = [0; secretbox::KEYBYTES];
		let log2_n = (self.key.n as f64).log2() as u8; // TODO: check that N is a power of 2 before applying log_2.
		let params = match scrypt::ScryptParams::new(log2_n, self.key.r as u32, self.key.p as u32) {
			Ok(params) => params,
			Err(err) => bail!("couldn't create scrypt parameters: {}", err),
		};
		if let Err(err) = scrypt::scrypt(
			passphrase.as_bytes(),
			&self.key.salt,
			&params,
			&mut kek_bytes,
		) {
			bail!("scrypt failure: {}", err);
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
			_ => bail!("incorrect passphrase"),
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
	location: PathBuf,
	key: secretbox::Key,
}

impl Store for SecretboxStore {
	fn list(&self) -> Result<Vec<String>, SimpleError> {
		let mut result = Vec::new();
		for entry in WalkDir::new(&self.location) {
			let entry = match entry {
				Ok(entry) => entry,
				Err(err) => bail!(
					"couldn't walk directory {}: {}",
					self.location.display(),
					err
				),
			};
			if !entry.file_type().is_file() {
				continue;
			}
			let mut path = entry.into_path();
			if path.extension() != Some(FILE_EXTENSION.as_ref()) {
				continue;
			}
			path = match path.strip_prefix(&self.location) {
				Ok(p) => p.with_extension(""),
				Err(err) => bail!(
					"couldn't strip prefix from {}: {}",
					self.location.display(),
					err
				),
			};
			let mut entry_name = String::from("/");
			match path.into_os_string().into_string() {
				Ok(s) => entry_name.push_str(&s),
				Err(s) => bail!("couldn't convert path to string: {:?}", s),
			};
			result.push(entry_name);
		}
		Ok(result)
	}

	fn get(&self, entry: &str) -> Result<String, SimpleError> {
		// Read entry content from disk.
		let e: Entry = {
			let filename = self.filename_for_entry(entry)?;
			let mut f = match File::open(filename) {
				Ok(f) => f,
				Err(err) => bail!("entry {} couldn't be opened: {}", entry, err),
			};
			match protobuf::parse_from_reader(&mut f) {
				Ok(e) => e,
				Err(err) => bail!("entry {} couldn't be parsed: {}", entry, err),
			}
		};

		// Decrypt content and return.
		let nonce = require_with!(
			secretbox::Nonce::from_slice(&e.nonce),
			"entry {} has incorrectly-sized nonce",
			entry
		);
		let content_bytes = match secretbox::open(&e.encrypted_content, &nonce, &self.key) {
			Ok(content_bytes) => content_bytes,
			_ => bail!("entry {} couldn't be decrypted", entry),
		};
		match String::from_utf8(content_bytes) {
			Ok(content) => Ok(content),
			Err(err) => bail!("entry {} couldn't be UTF-8 decoded: {}", entry, err),
		}
	}

	fn put(&self, entry: &str, content: &str) -> Result<(), SimpleError> {
		// Encrypt content & build up Entry proto.
		let nonce = secretbox::gen_nonce();
		let encrypted_content = secretbox::seal(content.as_bytes(), &nonce, &self.key);
		let mut e = Entry::new();
		e.set_encrypted_content(encrypted_content);
		e.mut_nonce().extend(nonce.as_ref());

		// Atomically write the new file content.
		let filename = self.filename_for_entry(entry)?;
		if let Some(dir) = filename.parent() {
			if let Err(err) = create_dir_all(dir) {
				bail!("couldn't create dir {}: {}", dir.display(), err);
			}
		}
		let path = require_with!(filename.parent(), "entry {} has no parent", entry);
		let mut temp_file = match tempfile::NamedTempFile::new_in(path) {
			Ok(temp_file) => temp_file,
			Err(err) => bail!("entry {} couldn't create temporary file: {}", entry, err),
		};
		if let Err(err) = e.write_to_writer(&mut temp_file) {
			bail!("entry {} couldn't write to temporary file: {}", entry, err);
		}
		if let Err(err) = temp_file.persist(filename) {
			bail!("entry {} couldn't persist temporary file: {}", entry, err);
		}
		Ok(())
	}

	fn delete(&self, entry: &str) -> Result<(), SimpleError> {
		// Delete file for entry.
		let filename = self.filename_for_entry(entry)?;
		if let Err(err) = remove_file(&filename) {
			bail!("entry {} couldn't be removed: {}", entry, err);
		}

		// Clean up any newly-empty directories.
		for anc in filename.ancestors().skip(1) {
			if anc == &self.location {
				break; // Never delete the base directory of the store.
			}
			let mut it = match anc.read_dir() {
				Ok(it) => it,
				Err(err) => bail!("couldn't read dir {}: {}", anc.display(), err),
			};
			if !it.next().is_none() {
				break; // Directory is not empty.
			}
			if let Err(err) = remove_dir(anc) {
				bail!("couldn't delete empty dir {}: {}", anc.display(), err);
			}
		}
		Ok(())
	}
}

impl SecretboxStore {
	fn filename_for_entry(&self, entry: &str) -> Result<PathBuf, SimpleError> {
		if !entry.starts_with("/") {
			bail!("invalid entry name: {}", entry)
		}
		let mut pb = PathBuf::from(&self.location);
		pb.push(&entry[1..]);
		pb.set_extension(FILE_EXTENSION);
		for c in pb.components() {
			if c == Component::ParentDir {
				bail!("invalid entry name: {}", entry)
			}
		}
		Ok(pb)
	}
}
