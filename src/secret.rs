use std::fmt;
use std::fs;
use std::fs::File;
use std::path::{Component, Path, PathBuf};

use protobuf;
use protobuf::Message;
use scrypt;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::utils::memzero;
use tempfile;
use walkdir::WalkDir;

use crate::proto::entry::Entry;
use crate::proto::key::{Key, Key_oneof_key, SecretboxKey};

const FILE_EXTENSION: &str = "harp";

/// Represents a passphrase-locked "vault" of secret data. Before data can be
/// accessed, the vault must be unlocked.
#[derive(Debug)]
pub struct Vault {
	location: PathBuf,
	key: SecretboxKey,
}

impl Vault {
	/// Creates a new Vault with the given locked `key`, using encrypted entry
	/// data from the given `location`.
	pub fn new<P: AsRef<Path>>(location: P, key: Key) -> Result<Vault> {
		let loc = PathBuf::from(location.as_ref())
			.canonicalize()
			.map_err(|e| Error::Internal(e.to_string()))?;
		match key.key {
			None => Err(Error::Internal(String::from("empty key"))),
			Some(Key_oneof_key::secretbox_key(sbox_key)) => Ok(Vault {
				location: loc,
				key: sbox_key,
			}),
			_ => Err(Error::Unimplemented(String::from("unimplemented key type"))),
		}
	}

	/// Attempts to open the vault. On success, a Store instance is returned.
	pub fn unlock(&self, passphrase: &str) -> Result<Store> {
		// Derive the key-encryption key (KEK).
		let mut kek_bytes: [u8; secretbox::KEYBYTES] = [0; secretbox::KEYBYTES];
		let log2_n = (self.key.n as f64).log2() as u8; // TODO: check that N is a power of 2 before applying log_2.
		let params = scrypt::ScryptParams::new(log2_n, self.key.r as u32, self.key.p as u32)
			.map_err(|e| Error::Internal(format!("scrypt parameters: {}", e)))?;
		scrypt::scrypt(passphrase.as_ref(), &self.key.salt, &params, &mut kek_bytes)
			.map_err(|e| Error::Internal(format!("scrypt error: {}", e)))?;
		let kek = secretbox::Key::from_slice(&kek_bytes).ok_or_else(|| {
			Error::Internal(String::from("key-encryption key was not KEYBYTES long"))
		})?;
		memzero(&mut kek_bytes);

		// Decrypt the encryption key (EK) using the derived KEK.
		let nonce =
			secretbox::Nonce::from_slice(&self.key.encrypted_key_nonce).ok_or_else(|| {
				Error::Internal(String::from("encrypted-key nonce was not NONCEBYTES long"))
			})?;
		let mut ek_bytes = secretbox::open(&self.key.encrypted_key, &nonce, &kek)
			.map_err(|_| Error::InvalidPassphrase)?;
		let key = secretbox::Key::from_slice(&ek_bytes).ok_or_else(|| {
			Error::Internal(String::from(
				"secretbox encrypted key was not KEYBYTES long",
			))
		})?;
		memzero(&mut ek_bytes);

		Ok(Store {
			location: self.location.clone(),
			key: key,
		})
	}
}

/// Store represents a serialized store of key-value entries. The keys can be
/// thought of as a service name (e.g. "My Bank"), while the values are some
/// content about the corresponding service which should be kept secret (e.g.
/// username, password, security questions, etc).
///
/// Entries are named with absolute slash-separated paths, for example
/// "/path/to/entry-name". There is no restriction on what can be stored as
/// content. Store implementations will always store entry content securely
/// (i.e. secretly), but may choose not to store entry names securely.
#[derive(Debug)]
pub struct Store {
	location: PathBuf,
	key: secretbox::Key,
}

impl Store {
	/// Retrieves all of the entries in the Store.
	pub fn list(&self) -> Result<Vec<String>> {
		let mut result = Vec::new();
		for entry in WalkDir::new(&self.location) {
			let entry = entry.map_err(|e| {
				Error::Internal(format!(
					"couldn't walk directory {}: {}",
					self.location.display(),
					e
				))
			})?;

			if !entry.file_type().is_file() {
				continue;
			}
			let mut path = entry.into_path();
			if path.extension() != Some(FILE_EXTENSION.as_ref()) {
				continue;
			}
			path = path
				.strip_prefix(&self.location)
				.map_err(|e| {
					Error::Internal(format!(
						"couldn't strip prefix from {}: {}",
						path.display(),
						e
					))
				})?
				.with_extension("");
			let mut entry_name = String::from("/");
			entry_name.push_str(path.to_str().ok_or_else(|| {
				Error::Internal(format!(
					"couldn't convert path to string: {}",
					path.display()
				))
			})?);
			result.push(entry_name);
		}
		Ok(result)
	}

	/// Gets an entry's contents given its name.
	pub fn get(&self, entry: &str) -> Result<String> {
		// Read entry content from disk.
		let e: Entry = {
			let filename = self.filename_for_entry(entry)?;
			let mut f = File::open(filename).map_err(|e| {
				Error::Internal(format!("entry {} couldn't be opened: {}", entry, e))
			})?;
			protobuf::parse_from_reader(&mut f).map_err(|e| {
				Error::Internal(format!("entry {} couldn't be parsed: {}", entry, e))
			})?
		};

		// Decrypt content and return.
		let nonce = secretbox::Nonce::from_slice(&e.nonce).ok_or_else(|| {
			Error::Internal(format!("entry {} has incorrectly-sized nonce", entry))
		})?;
		let content_bytes = secretbox::open(&e.encrypted_content, &nonce, &self.key)
			.map_err(|_| Error::Internal(format!("entry {} couldn't be decrypted", entry)))?;
		String::from_utf8(content_bytes).map_err(|e| {
			Error::Internal(format!("entry {} couldn't be UTF-8 decoded: {}", entry, e))
		})
	}

	/// Updates an entry's contents to the given value, or creates a new entry.
	pub fn put(&self, entry: &str, content: &str) -> Result<()> {
		// Encrypt content & build up Entry proto.
		let nonce = secretbox::gen_nonce();
		let encrypted_content = secretbox::seal(content.as_bytes(), &nonce, &self.key);
		let mut e = Entry::new();
		e.set_encrypted_content(encrypted_content);
		e.mut_nonce().extend(nonce.as_ref());

		// Atomically write the new file content.
		let filename = self.filename_for_entry(entry)?;
		if let Some(dir) = filename.parent() {
			fs::create_dir_all(dir).map_err(|e| {
				Error::Internal(format!("couldn't create dir {}: {}", dir.display(), e))
			})?;
		}
		let path = filename
			.parent()
			.ok_or_else(|| Error::Internal(format!("entry {} has no parent", entry)))?;
		let mut temp_file = tempfile::NamedTempFile::new_in(path)
			.map_err(|e| Error::Internal(format!("couldn't create temporary file: {}", e)))?;
		e.write_to_writer(&mut temp_file)
			.map_err(|e| Error::Internal(format!("couldn't write to temporary file: {}", e)))?;
		temp_file
			.persist(filename)
			.map_err(|e| Error::Internal(format!("couldn't persist temporary file: {}", e)))?;
		Ok(())
	}

	/// Removes an entry by name.
	pub fn delete(&self, entry: &str) -> Result<()> {
		// Delete file for entry.
		let filename = self.filename_for_entry(entry)?;
		fs::remove_file(&filename).map_err(|e| {
			Error::Internal(format!("couldn't remove {}: {}", filename.display(), e))
		})?;

		// Clean up any newly-empty directories.
		for anc in filename.ancestors().skip(1) {
			if anc == &self.location {
				break; // Never delete the base directory of the store.
			}
			let mut it = anc.read_dir().map_err(|e| {
				Error::Internal(format!("couldn't read dir {}: {}", anc.display(), e))
			})?;
			if !it.next().is_none() {
				break; // Directory is not empty.
			}
			fs::remove_dir(anc).map_err(|e| {
				Error::Internal(format!(
					"couldn't delete empty dir {}: {}",
					anc.display(),
					e
				))
			})?;
		}
		Ok(())
	}

	fn filename_for_entry(&self, entry: &str) -> Result<PathBuf> {
		if !entry.starts_with("/") {
			return Err(Error::Internal(format!("invalid entry name: {}", entry)));
		}
		let mut pb = PathBuf::from(&self.location);
		pb.push(&entry[1..]);
		pb.set_extension(FILE_EXTENSION);
		for c in pb.components() {
			if c == Component::ParentDir {
				return Err(Error::Internal(format!("invalid entry name: {}", entry)));
			}
		}
		Ok(pb)
	}
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
	Internal(String),
	InvalidPassphrase,
	Unimplemented(String),
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Error::Internal(msg) => write!(f, "internal error: {}", msg),
			Error::InvalidPassphrase => write!(f, "invalid passphrase"),
			Error::Unimplemented(msg) => write!(f, "unimplemented: {}", msg),
		}
	}
}

#[cfg(test)]
mod tests {
	use std::fs;
	use std::fs::File;
	use std::io;
	use std::path::{Path, PathBuf};

	use tempdir::TempDir;

	use crate::proto::key::Key;

	use super::{Error, Vault};

	const CORRECT_PASSWORD: &str = "password";
	const ALPHA_CONTENT: &str = "Alpha password\nsecond line\n\nhttp://google.com\nhttp://google.com/\nhttps://google.com/foo/bar\n";
	const BETA_CONTENT: &str = "Beta password\nsecond line\nthird line\n";
	const GAMMA_CONTENT: &str = "Gamma password\na second line\n";

	#[test]
	fn vault() {
		let (vault, _dir) = create_vault();

		// Correct password gets a Store.
		vault.unlock(CORRECT_PASSWORD).unwrap();

		// Incorrect password gets an InvalidPassphrase error.
		let incorrect_password = format!("incorrect_{}", CORRECT_PASSWORD);
		assert_eq!(
			vault.unlock(&incorrect_password).unwrap_err(),
			Error::InvalidPassphrase
		);
	}

	#[test]
	fn store() {
		let (vault, _dir) = create_vault();
		let store = vault.unlock(CORRECT_PASSWORD).unwrap();

		// Validate the initial state.
		let mut entries = store.list().unwrap();
		entries.sort();
		assert_eq!(entries, vec!("/Alpha", "/Beta", "/Gamma"));
		assert_eq!(store.get("/Alpha").unwrap(), ALPHA_CONTENT);
		assert_eq!(store.get("/Beta").unwrap(), BETA_CONTENT);
		assert_eq!(store.get("/Gamma").unwrap(), GAMMA_CONTENT);

		// Delete an entry and check that it's gone.
		store.delete("/Beta").unwrap();
		let mut entries = store.list().unwrap();
		entries.sort();
		assert_eq!(entries, vec!("/Alpha", "/Gamma"));

		// Add an entry and check that it shows up & has the correct contents.
		const DELTA_CONTENT: &str = "Delta password\nsecond line\n";
		store.put("/Delta", DELTA_CONTENT).unwrap();
		let mut entries = store.list().unwrap();
		entries.sort();
		assert_eq!(entries, vec!("/Alpha", "/Delta", "/Gamma"));
		assert_eq!(store.get("/Delta").unwrap(), DELTA_CONTENT);

		// Add an entry in a directory and check that it shows up & has the correct contents.DELTA_CONTENT
		const EPSILON_CONTENT: &str = "Epsilon password\n";
		store.put("/Dir/Epsilon", EPSILON_CONTENT).unwrap();
		let mut entries = store.list().unwrap();
		entries.sort();
		assert_eq!(entries, vec!("/Alpha", "/Delta", "/Dir/Epsilon", "/Gamma"));
		assert_eq!(store.get("/Dir/Epsilon").unwrap(), EPSILON_CONTENT);

		// Delete all entries, then check that the entries are gone.
		store.delete("/Alpha").unwrap();
		store.delete("/Delta").unwrap();
		store.delete("/Dir/Epsilon").unwrap();
		store.delete("/Gamma").unwrap();
		let mut entries = store.list().unwrap();
		entries.sort();
		assert_eq!(entries, Vec::<String>::new());
	}

	fn create_vault() -> (Vault, TempDir) {
		let dir = TempDir::new("harpoxide").unwrap();
		copy_dir_recursive("tests/assets/passwords.sbox", dir.path()).unwrap();
		let key: Key = {
			let mut f = File::open("tests/assets/key.sbox").unwrap();
			protobuf::parse_from_reader(&mut f).unwrap()
		};
		let vault = Vault::new(dir.as_ref(), key).unwrap();
		(vault, dir)
	}

	fn copy_dir_recursive<U: AsRef<Path>, V: AsRef<Path>>(from: U, to: V) -> io::Result<()> {
		let mut stack = Vec::new();
		stack.push(PathBuf::from(from.as_ref()));

		let output_root = PathBuf::from(to.as_ref());
		let input_root_count = PathBuf::from(from.as_ref()).components().count();

		while let Some(working_path) = stack.pop() {
			// Generate a relative path
			let src: PathBuf = working_path.components().skip(input_root_count).collect();

			// Create a destination if missing
			let dest = if src.components().count() == 0 {
				output_root.clone()
			} else {
				output_root.join(&src)
			};
			fs::create_dir_all(&dest)?;

			for entry in fs::read_dir(working_path)? {
				let entry = entry?;
				let path = entry.path();
				if path.is_dir() {
					stack.push(path);
				} else if let Some(filename) = path.file_name() {
					let dest_path = dest.join(filename);
					fs::copy(&path, &dest_path)?;
				}
			}
		}
		Ok(())
	}
}
