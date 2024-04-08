use crate::proto::secret::{key, Entry, Key, SecretboxKey};
use anyhow::{anyhow, Context};
use prost::Message as _;
use sodiumoxide::{crypto::secretbox, utils::memzero};
use std::{
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
};
use thiserror::Error;
use walkdir::WalkDir;

const FILE_EXTENSION: &str = "harp";

/// Represents a passphrase-locked "vault" of secret data. Before data can be accessed, the vault
/// must be unlocked.
#[derive(Debug)]
pub struct Vault {
    location: PathBuf,
    key: SecretboxKey,
}

impl Vault {
    /// Creates a new Vault with the given locked `key`, using encrypted entry data from the given
    /// `location`.
    pub fn new<P: AsRef<Path>>(location: P, key: Key) -> Result<Vault, Error> {
        let location = PathBuf::from(location.as_ref())
            .canonicalize()
            .context("Couldn't canonicalize path")?;
        match key.key {
            None => Err(anyhow!("Missing key").into()),
            Some(key::Key::SecretboxKey(key)) => Ok(Vault { location, key }),
            _ => Err(anyhow!("Unimplemented key type").into()),
        }
    }

    /// Attempts to open the vault. On success, a Store instance is returned.
    pub fn unlock(&self, passphrase: &str) -> Result<Store, Error> {
        // Derive the key-encryption key (KEK).
        let mut kek_bytes = [0; secretbox::KEYBYTES];
        let log2_n = (self.key.n as f64).log2() as u8; // TODO: check that N is a power of 2 before applying log_2.
        let params = scrypt::Params::new(
            log2_n,
            self.key.r as u32,
            self.key.p as u32,
            secretbox::KEYBYTES,
        )
        .map_err(|err| anyhow!("scrypt parameters: {}", err))?;
        scrypt::scrypt(passphrase.as_ref(), &self.key.salt, &params, &mut kek_bytes)
            .map_err(|err| anyhow!("scrypt: {}", err))?;
        let kek = secretbox::Key::from_slice(&kek_bytes)
            .ok_or_else(|| anyhow!("KEK length incorrect"))?;
        memzero(&mut kek_bytes);

        // Decrypt the encryption key (EK) using the derived KEK.
        let nonce = secretbox::Nonce::from_slice(&self.key.encrypted_key_nonce)
            .ok_or_else(|| anyhow!("Nonce length incorrect"))?;
        let mut ek_bytes = secretbox::open(&self.key.encrypted_key, &nonce, &kek)
            .map_err(|_| Error::InvalidPassphrase)?;
        let key = secretbox::Key::from_slice(&ek_bytes)
            .ok_or_else(|| anyhow!("Encrypted key length incorrect"))?;
        memzero(&mut ek_bytes);

        Ok(Store {
            location: self.location.clone(),
            key,
        })
    }
}

/// Store represents a serialized store of key-value entries. The keys can be thought of as a
/// service name (e.g. "My Bank"), while the values are some content about the corresponding service
/// which should be kept secret (e.g. username, password, security questions, etc).
///
/// Entries are named with absolute slash-separated paths, for example "/path/to/entry-name". There
/// is no restriction on what can be stored as content. Store implementations will always store
/// entry content securely (i.e. secretly), but may choose not to store entry names securely.
#[derive(Debug)]
pub struct Store {
    location: PathBuf,
    key: secretbox::Key,
}

impl Store {
    /// Retrieves all of the entries in the Store.
    pub fn list(&self) -> Result<Vec<String>, Error> {
        let mut result = Vec::new();
        for entry in WalkDir::new(&self.location) {
            let entry = entry.context("Couldn't walk directory")?;

            if !entry.file_type().is_file() {
                continue;
            }
            let mut path = entry.into_path();
            if path.extension() != Some(FILE_EXTENSION.as_ref()) {
                continue;
            }
            path = path
                .strip_prefix(&self.location)
                .with_context(|| format!("Couldn't strip prefix from {}", path.display()))?
                .with_extension("");
            let mut entry_name = String::from("/");
            entry_name.push_str(
                path.to_str().ok_or_else(|| {
                    anyhow!("Couldn't convert path to string: {}", path.display())
                })?,
            );
            result.push(entry_name);
        }
        Ok(result)
    }

    /// Gets an entry's contents given its name.
    pub fn get(&self, entry: &str) -> Result<String, Error> {
        // Read entry content from disk.
        let entry_pb = {
            let filename = self.filename_for_entry(entry)?;
            let entry_bytes =
                fs::read(filename).with_context(|| format!("Entry {entry} couldn't be read"))?;
            Entry::decode(entry_bytes.as_ref())
                .with_context(|| format!("Entry {entry} couldn't be parsed"))?
        };

        // Decrypt content and return.
        let nonce = secretbox::Nonce::from_slice(&entry_pb.nonce)
            .ok_or_else(|| anyhow!("Entry {entry} has incorrect nonce length"))?;
        let content_bytes = secretbox::open(&entry_pb.encrypted_content, &nonce, &self.key)
            .map_err(|_| anyhow!("Entry {entry} couldn't be decrypted"))?;
        Ok(String::from_utf8(content_bytes)
            .with_context(|| format!("Entry {entry} couldn't be UTF-8 decoded"))?)
    }

    /// Updates an entry's contents to the given value, or creates a new entry.
    pub fn put(&self, entry: &str, content: &str) -> Result<(), Error> {
        let filename = self.filename_for_entry(entry)?;

        // Encrypt content & build Entry proto.
        let nonce = secretbox::gen_nonce();
        let entry_bytes = Entry {
            encrypted_content: secretbox::seal(content.as_bytes(), &nonce, &self.key),
            nonce: nonce.as_ref().to_vec(),
        }
        .encode_to_vec();

        // Atomically write the new file content.
        let path = filename
            .parent()
            .ok_or_else(|| anyhow!("Entry {entry} has no parent"))?;
        fs::create_dir_all(path)
            .with_context(|| format!("Couldn't create dir {}", path.display()))?;
        let mut temp_file = tempfile::NamedTempFile::new_in(path)
            .with_context(|| format!("Couldn't create temporary file for entry {entry}"))?;
        temp_file
            .write_all(&entry_bytes)
            .with_context(|| format!("Couldn't write entry {entry} to temporary file"))?;
        temp_file
            .persist(filename)
            .with_context(|| format!("Couldn't persist entry {entry}"))?;
        Ok(())
    }

    /// Removes an entry by name.
    pub fn delete(&self, entry: &str) -> Result<(), Error> {
        // Delete file for entry.
        let filename = self.filename_for_entry(entry)?;
        fs::remove_file(&filename).with_context(|| format!("Couldn't delete entry {entry}"))?;

        // Clean up any newly-empty directories.
        for ancestor in filename.ancestors().skip(1) {
            if ancestor == self.location {
                break; // Never delete the base directory of the store.
            }
            let mut it = ancestor
                .read_dir()
                .with_context(|| format!("Couldn't read dir {}", ancestor.display()))?;
            if it.next().is_some() {
                break; // Directory is not empty.
            }
            fs::remove_dir(ancestor)
                .with_context(|| format!("Couldn't delete empty dir {}", ancestor.display()))?;
        }
        Ok(())
    }

    fn filename_for_entry(&self, entry: &str) -> Result<PathBuf, Error> {
        // Entry names must be absolute, e.g. "/My Bank". Strip the prefix to validate this & to
        // make the path relative for the next step. (This relies on the behavior of `strip_prefix`
        // to remove multiple leading slashes to ensure that `entry_path` ends up as a relative
        // path. This isn't documented, but the validation at the end of this function would catch
        // a path outside of `self.location` anyway.)
        let entry_path = match Path::new(entry).strip_prefix("/") {
            Ok(entry_path) => entry_path,
            Err(_) => return Err(anyhow!("Invalid entry name {entry}").into()),
        };

        // Produce the final filepath for this entry name.
        let path_buf = self
            .location
            .join(entry_path)
            .with_extension(FILE_EXTENSION);

        // Validate that the path is a subpath of the location to avoid path-traversal & return.
        if !path_buf.starts_with(&self.location)
            || path_buf.components().any(|c| c == Component::ParentDir)
        {
            return Err(anyhow!("Invalid entry name {entry}").into());
        }
        Ok(path_buf)
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid passphrase")]
    InvalidPassphrase,
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

#[cfg(test)]
mod tests {
    use super::{Error, Store, Vault};
    use crate::proto::secret::Key;
    use prost::Message as _;
    use sodiumoxide::crypto::secretbox;
    use std::{
        fs, io,
        path::{Path, PathBuf},
    };
    use tempfile::TempDir;

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
        assert!(matches!(
            vault.unlock(&incorrect_password).unwrap_err(),
            Error::InvalidPassphrase
        ));
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
        let dir = TempDir::with_prefix("harpoxide").unwrap();
        copy_dir_recursive("tests/assets/passwords.sbox", dir.path()).unwrap();
        let key = {
            let key_bytes = fs::read("tests/assets/key.sbox").unwrap();
            Key::decode(key_bytes.as_ref()).unwrap()
        };
        let vault = Vault::new(dir.as_ref(), key).unwrap();
        (vault, dir)
    }

    #[test]
    fn filename_for_entry() {
        let store = Store {
            location: PathBuf::from("/foo/bar"),
            key: secretbox::Key::from_slice(&[0; secretbox::KEYBYTES]).unwrap(), // key doesn't matter for this test
        };
        for (entry, want_filepath) in [
            ("/baz", Some("/foo/bar/baz.harp")),
            ("baz", None),
            ("/../baz", None),
            ("/baz/../quux", None),
            ("///baz", Some("/foo/bar/baz.harp")), // weird, but I'll take it for now
        ] {
            let rslt = store.filename_for_entry(entry);
            match &want_filepath {
                Some(want_filepath) => assert_eq!(
                    rslt.as_ref().unwrap(),
                    &PathBuf::from(want_filepath),
                    "entry: {:?} rslt: {:?}",
                    entry,
                    rslt
                ),
                None => assert!(rslt.is_err(), "entry: {:?} rslt: {:?}", entry, rslt),
            }
        }
    }

    fn copy_dir_recursive<U: AsRef<Path>, V: AsRef<Path>>(from: U, to: V) -> io::Result<()> {
        let mut stack = Vec::from([PathBuf::from(from.as_ref())]);

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
