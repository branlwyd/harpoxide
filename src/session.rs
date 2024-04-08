use crate::secret;
use anyhow::bail;
use base64::{display::Base64Display, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{distributions::Standard, prelude::Distribution, random, Rng};
use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::Display,
    str::FromStr,
    sync::{Arc, Mutex},
};

// TODO: rustdoc
// TODO: session timeout
// TODO: authenticated-paths support
// TODO: MFA (webauthn) support
// TODO: rate-limiting of session creation

pub struct Handler {
    vault: secret::Vault,
    sessions: Mutex<HashMap<Id, Arc<Session>>>,
}

impl Handler {
    pub fn new(vault: secret::Vault) -> Handler {
        Handler {
            vault,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn new_session(&self, passphrase: &str) -> Result<Arc<Session>, secret::Error> {
        let store = self.vault.unlock(passphrase)?;

        let mut sessions = self.sessions.lock().unwrap();
        loop {
            // Avoid conflicts on newly-allocated IDs.
            // This loop body is overwhelmingly likely to run only once per call to new_session.
            if let Entry::Vacant(v) = sessions.entry(random()) {
                let sess = Arc::new(Session {
                    id: v.key().clone(),
                    store,
                });
                v.insert(Arc::clone(&sess));
                return Ok(sess);
            }
        }
    }

    pub fn get_session(&self, session_id: &Id) -> Option<Arc<Session>> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(session_id).cloned()
    }

    pub fn close_session(&self, session_id: &Id) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(session_id);
    }
}

pub struct Session {
    id: Id,
    store: secret::Store,
}

impl Session {
    pub fn id(&self) -> &Id {
        &self.id
    }

    pub fn store(&self) -> &secret::Store {
        &self.store
    }
}

const ID_LENGTH: usize = 32;
const ENCODED_ID_LENGTH: usize = 43; // 4 * ceil(ID_LENGTH / 3)

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Id([u8; ID_LENGTH]);

impl FromStr for Id {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != ENCODED_ID_LENGTH {
            bail!("Incorrect length for ID");
        }
        let mut id_bytes = [0; ID_LENGTH];
        if URL_SAFE_NO_PAD.decode_slice(s, &mut id_bytes).is_err() {
            bail!("Bad encoding for ID");
        }
        Ok(Id(id_bytes))
    }
}

impl Distribution<Id> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Id {
        Id(rng.gen())
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Base64Display::new(&self.0, &URL_SAFE_NO_PAD))
    }
}

#[cfg(test)]
mod tests {
    use super::Id;
    use rand::random;
    use std::str::FromStr;

    #[test]
    fn id_generation() {
        assert_ne!(random::<Id>(), random::<Id>());
    }

    #[test]
    fn id_string_roundtrip() {
        let id: Id = random();
        assert_eq!(Id::from_str(&id.to_string()).unwrap(), id);
    }
}
