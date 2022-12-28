use crate::secret;
use base64::display::Base64Display;
use rand::{distributions::Standard, prelude::Distribution, random, Rng};
use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::Display,
    sync::{Arc, Mutex},
};

// TODO: rustdoc
// TODO: session timeout
// TODO: authenticated-paths support
// TODO: MFA (webauthn) support
// TODO: rate-limiting of session creation

pub struct Handler {
    vault: secret::Vault,
    sessions: Mutex<HashMap<ID, Arc<Session>>>,
}

impl Handler {
    pub fn new(vault: secret::Vault) -> Handler {
        Handler {
            vault,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn new_session(&self, passphrase: &str) -> secret::Result<Arc<Session>> {
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

    pub fn get_session(&self, session_id: &ID) -> Option<Arc<Session>> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(session_id).map(Arc::clone)
    }

    pub fn close_session(&self, session_id: &ID) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(session_id);
    }
}

pub struct Session {
    id: ID,
    store: secret::Store,
}

impl Session {
    pub fn id(&self) -> &ID {
        &self.id
    }

    pub fn store(&self) -> &secret::Store {
        &self.store
    }
}

const ID_LENGTH: usize = 32;
const ENCODED_ID_LENGTH: usize = 43; // 4 * ceil(ID_LENGTH / 3)

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ID([u8; ID_LENGTH]);

impl ID {
    pub fn from_slice<T: AsRef<[u8]>>(s: T) -> Option<ID> {
        let s = s.as_ref();
        if s.len() != ENCODED_ID_LENGTH {
            return None;
        }
        let mut id = ID([0; ID_LENGTH]);
        if base64::decode_config_slice(s, base64::URL_SAFE_NO_PAD, &mut id.0[..]).is_err() {
            return None;
        }
        Some(id)
    }
}

impl Distribution<ID> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ID {
        ID(rng.gen())
    }
}

impl Display for ID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            Base64Display::with_config(&self.0, base64::URL_SAFE_NO_PAD)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::ID;
    use rand::random;

    #[test]
    fn id_generation() {
        assert_ne!(random::<ID>(), random::<ID>());
    }

    #[test]
    fn id_slice_conversion() {
        let id: ID = random();
        assert_eq!(ID::from_slice(id.to_string()), Some(id));
    }
}
