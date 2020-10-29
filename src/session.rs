use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rand::{thread_rng, Rng};

use crate::secret;

// TODO: rustdoc
// TODO: session timeout
// TODO: authenticated-paths support
// TODO: MFA (webauthn) support
// TODO: rate-limiting of session creation
// TODO: ID base64 support (display trait? also need to parse from base64)

pub struct Handler {
    vault: secret::Vault,
    sessions: Mutex<HashMap<ID, Arc<Session>>>,
}

impl Handler {
    pub fn new(vault: secret::Vault) -> Handler {
        Handler {
            vault: vault,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn new_session(&self, passphrase: &str) -> secret::Result<Arc<Session>> {
        let store = self.vault.unlock(passphrase)?;

        let mut sessions = self.sessions.lock().unwrap();
        loop {
            // Avoid conflicts on newly-allocated IDs.
            // This loop body is overwhelmingly likely to run only once per call to new_session.
            if let Entry::Vacant(v) = sessions.entry(ID::new()) {
                let sess = Arc::new(Session {
                    id: v.key().clone(),
                    store: store,
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

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ID([u8; ID_LENGTH]);

impl ID {
    fn new() -> ID {
        ID(thread_rng().gen::<[u8; ID_LENGTH]>())
    }

    pub fn from_slice(s: &[u8]) -> Option<ID> {
        if s.len() != ID_LENGTH {
            return None;
        }
        let mut id = ID([0; ID_LENGTH]);
        id.0.copy_from_slice(s);
        Some(id)
    }
}
