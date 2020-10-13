use std::fs::File;

use protobuf;
use sodiumoxide;

use crate::proto::key::Key;

mod proto;
mod secret;

fn main() {
	sodiumoxide::init().unwrap();

	let key: Key = {
		let mut f = File::open("key.sbox").unwrap();
		protobuf::parse_from_reader(&mut f).unwrap()
	};
	let vault = secret::new_vault("./passwords.sbox", key).unwrap();
	let store = vault.unlock("password").unwrap();
	for entry in store.list().unwrap() {
		println!("{}\n===\n{}===\n\n", entry, store.get(&entry).unwrap());
	}
}
