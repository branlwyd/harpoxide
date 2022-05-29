#![allow(dead_code)] // TODO: remove, once everything is wired together

use crate::{proto::key::Key, secret::Vault};
use protobuf::{self, Message};
use std::fs::File;

mod config;
mod proto;
mod secret;
mod session;

fn main() {
    sodiumoxide::init().unwrap();

    let key = {
        let mut f = File::open("tests/assets/key.sbox").unwrap();
        Key::parse_from_reader(&mut f).unwrap()
    };
    let vault = Vault::new("tests/assets/passwords.sbox", key).unwrap();
    let store = vault.unlock("password").unwrap();
    for entry in store.list().unwrap() {
        println!("{}\n===\n{}===\n\n", entry, store.get(&entry).unwrap());
    }
}
