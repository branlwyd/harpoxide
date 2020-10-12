use protobuf::Message;
use sodiumoxide;

mod proto;
mod secret;

fn main() {
	sodiumoxide::init().unwrap();

	let mut secretbox_key = proto::key::SecretboxKey::new();
	secretbox_key.n = 11;
	secretbox_key.r = 21;
	secretbox_key.p = 31;

	let mut key = proto::key::Key::new();
	key.set_secretbox_key(secretbox_key);

	let mut vec = Vec::<u8>::new();
	let mut stream = protobuf::CodedOutputStream::vec(&mut vec);
	key.write_to(&mut stream)
		.expect("Couldn't write key to stream");
	stream.flush().expect("Couldn't flush stream to vec");

	println!("Hello, harpoxide!");
	println!("key = {:?}", vec)
}
