extern crate protoc_rust;

use std::fs;
use std::io::ErrorKind;

fn main() {
	let err = fs::remove_dir_all("src/proto");
	if let Err(ref e) = err {
		match e.kind() {
			ErrorKind::NotFound => (), // ignore not-found error
			_ => err.expect("Removing src/proto failed."),
		}
	}
	fs::create_dir_all("src/proto").expect("Creating src/proto failed.");

	protoc_rust::Codegen::new()
		.out_dir("src/proto")
		.inputs(&[
			"proto/harpd/config.proto",
			"proto/secret/entry.proto",
			"proto/secret/key.proto",
		])
		.include("proto")
		.customize(protoc_rust::Customize {
			gen_mod_rs: Some(true),
			..Default::default()
		})
		.run()
		.expect("Compiling protobufs failed.");
}
