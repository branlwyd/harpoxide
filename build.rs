extern crate protoc_rust;

use std::fs;

fn main() {
	fs::create_dir_all("src/proto/secret")
		.expect("Creating src/proto failed.");

	protoc_rust::Codegen::new()
		.out_dir("src/proto")
		.inputs(&[
			"proto/secret/entry.proto",
			"proto/secret/key.proto",
		])
		.include("proto")
		.customize(protoc_rust::Customize{
			gen_mod_rs: Some(true),
			..Default::default()
		})
		.run()
		.expect("Compiling protobufs failed.");
}
