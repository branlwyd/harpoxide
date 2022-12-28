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

    protobuf_codegen::Codegen::new()
        .out_dir("src/proto")
        .inputs([
            "proto/harpd/config.proto",
            "proto/secret/entry.proto",
            "proto/secret/key.proto",
        ])
        .include("proto")
        .customize(protobuf_codegen::Customize::default().gen_mod_rs(true))
        .run()
        .expect("Compiling protobufs failed.");
}
