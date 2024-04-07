fn main() {
    println!("cargo::rerun-if-changed=proto/");

    prost_build::compile_protos(
        &[
            "proto/harpd/config.proto",
            "proto/secret/entry.proto",
            "proto/secret/key.proto",
        ],
        &["proto"],
    )
    .expect("Compiling protobufs failed");
}
