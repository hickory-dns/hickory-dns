fn main() {
    if std::env::var("CARGO_FEATURE_DNSTAP").is_ok() {
        println!("cargo:rerun-if-changed=proto/dnstap.proto");
        prost_build::Config::new()
            .btree_map(["."])
            .compile_protos(&["proto/dnstap.proto"], &["proto"])
            .expect("Failed to compile dnstap proto files");
    }
}
