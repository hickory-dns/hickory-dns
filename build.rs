use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
  // write out a version file to link against for version information
  let out_dir = env::var("OUT_DIR").unwrap();
  let version = env::var("CARGO_PKG_VERSION").unwrap();
  let dest_path = Path::new(&out_dir).join("version.rs");
  let mut f = File::create(&dest_path).unwrap();


  f.write_all(b"pub fn version() -> &'static str {").unwrap();
  write!(f, " \"{}\" ", version).unwrap();
  f.write_all(b" }").unwrap();
}
