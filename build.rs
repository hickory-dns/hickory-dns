/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
