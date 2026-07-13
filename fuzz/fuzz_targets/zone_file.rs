#![no_main]
use libfuzzer_sys::fuzz_target;

use hickory_proto::serialize::txt::Parser;

fuzz_target!(|data: &str| {
    let _ = Parser::new(data, None, None).parse();
});
