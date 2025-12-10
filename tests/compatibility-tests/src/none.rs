use super::*;

#[cfg_attr(feature = "bind", allow(unreachable_pub))]
pub fn named_process() -> (NamedProcess, u16) {
    panic!("enable the desired tests with '--no-default-features --features=bind'")
}
