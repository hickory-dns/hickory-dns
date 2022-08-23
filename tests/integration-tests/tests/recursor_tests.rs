// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Integration tests for the recursor. These integration tests setup scenarios to verify that the recursor is able
//!  to recursively resolve various real world scenarios. As new scenarios are discovered, they should be added here.

/// Tests a basic recursive resolution `a.recursive.test.` , `.` -> `test.` -> `recursive.test.` -> `a.recursive.test.`
///
/// There are three authorities needed for this test `.` which contains the `test` nameserver, `recursive.test` which is
///  target zone containing `a.recursive.test.`.
#[test]
fn test_basic_recursion() {
    // TBD
}
