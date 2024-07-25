// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg(nightly)]
#![feature(test)]

extern crate test;

use std::str::FromStr;

use test::Bencher;

use hickory_proto::rr::{LowerName, Name};

#[bench]
fn name_cmp_short(b: &mut Bencher) {
    let name1 = LowerName::new(&Name::from_str("com").unwrap());
    let name2 = LowerName::new(&Name::from_str("COM").unwrap());

    b.iter(|| {
        assert_eq!(name1, name2);
    });
}

#[bench]
fn name_cmp_short_case(b: &mut Bencher) {
    let name1 = LowerName::new(&Name::from_str("com").unwrap());
    let name2 = LowerName::new(&Name::from_str("com").unwrap());

    b.iter(|| {
        assert_eq!(name1, name2);
    });
}

#[bench]
fn name_cmp_medium(b: &mut Bencher) {
    let name1 = LowerName::new(&Name::from_str("www.example.com").unwrap());
    let name2 = LowerName::new(&Name::from_str("www.EXAMPLE.com").unwrap());

    b.iter(|| {
        assert_eq!(name1, name2);
    });
}

#[bench]
fn name_cmp_medium_case(b: &mut Bencher) {
    let name1 = LowerName::new(&Name::from_str("www.example.com").unwrap());
    let name2 = LowerName::new(&Name::from_str("www.example.com").unwrap());

    b.iter(|| {
        assert_eq!(name1, name2);
    });
}

#[bench]
fn name_cmp_long(b: &mut Bencher) {
    let name1 = LowerName::new(&Name::from_str("a.crazy.really.long.example.com").unwrap());
    let name2 = LowerName::new(&Name::from_str("a.crazy.really.long.EXAMPLE.com").unwrap());

    b.iter(|| {
        assert_eq!(name1, name2);
    });
}

#[bench]
fn name_cmp_long_case(b: &mut Bencher) {
    let name1 = LowerName::new(&Name::from_str("a.crazy.really.long.example.com").unwrap());
    let name2 = LowerName::new(&Name::from_str("a.crazy.really.long.example.com").unwrap());

    b.iter(|| {
        assert_eq!(name1, name2);
    });
}
