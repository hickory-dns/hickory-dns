#![feature(test)]

extern crate test;
extern crate trust_dns_proto;

use std::cmp::Ordering;
use std::str::FromStr;

use test::Bencher;

use trust_dns_proto::rr::*;

#[bench]
fn name_cmp_short(b: &mut Bencher) {
    let name1 = Name::from_str("com").unwrap();
    let name2 = Name::from_str("COM").unwrap();

    b.iter(|| {
        assert_eq!(name1.cmp_with_case(&name2, true), Ordering::Equal);
    });
}

#[bench]
fn name_cmp_short_not_eq(b: &mut Bencher) {
    let name1 = Name::from_str("com").unwrap();
    let name2 = Name::from_str("COM").unwrap();

    b.iter(|| {
        assert_ne!(name1.cmp_with_case(&name2, false), Ordering::Equal);
    });
}

#[bench]
fn name_cmp_short_case(b: &mut Bencher) {
    let name1 = Name::from_str("com").unwrap();
    let name2 = Name::from_str("com").unwrap();

    b.iter(|| {
        assert_eq!(name1.cmp_with_case(&name2, false), Ordering::Equal);
    });
}

#[bench]
fn name_cmp_medium(b: &mut Bencher) {
    let name1 = Name::from_str("www.example.com").unwrap();
    let name2 = Name::from_str("www.EXAMPLE.com").unwrap();

    b.iter(|| {
        assert_eq!(name1.cmp_with_case(&name2, true), Ordering::Equal);
    });
}

#[bench]
fn name_cmp_medium_not_eq(b: &mut Bencher) {
    let name1 = Name::from_str("www.example.com").unwrap();
    let name2 = Name::from_str("www.EXAMPLE.com").unwrap();

    b.iter(|| {
        assert_ne!(name1.cmp_with_case(&name2, false), Ordering::Equal);
    });
}

#[bench]
fn name_cmp_medium_case(b: &mut Bencher) {
    let name1 = Name::from_str("www.example.com").unwrap();
    let name2 = Name::from_str("www.example.com").unwrap();

    b.iter(|| {
        assert_eq!(name1.cmp_with_case(&name2, false), Ordering::Equal);
    });
}

#[bench]
fn name_cmp_long(b: &mut Bencher) {
    let name1 = Name::from_str("a.crazy.really.long.example.com").unwrap();
    let name2 = Name::from_str("a.crazy.really.long.EXAMPLE.com").unwrap();

    b.iter(|| {
        assert_eq!(name1.cmp_with_case(&name2, true), Ordering::Equal);
    });
}

#[bench]
fn name_cmp_long_not_eq(b: &mut Bencher) {
    let name1 = Name::from_str("a.crazy.really.long.example.com").unwrap();
    let name2 = Name::from_str("a.crazy.really.long.EXAMPLE.com").unwrap();

    b.iter(|| {
        assert_ne!(name1.cmp_with_case(&name2, false), Ordering::Equal);
    });
}

#[bench]
fn name_cmp_long_case(b: &mut Bencher) {
    let name1 = Name::from_str("a.crazy.really.long.example.com").unwrap();
    let name2 = Name::from_str("a.crazy.really.long.example.com").unwrap();

    b.iter(|| {
        assert_eq!(name1.cmp_with_case(&name2, false), Ordering::Equal);
    });
}
