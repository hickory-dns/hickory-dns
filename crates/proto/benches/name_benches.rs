#![feature(test)]

extern crate test;

use std::cmp::Ordering;

use test::Bencher;

use trust_dns_proto::rr::*;

#[bench]
fn name_cmp_short(b: &mut Bencher) {
    let name1 = Name::from_ascii("com").unwrap();
    let name2 = Name::from_ascii("COM").unwrap();

    b.iter(|| {
        assert_eq!(name1.cmp(&name2), Ordering::Equal);
    });
}

#[bench]
fn name_cmp_short_not_eq(b: &mut Bencher) {
    let name1 = Name::from_ascii("com").unwrap();
    let name2 = Name::from_ascii("COM").unwrap();

    b.iter(|| {
        assert_ne!(name1.cmp_case(&name2), Ordering::Equal);
    });
}

#[bench]
fn name_cmp_short_case(b: &mut Bencher) {
    let name1 = Name::from_ascii("com").unwrap();
    let name2 = Name::from_ascii("com").unwrap();

    b.iter(|| {
        assert_eq!(name1.cmp_case(&name2), Ordering::Equal);
    });
}

#[bench]
fn name_cmp_medium(b: &mut Bencher) {
    let name1 = Name::from_ascii("www.example.com").unwrap();
    let name2 = Name::from_ascii("www.EXAMPLE.com").unwrap();

    b.iter(|| {
        assert_eq!(name1.cmp(&name2), Ordering::Equal);
    });
}

#[bench]
fn name_cmp_medium_not_eq(b: &mut Bencher) {
    let name1 = Name::from_ascii("www.example.com").unwrap();
    let name2 = Name::from_ascii("www.EXAMPLE.com").unwrap();

    b.iter(|| {
        assert_ne!(name1.cmp_case(&name2), Ordering::Equal);
    });
}

#[bench]
fn name_cmp_medium_case(b: &mut Bencher) {
    let name1 = Name::from_ascii("www.example.com").unwrap();
    let name2 = Name::from_ascii("www.example.com").unwrap();

    b.iter(|| {
        assert_eq!(name1.cmp_case(&name2), Ordering::Equal);
    });
}

#[bench]
fn name_cmp_long(b: &mut Bencher) {
    let name1 = Name::from_ascii("a.crazy.really.long.example.com").unwrap();
    let name2 = Name::from_ascii("a.crazy.really.long.EXAMPLE.com").unwrap();

    b.iter(|| {
        assert_eq!(name1.cmp(&name2), Ordering::Equal);
    });
}

#[bench]
fn name_cmp_long_not_eq(b: &mut Bencher) {
    let name1 = Name::from_ascii("a.crazy.really.long.example.com").unwrap();
    let name2 = Name::from_ascii("a.crazy.really.long.EXAMPLE.com").unwrap();

    b.iter(|| {
        assert_ne!(name1.cmp_case(&name2), Ordering::Equal);
    });
}

#[bench]
fn name_cmp_long_case(b: &mut Bencher) {
    let name1 = Name::from_ascii("a.crazy.really.long.example.com").unwrap();
    let name2 = Name::from_ascii("a.crazy.really.long.example.com").unwrap();

    b.iter(|| {
        assert_eq!(name1.cmp_case(&name2), Ordering::Equal);
    });
}

#[bench]
fn name_to_lower_short(b: &mut Bencher) {
    let name1 = Name::from_ascii("COM").unwrap();

    b.iter(|| {
        let lower = name1.to_lowercase();
        assert_eq!(lower.num_labels(), 1);
    });
}

#[bench]
fn name_to_lower_medium(b: &mut Bencher) {
    let name1 = Name::from_ascii("example.COM").unwrap();

    b.iter(|| {
        let lower = name1.to_lowercase();
        assert_eq!(lower.num_labels(), 2);
    });
}

#[bench]
fn name_to_lower_long(b: &mut Bencher) {
    let name1 = Name::from_ascii("www.EXAMPLE.com").unwrap();

    b.iter(|| {
        let lower = name1.to_lowercase();
        assert_eq!(lower.num_labels(), 3);
    });
}

#[bench]
fn name_no_lower_short(b: &mut Bencher) {
    let name1 = Name::from_ascii("com").unwrap();

    b.iter(|| {
        let lower = name1.to_lowercase();
        assert_eq!(lower.num_labels(), 1);
    });
}

#[bench]
fn name_no_lower_medium(b: &mut Bencher) {
    let name1 = Name::from_ascii("example.com").unwrap();

    b.iter(|| {
        let lower = name1.to_lowercase();
        assert_eq!(lower.num_labels(), 2);
    });
}

#[bench]
fn name_no_lower_long(b: &mut Bencher) {
    let name1 = Name::from_ascii("www.example.com").unwrap();

    b.iter(|| {
        let lower = name1.to_lowercase();
        assert_eq!(lower.num_labels(), 3);
    });
}
