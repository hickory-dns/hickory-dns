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
#![allow(clippy::dbg_macro, clippy::print_stdout)]

use super::*;
use crate::error::*;
use std::fmt::Debug;

fn get_character_data() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("", vec![0]),                      // base case, only the root
        ("a", vec![1, b'a']),               // a single 'a' label
        ("bc", vec![2, b'b', b'c']),        // two labels, 'a.bc'
        ("♥", vec![3, 0xE2, 0x99, 0xA5]), // two labels utf8, 'a.♥'
    ]
}

#[test]
fn read_character_data() {
    for (string, bytes) in get_character_data() {
        let mut decoder = BinDecoder::new(&bytes);
        assert_eq!(
            decoder.read_character_data().unwrap().unverified(),
            string.as_bytes()
        );
    }
}

#[test]
fn emit_character_data() {
    test_emit_data_set(get_character_data(), |ref mut e, d| {
        e.emit_character_data(&d)
    });
}

fn get_u16_data() -> Vec<(u16, Vec<u8>)> {
    vec![
        (0, vec![0x00, 0x00]),
        (1, vec![0x00, 0x01]),
        (256, vec![0x01, 0x00]),
        (u16::max_value(), vec![0xFF, 0xFF]),
    ]
}

#[test]
fn read_u16() {
    test_read_data_set(get_u16_data(), |mut d| {
        d.read_u16().map(Restrict::unverified).map_err(Into::into)
    });
}

#[test]
fn emit_u16() {
    test_emit_data_set(get_u16_data(), |ref mut e, d| e.emit_u16(d));
}

fn get_i32_data() -> Vec<(i32, Vec<u8>)> {
    vec![
        (0, vec![0x00, 0x00, 0x00, 0x00]),
        (1, vec![0x00, 0x00, 0x00, 0x01]),
        (256, vec![0x00, 0x00, 0x01, 0x00]),
        (256 * 256, vec![0x00, 0x01, 0x00, 0x00]),
        (256 * 256 * 256, vec![0x01, 0x00, 0x00, 0x00]),
        (-1, vec![0xFF, 0xFF, 0xFF, 0xFF]),
        (i32::min_value(), vec![0x80, 0x00, 0x00, 0x00]),
        (i32::max_value(), vec![0x7F, 0xFF, 0xFF, 0xFF]),
    ]
}

#[test]
fn read_i32() {
    test_read_data_set(get_i32_data(), |mut d| {
        d.read_i32().map(Restrict::unverified).map_err(Into::into)
    });
}

#[test]
fn emit_i32() {
    test_emit_data_set(get_i32_data(), |ref mut e, d| e.emit_i32(d));
}

#[allow(clippy::unreadable_literal)]
fn get_u32_data() -> Vec<(u32, Vec<u8>)> {
    vec![
        (0, vec![0x00, 0x00, 0x00, 0x00]),
        (1, vec![0x00, 0x00, 0x00, 0x01]),
        (256, vec![0x00, 0x00, 0x01, 0x00]),
        (256 * 256, vec![0x00, 0x01, 0x00, 0x00]),
        (256 * 256 * 256, vec![0x01, 0x00, 0x00, 0x00]),
        (u32::max_value(), vec![0xFF, 0xFF, 0xFF, 0xFF]),
        (2147483648, vec![0x80, 0x00, 0x00, 0x00]),
        (i32::max_value() as u32, vec![0x7F, 0xFF, 0xFF, 0xFF]),
    ]
}

#[test]
fn read_u32() {
    test_read_data_set(get_u32_data(), |mut d| {
        d.read_u32().map(Restrict::unverified).map_err(Into::into)
    });
}

#[test]
fn emit_u32() {
    test_emit_data_set(get_u32_data(), |ref mut e, d| e.emit_u32(d));
}

pub fn test_read_data_set<E, F>(data_set: Vec<(E, Vec<u8>)>, read_func: F)
where
    E: PartialEq<E> + Debug,
    F: Fn(BinDecoder<'_>) -> ProtoResult<E>,
{
    for (test_pass, (expect, binary)) in data_set.into_iter().enumerate() {
        println!("test {}: {:?}", test_pass, binary);

        let decoder = BinDecoder::new(&binary);
        assert_eq!(read_func(decoder).unwrap(), expect);
    }
}

pub fn test_emit_data_set<S, F>(data_set: Vec<(S, Vec<u8>)>, emit_func: F)
where
    F: Fn(&mut BinEncoder<'_>, S) -> ProtoResult<()>,
    S: Debug,
{
    for (test_pass, (data, expect)) in data_set.into_iter().enumerate() {
        println!("test {}: {:?}", test_pass, data);

        let mut bytes: Vec<u8> = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut bytes);
            emit_func(&mut encoder, data).unwrap();
        }
        assert_eq!(bytes, expect);
    }
}
