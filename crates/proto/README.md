# Overview

`hickory-proto` is a safe and secure low-level DNS library.
This is the foundational DNS protocol library used by the other higher-level Hickory DNS crates.

Unless you want to manipulate the DNS packets directly, it is likely not the library you want.
For higher-level interfaces, refer to the [`hickory-server`], [`hickory-resolver`] library crates
instead.

[`hickory-net`]: ../net
[`hickory-server`]: ../server
[`hickory-resolver`]: ../resolver

## Cryptography provider

Features requiring cryptography require selecting a specific cryptography
provider. See the [project README] for more information.

[project README]: ../../README.md#Cryptography-provider

## DNSSEC

In order to use DNSSEC you must enable a cargo feature corresponding to your
desired cryptography provider:

* `dnssec-aws-lc-rs`
* `dnssec-ring`

## Other crate features

* `text-parsing` - support for reading text-based zone files.
* `serde` - enable serde serialization support.
* `std` - disable for no-std support.
* `no-std-rand` - enables a custom random function backed by a no_std compatible mutex.
* `mdns` (experimental) - enable experimental mDNS support.
* `wasm-bindgen` - support for WASM.
* `access-control` - enable data structures useful for blocklists and access control.
