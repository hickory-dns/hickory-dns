# Generating Roots

The process for getting the current key-signing-key, ksk, roots is by means of a tool in `utils`. The tool can be run via `cargo run -p hickory-util --all-features --bin dns -- --nameserver 8.8.8.8:53 fetch-keys crates/proto/src/dnssec/roots`, it will output data that looks like this:

```console
$ cargo run -p hickory-util --all-features --bin dns -- --nameserver 8.8.8.8:53 fetch-keys crates/proto/src/dnssec/roots
   Compiling hickory-util v0.25.0-alpha.5 (/Users/benjaminfry/Development/rust/hickory-dns/util)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2.55s
     Running `target/debug/dns --nameserver '8.8.8.8:53' fetch-keys crates/proto/src/dnssec/roots`
; using udp:8.8.8.8:53
; querying . for key-signing-dnskeys, KSKs
; received response
; header 8971:RESPONSE:RD,RA:NoError:QUERY:3/0/1
; edns version: 0 dnssec_ok: false z_flags: 0 max_payload: 512 opts: 0
; query
;; . IN DNSKEY
; answers 3
. 20014 IN DNSKEY 257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=
. 20014 IN DNSKEY 256 3 8 AwEAAZ5A7jOztf62cGqhPhutjnyl7KBjIsjbyTb8il+FsgbMUbO2NQHaSbatHdlOlqANncDwSIKZ9ryqd1+Dy1PoGzeTUv95vOJnVVJHlJu7xdavnUmPs+Mh2NV7hDlTTwPn5uXgFxAaxoO9M/YIAC92GryCLjoJEg9JzeevkktEM/sFpmRv4I5jQtlLyRqVbnCzcWpi04XaVLxRKvURkd/Mdb/2RQS3MYvrkEBXuqtnAVBCf6Fx4sgBYOfYvbUuG2diLnGJW/MXvFpctZgQ76+3FwMqAZfR9k5bohL7AF3+jqz4MUiootYoh5koyt7VEnUULxxy6U5PINTGgOC26f3zZuk=
. 20014 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
; nameservers 0
; additionals 1

; found dnskey: 38696, RSASHA256, in Hickory TrustAnchor: false
; wrote dnskey 38696 to: crates/proto/src/dnssec/roots/38696.rsa
; found dnskey: 20326, RSASHA256, in Hickory TrustAnchor: true
; skipping key in TrustAnchor
```

The tags, represent key_tags, as generated when signing with keys and storing in RRSIG records. The keys will be output to `crates/proto/src/dnssec/roots/{key_tag}.{type}`, eg `crates/proto/src/dnssec/roots/20326.rsa`. See [https://www.icann.org/dns-resolvers-checking-current-trust-anchors](Checking the Current Trust Anchors in DNS Validating Resolvers) for additional help.

*WARNING* this does not verify the key, please verify with the URL from icann above.

Once generated, if a different path was used, copy the key to `proto/src/rr/dnssec/roots/` and then add to `proto/src/rr/dnssec/trust_anchor.rs`.

## FAQ

### Can't this be better?

Yes. We should get the signatures for these keys and verify them before adding them.