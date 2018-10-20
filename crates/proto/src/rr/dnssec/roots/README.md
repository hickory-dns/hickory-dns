# Generating Roots

The process for getting the current key-signing-key, ksk, roots is by means of a tool in `utils`. The tool can be run via `cargo run --bin get-root-ksks`, it will output data that looks like this:

```console
$ cargo run --bin get-root-ksks
   Compiling trust-dns-util v0.3.0-alpha.1 (file:///Users/benjaminfry/Development/rust/trust-dns/util)
    Finished dev [unoptimized + debuginfo] target(s) in 6.48s
     Running `/Users/benjaminfry/Development/rust/trust-dns/target/debug/get-root-ksks`
found: tag: 20326 info: DNSKEY { zone_key: true, secure_entry_point: true, revoke: false, algorithm: RSASHA256, public_key: [3, 1, 0, 1, 172, 255, 180, 9, 188, 201, 57, 248, 49, 247,161, 229, 236, 136, 247, 165, 146, 85, 236, 83, 4, 11, 228, 50, 2, 115, 144, 164, 206, 137, 109, 111, 144, 134, 243, 197, 225, 119, 251, 254, 17, 129, 99, 170, 236, 122, 241, 70, 44,71, 148, 89, 68, 196, 226, 192, 38, 190, 94, 152, 187, 205, 237, 37, 151, 130, 114, 225, 227, 224, 121, 197, 9, 77, 87, 63, 14, 131, 201, 47, 2, 179, 45, 53, 19, 177, 85, 11, 130, 105, 41, 200, 13, 208, 249, 44, 172, 150, 109, 23, 118, 159, 213, 134, 123, 100, 124, 63, 56, 2, 154, 189, 196, 129, 82, 235, 143, 32, 113, 89, 236, 197, 210, 50, 199, 193, 83, 124, 121, 244, 183, 172, 40, 255, 17, 104, 47, 33, 104, 27, 246, 214, 171, 165, 85, 3, 43, 246, 249, 240, 54, 190, 178, 170, 165, 179, 119, 141, 110, 235, 251, 166, 191, 158, 161, 145, 190, 74, 176, 202, 234, 117, 158, 47, 119, 58, 31, 144, 41, 199, 62, 203, 141, 87, 53, 185, 50, 29, 176, 133, 241, 184, 226, 216, 3, 143, 226, 148, 25, 146, 84, 140, 238, 13, 103, 221, 69, 71, 225, 29, 214, 58, 249, 201, 252, 28, 84, 102, 251, 104, 76, 240, 9, 215, 25, 124, 44, 247, 158, 121, 42, 181, 1, 230, 168, 161, 202, 81, 154, 242, 203, 155, 95, 99, 103, 233, 76, 13, 71, 80, 36, 81, 53, 123, 225, 181] }
found: tag: 19036 info: DNSKEY { zone_key: true, secure_entry_point: true, revoke: false, algorithm: RSASHA256, public_key: [3, 1, 0, 1, 168, 0, 32, 169, 85, 102, 186, 66, 232, 134, 187, 128, 76, 218, 132, 228, 126, 245, 109, 189, 122, 236, 97, 38, 21, 85, 44, 236, 144, 109, 33, 22, 208, 239, 32, 112, 40, 197, 21, 84, 20, 77, 254, 175, 231, 199, 203, 143, 0, 93, 209, 130, 52, 19, 58, 192, 113, 10, 129, 24, 44, 225, 253, 20, 173, 34, 131, 188, 131, 67, 95, 157, 242, 246, 49, 50, 81, 147, 26, 23, 109, 240, 218, 81, 229, 79, 66, 230, 4, 134, 13,251, 53, 149, 128, 37, 15, 85, 156, 197, 67, 196, 255, 213, 28, 190, 61, 232, 207, 208, 103, 25, 35, 127, 159, 196, 126, 231, 41, 218, 6, 131, 95, 164, 82, 232, 37, 233, 161, 142, 188, 46, 203, 207, 86, 52, 116, 101, 44, 51, 207, 86, 169, 3, 59, 205, 245, 217, 115, 18, 23, 151, 236, 128, 137, 4, 27, 110, 3, 161, 183, 45, 10, 115, 91, 152, 78, 3, 104, 115, 9, 51, 35, 36, 242, 124, 45, 186, 133, 233, 219, 21, 232, 58, 1, 67, 56, 46, 151, 75, 6, 33, 193, 142, 98, 94, 206, 201, 7, 87, 125, 158, 123, 173, 233, 82, 65, 168, 30, 187, 232, 169, 1, 212, 211, 39, 110, 64, 177, 20, 192, 162, 230, 252, 56, 209, 156, 46, 106, 171, 2, 100, 75, 40, 19, 245, 117, 252, 33, 96, 30, 13, 238, 73, 205, 158, 233, 106, 67, 16, 62, 82, 77, 98, 135, 61] }
```

The tags, represent key_tags, as generated when signing with keys and storing in RRSIG records. The current known key_tags are 20326 and 19036. The keys will be output to `/tmp/{key_tag}.{type}`, eg `/tmp/20326.rsa`. See [https://www.icann.org/dns-resolvers-checking-current-trust-anchors](Checking the Current Trust Anchors in DNS Validating Resolvers) for additional help.

Once generated, copy the key to `proto/src/rr/dnssec/roots/` and then add to `proto/src/rr/dnssec/trust_anchor.rs`.

## FAQ

### Can't this be better?

Yes. We should get the signatures for these keys and verify them before adding them.