# Architecture of Hickory DNS

The Hickory DNS libraries are built from the ground up to be asynchronous. This project grew from first using non-blocking IO interfaces (before Futures 0.1 or async/await had landed in Rust). There are some artifacts of this history sporadically left around the project. Please feel free to submit PRs that clean up areas that still have hand-written Futures based state-machines. Additionally, much of the project was written by @bluejekyll while he learned the Rust language–this means that there may be patterns or missing common implementations in places where he didn't know better. Feel free to clean that up if you feel open to submitting a PR.

## Layout

Most of the project is in the form of crates. The crates are all individually published to crates.io.

The project has these high-level crates (to be used as dependencies in other projects):

- **[hickory-resolver](crates/resolver)** - implements a stub-resolver with support for CNAME chasing and other things, abstract over runtimes (Tokio supported by default)
- **[hickory-client](crates/client)** - a bare-bones client crate, most useful for dynamic DNS updates
- **[hickory-server](crates/server)** - implements support for hosted Authorities of various types
- **tokio-resolver** - (under consideration, currently Tokio support is directly in hickory-resolver)

Low-level crates supporting the above high-level crates:

- **[hickory-proto](crates/proto)** - the lowest level crate, implements the basics of DNS

Binaries:

- **[hickory-dns](bin/)** - server binary, `hickory-dns`, for hosting authorities, zones, and/or setting up a forwarder
- **[hickory-util](util/)** - helpful utilities, e.g. `resolve` for a CLI resolver, as well as some DNSSEC utilities

Old and Outdated crates:

- **[async-std-resolver](crates/async-std-resolver)** - removed in favor of features in hickory-resolver in 0.25.0
- **[trust-dns-*](https://github.com/bluejekyll/trust-dns/tree/v0.23.1/)** - removed in favor of features in hickory-proto, crate in [v0.24.0](https://github.com/hickory-dns/hickory-dns/tree/v0.24.0)
- **[trust-dns-rustls](https://github.com/bluejekyll/trust-dns/tree/v0.21.0/crates/rustls)** - removed in favor of features in hickory-proto, crate in [v0.21.0](https://github.com/hickory-dns/hickory-dns/tree/v0.21.0)
- **[trust-dns-openssl](https://github.com/bluejekyll/trust-dns/tree/v0.21.0/crates/openssl)** - removed in favor of features in hickory-proto, crate in [v0.21.0](https://github.com/hickory-dns/trust-dns/tree/v0.21.0)
- **[trust-dns-native-tls](https://github.com/bluejekyll/trust-dns/tree/v0.21.0/crates/native-tls)** - removed in favor of features in hickory-proto, crate in [v0.21.0](https://github.com/hickory-dns/trust-dns/tree/v0.21.0)
- **[trust-dns-https](https://github.com/bluejekyll/trust-dns/tree/v0.21.0/crates/https)** - removed in favor of features in hickory-proto, crate in [v0.21.0](https://github.com/hickory-dns/trust-dns/tree/v0.21.0)

## TBD

More on general patterns used in each library
