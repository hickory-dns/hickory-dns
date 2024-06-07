# `dnssec-tests`

This repository contains two packages:

- `dns-test`. This is a test framework (library) for testing DNS implementations.
- `conformance-tests`. This is a collection of DNS, mainly DNSSEC, tests.

## Requirements

To use the code in this repository you need:

- a stable Rust toolchain to build the code
- a working Docker setup that can run *Linux* containers -- the host OS does not need to be Linux 

## `dns-test`

This test framework was built with the following design goals and constraints in mind:

- Tests must work without access to the internet. That is, tests cannot rely on external services like `1.1.1.1`, `8.8.8.8`, `a.root-servers.net.`, etc. To this effect, each test runs into its own ephemeral network isolated from the internet and from the networks of other tests running concurrently.

- Test code must be decoupled from the API of any DNS implementation. That is, DNS implementation specific details (library/FFI calls, configuration files) must not appear in test code. To this end, interaction with DNS implementations is done at the network level using tools like `dig`, `delv` and `tshark`.

- It must be possible to switch the 'implementation under test' at runtime. In other words, one should not need to recompile the tests to switch the DNS implementation being tested. To this end, the `DNS_TEST_SUBJECT` environment variable is used to switch the DNS implementation that'll be tested.

### Test drive

To start a small DNS network using the `dns-test` framework run this command and follow the instructions to interact with the DNS network.

``` console
$ cargo run --example explore
```

By default, this will use `unbound` as the resolver. You can switch the resolver to `hickory-dns` using the `DNS_TEST_SUBJECT` environment variable:

``` shell
$ DNS_TEST_SUBJECT="hickory https://github.com/hickory-dns/hickory-dns" cargo run --example explore
```

### Environment variables

- `DNS_TEST_SUBJECT`. This variable controls what the `dns_test::subject` function returns. The variable can contain one of these values:
  - `unbound`
  - `hickory $REPOSITORY`. where `$REPOSITORY` is a placeholder for git repository. Examples values for `$REPOSITORY`: `https://github.com/hickory-dns/hickory-dns`; `/home/user/git-repos/hickory-dns`. NOTE: when using a local repository, changes that have not been committed, regardless of whether they are staged or not, will **not** be included in the `hickory-dns` build.
  
- `DNS_TEST_VERBOSE_DOCKER_BUILD`. Setting this variable prints the output of the `docker build` invocations that the framework does to the console. This is useful to verify that image caching is working; for example if you set `DNS_TEST_SUBJECT` to a local `hickory-dns` repository then consecutively running the `explore` example and/or `conformance-tests` test suite **must** not rebuild `hickory-dns` provided that you have not *committed* any new change to the local repository.

### Automatic clean-up

`dns-test` has been designed to clean up, that is remove, the Docker containers and Docker networks that it creates.
If you use `dns-test` and it does not clean up Docker resources, that's a bug that should be reported.

`dns-test` uses destructors (the `Drop` trait) to clean up resources.
If you forcefully terminate a process, e.g. using Ctrl+C or a signal like SIGINT, that uses `dns-test` then the destructors won't run and Docker resources won't be cleaned up.

Note that `cargo watch` terminates the last process using signals before starting a new instance of it.
Therefore we advise against using `cargo watch` to *run* tests that use the `dns-test` framework;
using `cargo-watch` to `check` such tests is perfectly fine, however.

### Writing tests

Here are some considerations when writing tests.

- Both `unbound` and BIND, in the resolver role, will initially query for the A record of their configured root server's FQDN as well as the A records of all the name servers covering the zones required to resolve the root server's FQDN. As of [49c89f7], All the name servers have a FQDN of the form `primaryNNN.nameservers.com.`, where `NNN` is a non-negative integer. These initial `A primaryNNN.nameservers.com.` queries will be sent to the name server that covers the `nameservers.com.` zone. What all this means in practice, is that you'll need to add these A records -- the root server's, `com.`'s name server and `nameservers.com.`'s name server -- to the `nameservers.com.` zone file; if you don't, most queries (expect perhaps for `SOA .`) will fail to resolve with return code SERVFAIL.

[49c89f7]: https://github.com/ferrous-systems/dnssec-tests/commit/49c89f764ede89aefe578b799e7766f051a600cc

``` rust
let root_ns: NameServer;        // for `.` zone
let com_ns: NameServer;         // for `com.` zone
let nameservers_ns: NameServer; // for `nameservers.com.` zone

nameservers_ns
    .add(root_ns.a())
    .add(com_ns.a());

// each `NameServer` will start out with an A record of its FQDN to its own IPv4 address in its
// zone file so NO need to add that one in the preceding statement
```

- To get resolution to work, you need referrals -- in the form of NS and A record pairs -- from parent zones to child zones. Check the [`dns::scenarios::can_resolve`] for an example of how to set up referrals.

[`dns::scenarios::can_resolve`]: https://github.com/ferrous-systems/dnssec-tests/blob/49c89f764ede89aefe578b799e7766f051a600cc/packages/conformance-tests/src/resolver/dns/scenarios.rs#L10

- To get DNSSEC validation to work, you need the DS record of the child zone in the parent zone. Furthermore, the DS record needs to be signed using parent zone's key. Check the [`dnssec::scenarios::secure::can_validate_with_delegation`] for an example of how to set up the DS records.

[`dnssec::scenarios::secure::can_validate_with_delegation`]: https://github.com/ferrous-systems/dnssec-tests/blob/49c89f764ede89aefe578b799e7766f051a600cc/packages/conformance-tests/src/resolver/dnssec/scenarios/secure.rs#L48

- You can get the logs of both a `Resolver` and `NameServer` using the `terminate` method. This method terminates the server and returns all the logs. This can be useful when trying to figure out why a query is not producing the expected results.

``` rust
let resolver: Resolver;

let ans = client.dig(/* .. */);

let logs = resolver.terminate()?;

// print the logs to figure out ...
eprintln!("{logs}");

// ... why this assertion is not working
assert!(ans.status.is_noerror());
```

## `conformance-tests`

This is a collection of tests that check the conformance of a DNS implementation to the different RFCs around DNS and DNSSEC.

### Running the test suite

To run the conformance tests against `unbound` run:

``` console
$ cargo test -p conformance-tests -- --include-ignored
```

To run the conformance tests against `hickory-dns` run:

``` console
$ DNS_TEST_SUBJECT="hickory /path/to/repository" cargo test -p conformance-tests
```

### Test organization

The module organization is not yet set in stone but currently uses the following structure:

``` console
packages/conformance-tests/src
├── lib.rs
├── resolver
│  ├── dns
│  │  └── scenarios.rs
│  ├── dns.rs
│  ├── dnssec
│  │  ├── rfc4035
│  │  │  ├── section_4
│  │  │  │  └── section_4_1.rs
│  │  │  └── section_4.rs
│  │  ├── rfc4035.rs
│  │  └── scenarios.rs
│  └── dnssec.rs
└── resolver.rs
```

The modules in the root correspond to the *role* being tested: `resolver` (recursive resolver), `name-server` (authoritative-only name server), etc.

The next module level contains the *functionality* being tested: (plain) DNS, DNSSEC, NSEC3, etc.

The next module level contains the RFC documents, whose requirements are being tested: RFC4035, etc.

The next module levels contain sections, subsections and any other subdivision that may be relevant.

At the RFC module level there's a special module called `scenarios`. This module contains tests that map to representative use cases of the parent functionality. Each use case can be tested in successful and failure scenarios, hence the name. The organization within this module will be ad hoc.

### Adding tests and the use of `#[ignore]`

When adding a new test to the test suite, it must pass with the `unbound` implementation, which is treated as the *reference* implementation. The CI workflow will check that *all* tests, including the ones that have the `#[ignore]` attribute, pass with the `unbound` implementation.

New tests that don't pass with the `hickory-dns` implementation must be marked as `#[ignore]`-d. The CI workflow will check that non-`#[ignore]`-d tests pass with the `hickory-dns` implementation. Additionally, the CI workflow will check that all `#[ignore]`-d tests *fail* with the `hickory-dns` implementation; this is to ensure that fixed tests get un-`#[ignore]`-d.

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.
