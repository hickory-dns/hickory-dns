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
