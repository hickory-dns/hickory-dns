# Summary

Add a conformance test suite to validate that `hickory-dns` adheres to the different DNSSEC RFCs. The test suite will let us measure implementation progress.

* The tests will check requirements laid out in RFC documents.
* The tests will be self-contained, that is they will not rely on internet access or external services.
* The tests will be of the "end-to-end" kind and will exercise interoperability with other DNS implementations like `unbound` and BIND.
* The correctness of the tests will be validated using a reference DNS implementation.

# Motivation

`hickory-dns` partially implements DNSSEC functionality and contains tests that exercise said functionality [[1]].

[1]: https://github.com/hickory-dns/hickory-dns/blob/a3669bd80f3f7b97f0c301c15f1cba6368d97b63/tests/integration-tests/tests/dnssec_client_handle_tests.rs

## Coverage and flaky tests

However, it's hard to determine from the existing tests how well covered the different requirements laid in the RFC documents are.

Furthermore, some of the tests are currently disabled (`#[ignore]`), part due the flakiness [[2]]. Others may be ignored to signal a bug or unimplemented feature but some ignored tests don't include an explanation of why they are ignored.

[2]: https://github.com/hickory-dns/hickory-dns/blob/a3669bd80f3f7b97f0c301c15f1cba6368d97b63/tests/integration-tests/tests/dnssec_client_handle_tests.rs#L34

## Dependency on external services, reliability

Some tests involve `hickory` interacting with an external services like public root servers (e.g. `a.root-servers.net`). Depending on external services reduces the reliability of the tests as the third-party service may have down times or may choose to rate limit clients that share the same IP address. More importantly, we have no insight into or control over the configuration of those external services; for example, a server may enable or disable DNSSEC support at any time. Depending on external services also means that internet connection is required to run the test suite.

## Potentially fallible assumptions

Some tests hard-code expectations on the outcome of querying external services [[3]], [[4]]. These tests can break due to circumstances outside the project's control, like `example.com` changing its underlying IP address or `none.example.com` becoming available.

[3]: https://github.com/hickory-dns/hickory-dns/blob/a3669bd80f3f7b97f0c301c15f1cba6368d97b63/tests/integration-tests/tests/dnssec_client_handle_tests.rs#L48-L67
[4]: https://github.com/hickory-dns/hickory-dns/blob/a3669bd80f3f7b97f0c301c15f1cba6368d97b63/tests/integration-tests/tests/dnssec_client_handle_tests.rs#L94-L99

Some tests involve `hickory` interacting with itself in a different role [[5]]. This approach can lead to a test passing even though both sides / roles are incorrectly implemented.

[5]: https://github.com/hickory-dns/hickory-dns/blob/a3669bd80f3f7b97f0c301c15f1cba6368d97b63/tests/integration-tests/tests/server_future_tests.rs#L73-L81

This proposal aims to produce a high reliability and high assurance test suite that will drive the DNSSEC implementation in `hickory-dns` to completion.

# Developer-facing changes 

## The `dns-test` API

**All the conformance tests will be written using the `dns-test` framework (library).**

- The library can spawn local, private IP networks and network nodes, acting in different DNS roles: resolver, name server and client.
- Most tests will involve setting up a small DNS network made up of a resolver server and a few authoritative-only name servers.
- The test input will usually be a DNS query to the resolver, or to a name server, and the outcome to check will be the response to that query.

### An example of a DNSSEC test

⚠️  *Note:  the API is not final and may be further tweaked*

``` rust
// no DS records are involved; this is a single-link chain of trust
#[test]
fn can_validate_without_delegation() -> Result<()> {
    let network = Network::new()?;

    // construct a zone file in the name server node
    let mut name_server = NameServer::new(dns_test::peer(), FQDN::ROOT, &network)?;
    name_server.add(Record::a(
        name_server.fqdn().clone(),
        name_server.ipv4_addr(),
    ));

    // sign the zone file
    let name_server = name_server.sign()?;

    // fetch name server's public keys
    let root_ksk = name_server.key_signing_key().clone();
    let root_zsk = name_server.zone_signing_key().clone();

    // complete name server set up
    let name_server = name_server.start()?;

    // start resolver node
    let root_hints = &[Root::new(
        name_server.fqdn().clone(),
        name_server.ipv4_addr(),
    )];
    let trust_anchor = TrustAnchor::from_iter([root_ksk.clone(), root_zsk.clone()]);
    let resolver = Resolver::start(dns_test::subject(), root_hints, &trust_anchor, &network)?;

    let client = Client::new(&network)?;

    // $ dig +adflag +recurse @$RESOLVER_ADDR SOA .
    let resolver_addr = resolver.ipv4_addr();
    let settings = *DigSettings::default().recurse().authentic_data();
    let output = client.dig(settings, resolver_addr, RecordType::SOA, &FQDN::ROOT)?;

    assert!(output.status.is_noerror());
    assert!(output.flags.authenticated_data);

    // $ delv -a $TRUST_ANCHOR @$RESOLVER_ADDR SOA .
    let output = client.delv(resolver_addr, RecordType::SOA, &FQDN::ROOT, &trust_anchor)?;
    assert!(output.starts_with("; fully validated"));

    Ok(())
}
```

This test creates a network with three nodes:

1. a name server authoritative over the `.` (root) zone
2. a resolver server
3. a client

Important things to note in the test:
- Queries are sent from the client node to the resolver and the outcomes of those queries are checked.
- The expectation is that the resolver is able to validate the single-link chain of trust as its trust anchor includes the public keys of the name server.
- The configuration is explicit and required, that is we do not rely on built-in settings like root hints or a pre-configured trust anchor.
- The test does not require internet access either.

### The `subject` and `peer` functions

- `dns_test::peer` and `dns_test::subject` are used to initialize the `NameServer` and the `Resolver`.
- These functions return an `Implementation` enum whose variants are: `hickory-dns`, `unbound` and `bind`.
- By default, both functions return `Implementation::Unbound` but their return values can be changed through the environment variables: `DNS_TEST_PEER` and `DNS_TEST_SUBJECT`.
- Each test must contain one node initialized with the `subject` implementation. This is the implementation that's being tested, that is the "test subject".
- All the other nodes in the network will usually be configured to use the `peer` implementation.

*This mechanism lets us switch the test subject without recompiling the test suite*.

This feature is vital to the development workflow, which will be covered in a later section. It's also possible to change the `peer` implementation at runtime to check interoperability with different DNS implementations.

### The `eavesdrop` API (using `tshark`)

Testing certain DNS RFC requirements need more observability than the just being to check the response to a DNS query. This is the case when testing the resolver which sends DNS queries to name servers on behalf of a client.

The `eavesdrop` API captures all the DNS messages going in and out of a network node and returns them in chronological order. Each message can then be inspected to check if it set certain flags, included the OPT pseudo-record, etc. as required by RFC documents.

A snippet that uses the `eavesdrop` API on the resolver is shown below:

``` rust
let resolver = Resolver::start(/* .. */)?;

// start capturing messages
let tshark = resolver.eavesdrop()?;

// perform query (blocking)
let response = client.dig(/* .. */)?;

// stop capture and return captured messages
let captures = tshark.terminate()?;

// check captures
let nameserver_addr = nameserver.ipv4_addr();
let client_addr = client.ipv4_addr();
for Captures { message, direction } in captures {
    if let Direction::Outgoing { destination } = direction {
        if destination == client_addr {
            // ignore response to client
            continue;
        }
        
        // RFC 4035 / section 4.1 / EDNS support
        assert!(message.is_do_bit_set());
        assert!(message.udp_payload_size() >= 1220);
    }
}
```

### Fault injection

The `sign` API used in the first example produces a correctly signed zone file. Tests that exercise non-secure scenarios may require that a name server responds with incorrectly signed records. To introduce this fault in the system, one can modify the records in the signed zone file.

An example of modifying records in the signed zone file is shown below:

``` rust
let mut nameserver = nameserver.sign()?;

// change the signature field of RRSIG records of interest
for record in &mut nameserver.signed_zone_file_mut().records {
    if let Record::RRSIG(rrsig) = record {
        if is_relevant(rrsig) {
            let mut signature = BASE64_STANDARD.decode(&rrsig.signature)?;
            let last = signature.last_mut().expect("empty signature");
            *last = !*last;

            rrsig.signature = BASE64_STANDARD.encode(&signature);
        }
    }
}
```

## `conformance-tests`

The conformance tests will live in a separate package called `conformance-tests`.

### Reference implementation

- `unbound` will be used as the reference DNS implementation.
- By default all tests will use the reference implementation as the test subject.
- Running tests against the reference implementation is done to validate that the tests themselves are correct.
- To run the tests against `hickory-dns` set the `DNS_TEST_SUBJECT` environment variable to `hickory /path/to/local/repository`.

⚠️ The framework will clone the specified local repository and build `hickory-dns` out of that fresh clone. This means that any change that has not been commited will *not* be included the `hickory-dns` build.

### Use of `#[ignore]` 

Tests that fail to pass with `hickory-dns` will be disabled using the `#[ignore]` attribute.

``` rust
#[ignore]
fn works_with_unbound_but_not_with_hickory() -> Result<()> {
    // ..
}
```

Note that *all* tests including the ignored ones must pass with the reference implementation (`unbound`) so check that the following Cargo invocation never breaks:

``` console
$ cargo test -- --include-ignored
```

### Test organization

The following file tree gives an overview of the module organization:

``` text
.
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
│  │  ├── scenarios
│  │  │  ├── bogus.rs
│  │  │  └── secure.rs
│  │  └── scenarios.rs
│  └── dnssec.rs
└── resolver.rs
```

#### Module hierarchy

Modules are used to organize tests:

1. The modules in the root correspond to the *role* being tested: `resolver` (recursive resolver), `name-server` (authoritative-only name server), etc.
2. The next module level contains the *functionality* being tested: (plain) DNS, DNSSEC, NSEC3, etc.
3. The next module level contains the RFC documents, whose requirements are being tested: RFC4035, etc.
4. The following module levels contain sections, subsections and any other subdivision that may be relevant.

This module organization makes it easy to map a unit test back to the RFC section that it exercises.

#### Ad-hoc `scenarios`

⚠️ Next to the RFC modules there's a special module called `scenarios`.

This module contains tests that map to representative use cases of the parent functionality.
Each use case can be tested in successful and failure *scenarios*, hence the name of the module.
The organization within this module will be ad hoc.

## GitHub Workflow 

### CI checks

The CI workflow will perform these checks:

- `cargo test -- --include-ignored`: must have 0 test failures. This test suite run uses the reference implementation and validates that the tests are correct.
- `DNS_SUBJECT_HICKORY="hickory /path/to/checked/out/hickory/source" cargo test` must have 0 test failures. This run serves as regressions tests for `hickory-dns`
- `DNS_SUBJECT_HICKORY="hickory /path/to/checked/out/hickory/source" cargo test -- --ignored` must have 0 *passing* tests. This ensures that tests fixed by a PR are re-enabled, i.e. that their `#[ignore]` attribute gets removed.

Contributors are encouraged to run the above three commands prior to submitting a pull request that modifies `hickory-dns` or the conformance test suite.

### Tracking failures

`#[ignore]`d tests in the conformance test suite must include a comment indicating the GitHub issue number that tracks the test failure:

``` rust
#[ignore = "gh1234"]
#[test]
fn currently_broken_with_hickory() -> Result<()> {
    // ..
}
```

GitHub issues can then group related test failures. 

This proposal does not suggest any particular grouping of test failures, e.g. by RFC section; the goal of using GitHub issues is to make the test failures visible. Issues tracking conformance test failures should, however, by grouped using a label, e.g. `nonconforming`. This is so that the issues are easy to find in the issue tracker.

Issues that each track multiple failures should make use of [task lists], where each item corresponds to a test failure. This makes it easier to assess progress from the issue tracker.

[task lists]: https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/about-task-lists

The ultimate measure of implementation progress is the percentage of passing tests when running the entire conformance test suite.

# Implementation details

## `dns-test`

The test framework internally uses one ephemeral Docker container for each network node. The framework also creates ephemeral Docker networks that are isolated from the internet and from each other. `Drop` implementations are used to remove containers and networks when a test finishes, regardless of whether the test passed or failed / panicked.

Should the need arise, the implementation can be modified to make unit tests reuse containers and networks from a fixed size pool. This would be a change in the implementation details that won't impact existing test code.

End users don't need to build Docker images nor start containers prior to running the test suite as the framework takes care of doing that. The only thing that needs to be done prior to running the test suite is to have the Docker service running.

The test framework has been shown to work on Linux and macOS machines as well as on GitHub Actions CI (`ubuntu-latest` worker).

## Integration into `hickory-dns`

Under this proposal, the `conformance-tests` and `dns-test` packages will first be developed out of tree and eventually be merged into the `hickory-dns` repository. At that point, `conformance-tests` can act as both regressions tests and issues (test failures) that need to be fixed.

# Drawbacks

Having more tests inevitably means longer CI times. The impact can be ameliorated by different means: 

- making the test framework more efficient, e.g. reuse containers and networks;
- making the execution of tests more efficient, e.g. skip running unchanged tests against the reference implementation which never changes;
- grouping pull requests using the [merge queue] to reduce the number of times full CI runs per day; etc.

[merge queue]: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue

# Rationale and alternatives

Instead of merging the `conformance-tests` and `dns-test` packages into the `hickory-dns` repository, the packages can be kept in a separate repository under the `hickory-dns` GitHub organization.
However, this means that instead of the `#[ignore]` attribute some other mechanism needs to be devised to track tests failures in the `hickory-dns` repository -- perhaps some sort of lock file.

Having the `conformance-tests` in its repository means that adding tests can be done without running `hickory-dns`'s CI workflow which is a more efficient use of CI time.
Note that the main proposal also has this advantage because `conforomance-tests` will be first developed *out of tree*, that is in its own repository.

# Prior art

This approach to testing where the test suite is also run against a third-party reference implementation has been used in the development of [sudo-rs], a Rust implementation of the `sudo` program. Although the original `sudo` lacks a specification, it was possible to derive conformance-like tests from its user manual and other documentation.

Being able to add tests for incomplete / unimplemented features generated test cases that greatly helped the people focused on implementing said features in sudo-rs. This also let more people work on the codebase in parallel: some folks focused on adding tests; while others focused on fixing bugs and adding and completing features. Being able to validate the tests against the original `sudo` also helped found several bugs in sudo-rs, specially in not well documented edge cases.

[sudo-rs]: https://github.com/memorysafety/sudo-rs

A write up about applying this testing approach to the sudo-rs project can be found in [this blog post][testing-sudo-rs].

[testing-sudo-rs]: https://ferrous-systems.com/blog/testing-sudo-rs/

# Future possibilities

Although the motivation of adding a test suite is testing DNSSEC functionality, the test framework and workflow can be used to test plain DNS functionality and non-RFC functionality like IP address allow and block lists.

The test framework can also be used to test that CVE that affect other implementations, like `unbound` and BIND, do not affect `hickory-dns`.

The test framework can be used as an exploratory tool. It can set up a local DNS network then a user can attach to any of the nodes and perform queries to learn more about DNS or inspect the name server and resolver logs to debug issues.

Being able to set up a local DNS network where it's easy to swap the implementation that powers one of the nodes could be useful for comparative benchmarking between implementations.
