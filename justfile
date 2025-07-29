## Script for executing commands for the project.
export TARGET_DIR := join(justfile_directory(), "target")
export TDNS_BIND_PATH := join(TARGET_DIR, "bind")
export TEST_DATA := join(join(justfile_directory(), "tests"), "test-data")

NIGHTLY_DATE := "2025-01-19"

## MSRV
MSRV := env_var_or_default('MSRV', "")

## Code coverage config
COV_RUSTFLAGS := "-C instrument-coverage -C llvm-args=--instrprof-atomic-counter-update-all --cfg=coverage --cfg=trybuild_no_target"
COV_CARGO_INCREMENTAL := "0"
COV_CARGO_LLVM_COV := "1"
COV_CARGO_LLVM_COV_TARGET_DIR := join(TARGET_DIR, "llvm-cov-target")
COV_LLVM_PROFILE_FILE := join(COV_CARGO_LLVM_COV_TARGET_DIR, "hickory-dns-%p-%m_%c.profraw")
COV_OUTPUT_DIR := join(justfile_directory(), "coverage")

BIND_VER := "9.16.41"

# Check, build, and test all crates with default features enabled
default feature='' ignore='': (check feature ignore) (build feature ignore) (test feature ignore)

# Check, build, and test all crates with all-features enabled
all-features: (default "--all-features")

# Check, build, and test all crates with no-default-features
no-default-features: (default "--no-default-features" "--ignore=\\{hickory-compatibility\\}")

# Check, build, and test all crates with no-default-features, but with std features enabled
std: (default "--no-default-features" "--ignore=\\{hickory-compatibility,hickory-proto\\}")
    cargo {{MSRV}} test --locked --package hickory-proto --no-default-features --features="std"

# Check, build, and test all crates with tls-aws-lc-rs enabled
tls-aws-lc-rs: (default "--features=tls-aws-lc-rs" "--ignore=\\{hickory-compatibility,test-support\\}")

# Check, build, and test all crates with https-aws-lc-rs enabled
https-aws-lc-rs: (default "--features=https-aws-lc-rs" "--ignore=\\{hickory-compatibility,test-support\\}")

# Check, build, and test all crates with quic-aws-lc-rs enabled
quic-aws-lc-rs: (default "--features=quic-aws-lc-rs" "--ignore=\\{hickory-compatibility,test-support\\}")

# Check, build, and test all crates with h3-aws-lc-rs enabled
h3-aws-lc-rs: (default "--features=h3-aws-lc-rs" "--ignore=\\{hickory-compatibility,hickory-client,test-support\\}")

# Check, build, and test all crates with tls-ring enabled
tls-ring: (default "--features=tls-ring" "--ignore=\\{hickory-compatibility,test-support\\}")

# Check, build, and test all crates with https-ring enabled
https-ring: (default "--features=https-ring" "--ignore=\\{hickory-compatibility,test-support\\}")

# Check, build, and test all crates with quic-ring enabled
quic-ring: (default "--features=quic-ring" "--ignore=\\{hickory-compatibility,test-support\\}")

# Check, build, and test all crates with h3-ring enabled
h3-ring: (default "--features=h3-ring" "--ignore=\\{hickory-compatibility,hickory-client,test-support\\}")

# Check, build, and test all crates with dnssec-aws-lc-rs enabled
dnssec-aws-lc-rs: (default "--features=dnssec-aws-lc-rs" "--ignore=\\{hickory-compatibility,test-support\\}")

# Check, build, and test all crates with dnssec-ring enabled
dnssec-ring: (default "--features=dnssec-ring" "--ignore=\\{hickory-compatibility,test-support\\}")

# Run check on all projects in the workspace
check feature='' ignore='':
    cargo ws exec {{ignore}} cargo {{MSRV}} check --locked --all-targets {{feature}}
    cargo {{MSRV}} check --manifest-path fuzz/Cargo.toml --locked --all-targets

# Run build on all projects in the workspace
build feature='' ignore='':
    cargo ws exec {{ignore}} cargo {{MSRV}} build --locked --all-targets {{feature}}

# Run tests on all projects in the workspace
test feature='' ignore='':
    cargo ws exec {{ignore}} cargo {{MSRV}} test --locked --all-targets {{feature}}

doc feature='':
    cargo ws exec --ignore=hickory-dns cargo {{MSRV}} test --locked --doc {{feature}}

test-docs:
    RUSTDOCFLAGS="-Dwarnings" cargo ws exec cargo doc --locked --all-features --no-deps --document-private-items

# This tests compatibility with BIND9, TODO: support other feature sets besides openssl for tests
[unix]
compatibility: init-bind9
    RUST_LOG=debug cargo test --manifest-path tests/compatibility-tests/Cargo.toml --locked --all-targets --no-default-features --features=none;
    RUST_LOG=debug cargo test --manifest-path tests/compatibility-tests/Cargo.toml --locked --all-targets --no-default-features --features=bind;

# Build all bench marking tools, i.e. check that they work, but don't run
build-bench:
    RUSTFLAGS="--cfg=nightly" cargo ws exec cargo +nightly-{{NIGHTLY_DATE}} check --locked --benches

[private]
clippy-inner feature='':
    cargo ws exec cargo {{MSRV}} clippy --locked --all-targets {{feature}} -- -D warnings

# Run clippy on all targets and all sources
clippy:
    just clippy-inner --no-default-features
    just clippy-inner
    just clippy-inner --all-features
    cargo clippy --manifest-path fuzz/Cargo.toml --locked --all-targets -- -D warnings

# Check the format of all the Rust code with rustfmt
fmt:
    cargo ws exec cargo fmt -- --check
    cargo fmt --manifest-path fuzz/Cargo.toml -- --check

# Audit all depenedencies
audit: init-audit (check '--all-features')
    cargo audit --deny warnings
    cargo audit --file fuzz/Cargo.lock --deny warnings

# Task to run clippy, rustfmt, and audit on all crates
cleanliness: clippy fmt audit

# Generate coverage report
coverage: init-llvm-cov
    #!/usr/bin/env bash
    set -euxo pipefail

    export RUSTFLAGS="{{COV_RUSTFLAGS}}"
    export CARGO_LLVM_COV={{COV_CARGO_LLVM_COV}}
    export CARGO_LLVM_COV_TARGET_DIR={{COV_CARGO_LLVM_COV_TARGET_DIR}}
    export LLVM_PROFILE_FILE={{COV_LLVM_PROFILE_FILE}}

    echo $RUSTFLAGS

    cargo +nightly llvm-cov clean --workspace
    mkdir -p {{COV_OUTPUT_DIR}}

    # --no-cfg-coverage-nightly added while waiting for #[coverage] stabilization.
    # See: https://github.com/rust-lang/rust/issues/84605
    cargo +nightly llvm-cov test --workspace --no-report --all-targets --all-features --no-cfg-coverage-nightly
    cargo +nightly llvm-cov test --workspace --no-report --doc --doctests --all-features --no-cfg-coverage-nightly
    cargo +nightly llvm-cov report --doctests --codecov --output-path {{join(COV_OUTPUT_DIR, "hickory-dns-coverage.json")}}

# Open the html view of the coverage report
coverage-html: coverage
    #!/usr/bin/env bash
    set -euxo pipefail

    export RUSTFLAGS="{{COV_RUSTFLAGS}}"
    export CARGO_LLVM_COV={{COV_CARGO_LLVM_COV}}
    export CARGO_LLVM_COV_TARGET_DIR={{COV_CARGO_LLVM_COV_TARGET_DIR}}
    export LLVM_PROFILE_FILE={{COV_LLVM_PROFILE_FILE}}

    cargo +nightly llvm-cov report --doctests --html --open --output-dir {{COV_OUTPUT_DIR}}

# Export coverage data in lcov format
coverage-lcov: coverage
    #!/usr/bin/env bash
    set -euxo pipefail

    export RUSTFLAGS="{{COV_RUSTFLAGS}}"
    export CARGO_LLVM_COV={{COV_CARGO_LLVM_COV}}
    export CARGO_LLVM_COV_TARGET_DIR={{COV_CARGO_LLVM_COV_TARGET_DIR}}
    export LLVM_PROFILE_FILE={{COV_LLVM_PROFILE_FILE}}

    cargo +nightly llvm-cov report --doctests --lcov --output-path {{join(COV_OUTPUT_DIR, "lcov.info")}}

# (Re)generates Test Certificates, if tests are failing, this needs to be run yearly
[unix]
generate-test-certs: init-openssl
    cd {{TEST_DATA}} && rm -f ca.key ca.pem cert.key cert-key.pkcs8 cert.csr cert.pem cert.p12
    scripts/gen_certs.sh
    cd {{TEST_DATA}}/test_configs/sec && rm -f example.key example.key.pem example.cert example.cert.pem example.p12
    cd {{TEST_DATA}}/test_configs/sec && ./gen-keys.sh

# Publish all crates
publish:
    cargo ws publish --publish-as-is --no-remove-dev-deps --token $CRATES_IO_TOKEN

# Removes the target directories cleaning all built artifacts
clean:
    rm -rf {{TARGET_DIR}}
    rm -rf {{join(justfile_directory(), "conformance/target")}}
    rm -rf {{join(justfile_directory(), "tests/e2e-tests/target")}}
    rm -rf {{join(justfile_directory(), "tests/ede-dot-com/target")}}
    rm -rf {{join(justfile_directory(), "fuzz/target")}}

# runs all other conformance-* tasks
conformance: (conformance-framework) (conformance-unbound) (conformance-bind) (conformance-hickory) (conformance-ignored) (conformance-clippy) (conformance-fmt)

# tests the conformance test framework
conformance-framework:
    DNS_TEST_VERBOSE_DOCKER_BUILD=1 cargo t --manifest-path conformance/Cargo.toml -p dns-test

# runs the conformance test suite against unbound
conformance-unbound filter='':
    DNS_TEST_VERBOSE_DOCKER_BUILD=1 DNS_TEST_PEER=bind DNS_TEST_SUBJECT=unbound cargo t --manifest-path conformance/Cargo.toml -p conformance-tests -- --include-ignored {{filter}}

# runs the conformance test suite against BIND
conformance-bind filter='':
    DNS_TEST_VERBOSE_DOCKER_BUILD=1 DNS_TEST_PEER=unbound DNS_TEST_SUBJECT=bind cargo t --manifest-path conformance/Cargo.toml -p conformance-tests -- --include-ignored {{filter}}

# runs the conformance test suite against the latest local hickory-dns commit -- changes that have not been commited will be ignored!
conformance-hickory: (conformance-hickory-aws-lc-rs)

conformance-hickory-aws-lc-rs filter='':
    @ bash -c '[[ -n "$(git status -s)" ]] && echo "WARNING: uncommitted changes will NOT be tested" || true'
    DNS_TEST_VERBOSE_DOCKER_BUILD=1 DNS_TEST_PEER=unbound DNS_TEST_SUBJECT="hickory {{justfile_directory()}} aws-lc-rs" cargo t --manifest-path conformance/Cargo.toml -p conformance-tests -- {{filter}}
    @ bash -c '[[ -n "$(git status -s)" ]] && echo "WARNING: uncommitted changes were NOT tested" || true'

conformance-hickory-ring filter='':
    @ bash -c '[[ -n "$(git status -s)" ]] && echo "WARNING: uncommitted changes will NOT be tested" || true'
    DNS_TEST_VERBOSE_DOCKER_BUILD=1 DNS_TEST_PEER=unbound DNS_TEST_SUBJECT="hickory {{justfile_directory()}} ring" cargo t --manifest-path conformance/Cargo.toml -p conformance-tests -- {{filter}}
    @ bash -c '[[ -n "$(git status -s)" ]] && echo "WARNING: uncommitted changes were NOT tested" || true'

# checks that all conformance tests that pass with hickory-dns have been un-#[ignore]-d
conformance-ignored:
    #!/usr/bin/env bash

    set -euxo pipefail

    tmpfile="$(mktemp)"
    bash -c '[[ -n "$(git status -s)" ]] && echo "WARNING: uncommitted changes will NOT be tested" || true'
    ( DNS_TEST_VERBOSE_DOCKER_BUILD=1 DNS_TEST_PEER=unbound DNS_TEST_SUBJECT="hickory {{justfile_directory()}} aws-lc-rs" cargo test --manifest-path conformance/Cargo.toml -p conformance-tests --lib -- --ignored || true ) | tee "$tmpfile"
    grep -e 'test result: \(ok\|FAILED\). 0 passed' "$tmpfile" || ( echo "expected ALL tests to fail but at least one passed; the passing tests must be un-#[ignore]-d" && exit 1 )
    bash -c '[[ -n "$(git status -s)" ]] && echo "WARNING: uncommitted changes were NOT tested" || true'

# lints the conformance test suite
conformance-clippy:
    cargo clippy --locked --manifest-path conformance/Cargo.toml --workspace --all-targets -- -D warnings

# formats the conformance test suite code
conformance-fmt:
    cargo fmt --manifest-path conformance/Cargo.toml --all -- --check

# removes leftover Docker containers and networks that the test framework failed to remove
conformance-clean: (conformance-clean-containers) (conformance-clean-networks)

# removes leftover Docker containers that the test framework failed to remove
conformance-clean-containers:
    docker rm -f $(docker ps | grep dns-test | cut -f 1 -d " ")

# removes leftover Docker networks that the test framework failed to remove
conformance-clean-networks:
    docker network rm $(docker network ls | grep dns-test | cut -f 1 -d " ")

# runs all other e2e-tests-* tasks
e2e-tests: (e2e-tests-run) (e2e-tests-ignored) (e2e-tests-clippy) (e2e-tests-fmt)

# runs hickory-specific end-to-end tests that use the dns-test framework
e2e-tests-run:
    bash -c '[[ -n "$(git status -s)" ]] && echo "WARNING: uncommitted changes will NOT be tested" || true'
    DNS_TEST_VERBOSE_DOCKER_BUILD=1 cargo test --manifest-path tests/e2e-tests/Cargo.toml
    bash -c '[[ -n "$(git status -s)" ]] && echo "WARNING: uncommitted changes were NOT tested" || true'

# check that any fixed e2e-test has not been left marked as `#[ignore]`
e2e-tests-ignored:
    #!/usr/bin/env bash

    set -euxo pipefail

    tmpfile="$(mktemp)"
    bash -c '[[ -n "$(git status -s)" ]] && echo "WARNING: uncommitted changes will NOT be tested" || true'
    ( DNS_TEST_VERBOSE_DOCKER_BUILD=1 cargo test --manifest-path tests/e2e-tests/Cargo.toml --lib -- --ignored || true ) | tee "$tmpfile"
    grep -e 'test result: \(ok\|FAILED\). 0 passed' "$tmpfile" || ( echo "expected ALL tests to fail but at least one passed; the passing tests must be un-#[ignore]-d" && exit 1 )
    bash -c '[[ -n "$(git status -s)" ]] && echo "WARNING: uncommitted changes were NOT tested" || true'

# lints the end-to-end test suite
e2e-tests-clippy:
    cargo clippy --manifest-path tests/e2e-tests/Cargo.toml --all-targets -- -D warnings

# formats the end-to-end test suite code
e2e-tests-fmt:
    cargo fmt --manifest-path tests/e2e-tests/Cargo.toml --all -- --check

# runs all other ede-dot-com-* tasks
ede-dot-com: (ede-dot-com-run) (ede-dot-com-ignored) (ede-dot-com-check)

# runs hickory-specific ede-dot-com tests that use the dns-test framework
ede-dot-com-run filter='':
    bash -c '[[ -n "$(git status -s)" ]] && echo "WARNING: uncommitted changes will NOT be tested" || true'
    DNS_TEST_VERBOSE_DOCKER_BUILD=1 cargo test --manifest-path tests/ede-dot-com/Cargo.toml --locked -- {{filter}}
    bash -c '[[ -n "$(git status -s)" ]] && echo "WARNING: uncommitted changes were NOT tested" || true'

# check that any fixed ede-dot-com test has not been left marked as `#[ignore]`
ede-dot-com-ignored:
    #!/usr/bin/env bash

    set -euxo pipefail

    tmpfile="$(mktemp)"
    bash -c '[[ -n "$(git status -s)" ]] && echo "WARNING: uncommitted changes will NOT be tested" || true'
    ( DNS_TEST_VERBOSE_DOCKER_BUILD=1 cargo test --manifest-path tests/ede-dot-com/Cargo.toml --locked --lib -- --ignored || true ) | tee "$tmpfile"
    grep -e 'test result: \(ok\|FAILED\). 0 passed' "$tmpfile" || ( echo "expected ALL tests to fail but at least one passed; the passing tests must be un-#[ignore]-d" && exit 1 )
    bash -c '[[ -n "$(git status -s)" ]] && echo "WARNING: uncommitted changes were NOT tested" || true'

# checks the ede-dot-com workspace
ede-dot-com-check: (ede-dot-com-clippy) (ede-dot-com-fmt)

# lints the ede-dot-com test suite
ede-dot-com-clippy:
    cargo clippy --manifest-path tests/ede-dot-com/Cargo.toml --locked --all-targets -- -D warnings

# formats the ede-dot-com test suite code
ede-dot-com-fmt:
    cargo fmt --manifest-path tests/ede-dot-com/Cargo.toml --all -- --check

# builds no-std variant for aarch64-unknown-none
proto-aarch64-none:
    cargo build --package hickory-proto -v --lib --target aarch64-unknown-none --no-default-features --features=no-std-rand

[private]
[macos]
init-openssl:
    openssl version || brew install openssl@1.1

[private]
[linux]
init-openssl:
    openssl version

[private]
[macos]
init-bind9-deps: init-openssl
    pip install ply
    brew install wget libuv userspace-rcu openssl

[private]
[linux]
init-bind9-deps:
    if apt-get --version ; then sudo apt-get install -y python3-ply libuv1-dev liburcu-dev libssl-dev libcap-dev ; fi

# Install BIND9, needed for compatibility tests
[unix]
init-bind9:
    #!/usr/bin/env bash
    set -euxo pipefail

    if {{TDNS_BIND_PATH}}/sbin/named -v ; then exit 0 ; fi

    just init-bind9-deps

    ## This must run after OpenSSL installation
    if openssl version ; then WITH_OPENSSL="--with-openssl=$(dirname $(dirname $(which openssl)))" ; fi

    mkdir -p {{TARGET_DIR}}

    echo "----> downloading bind"
    rm -rf {{TARGET_DIR}}/bind-{{BIND_VER}}
    wget -O {{TARGET_DIR}}/bind-{{BIND_VER}}.tar.xz https://downloads.isc.org/isc/bind9/{{BIND_VER}}/bind-{{BIND_VER}}.tar.xz

    ls -la {{TARGET_DIR}}/bind-{{BIND_VER}}.tar.xz
    tar -xJf {{TARGET_DIR}}/bind-{{BIND_VER}}.tar.xz -C {{TARGET_DIR}}

    echo "----> compiling bind"
    cd {{TARGET_DIR}}/bind-{{BIND_VER}}

    ./configure --prefix {{TDNS_BIND_PATH}} ${WITH_OPENSSL}
    make install
    cd -

    {{TDNS_BIND_PATH}}/sbin/named -v

    rm {{TARGET_DIR}}/bind-{{BIND_VER}}.tar.xz
    rm -rf {{TARGET_DIR}}/bind-{{BIND_VER}}

# Check for the cargo-workspaces command, install if it does not exist
init-cargo-workspaces:
    @cargo ws --version || cargo install cargo-workspaces

# Install audit tools
init-audit:
    @cargo audit --version || cargo install cargo-audit

# Install the code coverage components for LLVM
init-llvm-cov:
    @cargo llvm-cov --version || cargo install cargo-llvm-cov
    @rustup component add llvm-tools-preview

# Initialize all tools needed for running tests, etc.
init: init-cargo-workspaces init-audit
    @echo 'all tools initialized'

# Run the server with example config, for manual testing purposes
run-example:
    @cargo {{MSRV}} run --bin hickory-dns --locked -- -d -c {{TEST_DATA}}/test_configs/example.toml -z {{TEST_DATA}}/test_configs -p 2053
