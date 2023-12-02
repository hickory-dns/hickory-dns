## Script for executing commands for the project.
export TARGET_DIR := join(justfile_directory(), "target")
export TDNS_BIND_PATH := join(TARGET_DIR, "bind")
export TEST_DATA := join(join(justfile_directory(), "tests"), "test-data")

## MSRV
MSRV := env_var_or_default('MSRV', "")

## Code coverage config
COV_RUSTFLAGS := "-C instrument-coverage -C llvm-args=--instrprof-atomic-counter-update-all --cfg=coverage --cfg=trybuild_no_target"
COV_CARGO_INCREMENTAL := "0"
COV_CARGO_LLVM_COV := "1"
COV_CARGO_LLVM_COV_TARGET_DIR := join(TARGET_DIR, "llvm-cov-target")
COV_LLVM_PROFILE_FILE := join(COV_CARGO_LLVM_COV_TARGET_DIR, "hickory-dns-%p-%m_%c.profraw")

BIND_VER := "9.16.41"

# Check, build, and test all crates with default features enabled
default feature='' ignore='': (check feature ignore) (build feature ignore) (test feature ignore)

# Check, build, and test all crates with all-features enabled
all-features: (default "--all-features")

# Check, build, and test all crates with no-default-features
no-default-features: (default "--no-default-features" "--ignore=\\{hickory-compatibility\\}")

# Check, build, and test all crates with dns-over-rustls enabled
dns-over-rustls: (default "--features=dns-over-rustls" "--ignore=\\{async-std-resolver,hickory-compatibility\\}")

# Check, build, and test all crates with dns-over-https-rustls enabled
dns-over-https-rustls: (default "--features=dns-over-https-rustls" "--ignore=\\{async-std-resolver,hickory-compatibility\\}")

# Check, build, and test all crates with dns-over-quic enabled
dns-over-quic: (default "--features=dns-over-quic" "--ignore=\\{async-std-resolver,hickory-compatibility\\}")

# Check, build, and test all crates with dns-over-h3 enabled
dns-over-h3: (default "--features=dns-over-h3" "--ignore=\\{async-std-resolver,hickory-compatibility,hickory-client\\}")

# Check, build, and test all crates with dns-over-native-tls enabled
dns-over-native-tls: (default "--features=dns-over-native-tls" "--ignore=\\{async-std-resolver,hickory-compatibility,hickory-server,hickory-dns,hickory-util,hickory-integration\\}")

# Check, build, and test all crates with dns-over-openssl enabled
dns-over-openssl: (default "--features=dnssec-openssl" "--ignore=\\{async-std-resolver,hickory-compatibility\\}")

# Check, build, and test all crates with dnssec-openssl enabled
dnssec-openssl: (default "--features=dnssec-openssl" "--ignore=\\{async-std-resolver,hickory-compatibility\\}")

# Check, build, and test all crates with dnssec-ring enabled
dnssec-ring: (default "--features=dnssec-ring" "--ignore=\\{async-std-resolver,hickory-compatibility\\}")

# Run check on all projects in the workspace
check feature='' ignore='':
    cargo ws exec {{ignore}} cargo {{MSRV}} check --all-targets --benches --examples --bins --tests {{feature}}
    cargo {{MSRV}} check --manifest-path fuzz/Cargo.toml --all-targets --benches --examples --bins --tests

# Run build on all projects in the workspace
build feature='' ignore='':
    cargo ws exec {{ignore}} cargo {{MSRV}} build --all-targets --benches --examples --bins --tests {{feature}}

# Run tests on all projects in the workspace
test feature='' ignore='':
    cargo ws exec {{ignore}} cargo {{MSRV}} test --all-targets --benches --examples --bins --tests {{feature}}

doc feature='':
    cargo ws exec --ignore=hickory-dns cargo {{MSRV}} test --doc {{feature}}

# This tests compatibility with BIND9, TODO: support other feature sets besides openssl for tests
compatibility: init-bind9
    cargo test --manifest-path tests/compatibility-tests/Cargo.toml --all-targets --benches --examples --bins --tests --no-default-features --features=none;
    cargo test --manifest-path tests/compatibility-tests/Cargo.toml --all-targets --benches --examples --bins --tests --no-default-features --features=bind;

# Build all bench marking tools, i.e. check that they work, but don't run
build-bench:
    cargo ws exec cargo +nightly bench --no-run

[private]
clippy-inner feature='':
    cargo ws exec cargo {{MSRV}} clippy --all-targets --benches --examples --bins --tests {{feature}} -- -D warnings

# Run clippy on all targets and all sources
clippy:
    find {{justfile_directory()}} -name '*.rs' -exec touch {} \;
    just clippy-inner --no-default-features
    just clippy-inner
    just clippy-inner --all-features

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
    
    cargo +nightly llvm-cov clean
    mkdir -p {{COV_CARGO_LLVM_COV_TARGET_DIR}}
    
    cargo +nightly build --workspace --all-targets --all-features 
    cargo +nightly llvm-cov test --workspace --no-report --all-targets --benches --examples --bins --tests --all-features
    cargo +nightly llvm-cov test --workspace --no-report --doc --doctests --all-features
    cargo +nightly llvm-cov report --codecov --output-path {{join(COV_CARGO_LLVM_COV_TARGET_DIR, "hickory-dns-coverage.json")}}

# Open the html view of the coverage report
coverage-html: coverage
    #!/usr/bin/env bash
    set -euxo pipefail
    
    export RUSTFLAGS="{{COV_RUSTFLAGS}}"
    export CARGO_LLVM_COV={{COV_CARGO_LLVM_COV}}
    export CARGO_LLVM_COV_TARGET_DIR={{COV_CARGO_LLVM_COV_TARGET_DIR}}
    export LLVM_PROFILE_FILE={{COV_LLVM_PROFILE_FILE}}

    cargo +nightly llvm-cov report --html --open --output-dir {{COV_CARGO_LLVM_COV_TARGET_DIR}}

# (Re)generates Test Certificates, if tests are failing, this needs to be run yearly
generate-test-certs: init-openssl
    cd {{TEST_DATA}} && rm -f ca.key ca.pem cert.key cert-key.pkcs8 cert.csr cert.pem cert.p12
    scripts/gen_certs.sh

# Publish all crates
publish:
    cargo ws publish --from-git --token $CRATES_IO_TOKEN

# Removes the target directory cleaning all built artifacts
clean:
    rm -rf {{TARGET_DIR}}

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
    brew install wget

[private]
[linux]
init-bind9-deps:
    if apt-get --version ; then sudo apt-get install -y python3-ply ; fi

# Install BIND9, needed for compatability tests
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
init: init-cargo-workspaces init-audit init-bind9
    @echo 'all tools initialized'

# Run the server with example config, for manual testing purposes
run-example:
    @cargo {{MSRV}} run --bin hickory-dns -- -d -c {{TEST_DATA}}/test_configs/example.toml -z {{TEST_DATA}}/test_configs -p 2053
