## Script for executing commands for the project.
export TARGET_DIR := join(justfile_directory(), "target")
export TDNS_BIND_PATH := join(TARGET_DIR, "bind")

BIND_VER := "9.16.41"

# Default target to check, build, and test all crates
default feature='': (check feature) (build feature) (test feature)

# Run check on all projects in the workspace
check feature='':
    cargo ws exec cargo check --all-targets --benches --examples --bins --tests {{feature}}
    cargo check --manifest-path fuzz/Cargo.toml --all-targets --benches --examples --bins --tests

# Run build on all projects in the workspace
build feature='':
    cargo ws exec cargo build --all-targets --benches --examples --bins --tests {{feature}}

# Run tests on all projects in the workspace
test feature='':
    cargo ws exec cargo test --all-targets --benches --examples --bins --tests {{feature}}
   
# This tests compatibility with BIND9, TODO: support other feature sets besides openssl for tests
compatibility: init-bind9
    cargo test --manifest-path tests/compatibility-tests/Cargo.toml --all-targets --benches --examples --bins --tests --no-default-features --features=none;
    cargo test --manifest-path tests/compatibility-tests/Cargo.toml --all-targets --benches --examples --bins --tests --no-default-features --features=bind;

# Build all bench marking tools, i.e. check that they work, but don't run
build-bench:
    cargo ws exec cargo +nightly bench --no-run

# Removes the target directory cleaning all built artifacts
clean:
    rm -rf {{TARGET_DIR}}

[private]
[macos]
init-bind9-deps:
    pip install ply
    brew install openssl@1.1
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


# Initialize all tools needed for running tests, etc.
init: init-cargo-workspaces
    @echo 'all tools initialized'
