## Script for executing commands for the project.

# Check for the cargo-workspaces command, install if it does not exist
init-cargo-workspaces:
    @cargo ws --version || cargo install cargo-workspaces

# Initialize all tools needed for running tests, etc.
init: init-cargo-workspaces
    @echo 'all tools initialized'

check feature='':
    cargo ws exec cargo check --all-targets --benches --examples --bins --tests {{feature}}
    cargo check --manifest-path fuzz/Cargo.toml --all-targets --benches --examples --bins --tests

build feature='':
    cargo ws exec cargo build --all-targets --benches --examples --bins --tests {{feature}}

test feature='':
    cargo ws exec cargo test --all-targets --benches --examples --bins --tests {{feature}}
    cargo test --manifest-path tests/compatibility-tests/Cargo.toml --all-targets --benches --examples --bins --tests --no-default-features --features=none {{feature}}
#    cargo test --manifest-path tests/compatibility-tests/Cargo.toml --all-targets --benches --examples --bins --tests --no-default-features --features=bind {{feature}}

# Default target to check, build, and test all crates
default feature='': (check feature) (build feature) (test feature)
    
