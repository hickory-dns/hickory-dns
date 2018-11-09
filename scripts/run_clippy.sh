#!/bin/bash

set -e

cargo clippy --version || rustup component add clippy-preview

cargo clean -p trust-dns
cargo clean -p trust-dns-proto
cargo clean -p trust-dns-server
cargo clean -p trust-dns-resolver
cargo clean -p trust-dns-rustls
cargo clean -p trust-dns-openssl
cargo clean -p trust-dns-https
cargo clean -p trust-dns-native-tls
cargo clean -p trust-dns-compatibility
cargo clean -p trust-dns-integration

TARGETS_OPTS="--all --lib --examples --tests --bins"
CLIPPY_OPTS="-D warnings\
    -A clippy::large_enum_variant\
    -A clippy::many_single_char_names\
    -A clippy::module-inception\
    -A clippy::needless_pass_by_value\
    -A clippy::new_ret_no_self\
    -A clippy::too_many_arguments\
    -A clippy::type_complexity\
    -A clippy::unreadable_literal\
    -A clippy::useless_attribute\
    \
    -A clippy::block_in_if_condition_stmt\
    -A clippy::cast_lossless\
    -A clippy::clone_double_ref\
    -A clippy::clone_on_copy\
    -A clippy::const_static_lifetime\
    -A clippy::cyclomatic_complexity\
    -A clippy::derive_hash_xor_eq\
    -A clippy::enum_variant_names\
    -A clippy::expect_fun_call\
    -A clippy::filter_next\
"

cargo clippy ${TARGETS_OPTS:?} -- ${CLIPPY_OPTS:?}
cargo clippy ${TARGETS_OPTS:?} --all-features -- ${CLIPPY_OPTS:?}
cargo clippy ${TARGETS_OPTS:?} --no-default-features -- ${CLIPPY_OPTS:?}