#!/bin/bash -e

set -x

# This script is used for CI and assumes clippy is installed already.
# TODO: run clippy on the other crates, for now we only fixed the clippy warning on the client crate

pushd client
cargo clippy --all-features -- \
    --allow type_complexity \
    --allow doc_markdown \
    --allow module_inception
popd

pushd compatibility-tests
cargo clippy --features "bind" --no-default-features -- \
    --allow type_complexity \
    --allow doc_markdown \
    --allow module_inception
popd

pushd compatibility-tests
cargo clippy -- \
    --allow type_complexity \
    --allow doc_markdown \
    --allow module_inception
popd

pushd integration-tests
cargo clippy --all-features -- \
    --allow type_complexity \
    --allow doc_markdown \
    --allow module_inception
popd

pushd native-tls
cargo clippy --all-features -- \
    --allow type_complexity \
    --allow doc_markdown \
    --allow module_inception
popd

pushd openssl
cargo clippy --all-features -- \
    --allow type_complexity \
    --allow doc_markdown \
    --allow module_inception
popd

pushd proto
# FIXME: we should probably not allow `block_in_if_condition_stmt
cargo clippy --all-features -- \
    --allow doc_markdown \
    --allow type_complexity \
    --allow many_single_char_names \
    --allow needless_lifetimes \
    --allow block_in_if_condition_stmt \
    --allow too_many_arguments \
    --allow new_ret_no_self \
    --allow enum_variant_names
popd

pushd resolver
cargo clippy --all-features -- \
    --allow type_complexity \
    --allow doc_markdown \
    --allow module_inception
popd

pushd rustls
cargo clippy --all-features -- \
    --allow type_complexity \
    --allow doc_markdown \
    --allow module_inception
popd

pushd server
cargo clippy --all-features -- \
    --allow type_complexity \
    --allow doc_markdown \
    --allow module_inception
popd

pushd util
cargo clippy --all-features -- \
    --allow type_complexity \
    --allow doc_markdown \
    --allow module_inception
popd
