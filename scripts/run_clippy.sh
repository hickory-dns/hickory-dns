#!/bin/bash

set -e

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
CLIPPY_OPTS="-D warnings -A clippy::useless_format -A clippy::identity_conversion -A clippy::derive_hash_xor_eq -A clippy::needless_lifetimes -A clippy::len_zero -A clippy::single_char_pattern -A clippy::block_in_if_condition_stmt -A clippy::new_ret_no_self -A clippy::len_without_is_empty -A clippy::useless_attribute -A clippy::clone_on_copy -A clippy::expect_fun_call -A clippy::needless_pass_by_value -A clippy::redundant_pattern -A clippy::match_ref_pats -A clippy::redundant_closure -A clippy::cast_lossless -A clippy::new_without_default_derive -A clippy::trivially_copy_pass_by_ref -A clippy::if_let_redundant_pattern_matching -A clippy::large_enum_variant -A clippy::unneeded_field_pattern -A clippy::suspicious_else_formatting -A clippy::needless_return -A clippy::redundant_field_names -A clippy::if_same_then_else -A clippy::single_match -A clippy::or_fun_call -A clippy::unreadable_literal -A clippy::new_without_default -A clippy::type_complexity -A clippy::new_without_default -A clippy::new_without_default -A clippy::new_without_default -A clippy::string_lit_as_bytes -A clippy::too_many_arguments -A clippy::const_static_lifetime -A clippy::enum_variant_names -A clippy::many_single_char_names -A clippy::clone_double_ref -A clippy::wrong_self_convention -A clippy::question_mark -A clippy::filter_next -A clippy::op_ref -A clippy::module_inception -A clippy::needless_update -A clippy::unit_arg -A clippy::cyclomatic_complexity -A clippy::module_inception -A clippy::op_ref -A clippy::collapsible-if -A clippy::ptr-arg -A clippy::zero-prefixed-literal -A clippy::ok-expect -A clippy::explicit-counter-loop -A clippy::map-clone -A clippy::ok-expect -A clippy::needless-collect"

cargo clippy ${TARGETS_OPTS:?} -- ${CLIPPY_OPTS:?}
cargo clippy ${TARGETS_OPTS:?} --all-features -- ${CLIPPY_OPTS:?}
cargo clippy ${TARGETS_OPTS:?} --no-default-features -- ${CLIPPY_OPTS:?}