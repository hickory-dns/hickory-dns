// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Default logger configuration for the project

use std::env;
use std::fmt::Display;
use std::io::{self, Write};

use env_logger;
use env_logger::fmt::Formatter;
use log;
use time::OffsetDateTime;

fn format<L, M, LN, A>(
    fmt: &mut Formatter,
    level: L,
    module: M,
    line: LN,
    args: A,
) -> io::Result<()>
where
    L: Display,
    M: Display,
    LN: Display,
    A: Display,
{
    let now = OffsetDateTime::now_utc();
    let now_secs = now.unix_timestamp();
    writeln!(fmt, "{}:{}:{}:{}:{}", now_secs, level, module, line, args)
}

fn plain_formatter(fmt: &mut Formatter, record: &log::Record<'_>) -> io::Result<()> {
    format(
        fmt,
        record.level(),
        record.module_path().unwrap_or("None"),
        record.line().unwrap_or(0),
        record.args(),
    )
}

fn get_env() -> String {
    env::var("RUST_LOG").unwrap_or_default()
}

fn all_trust_dns(level: &str) -> String {
    format!(
        ",named={level},trust_dns_client={level},trust_dns_server={level},trust_dns_proto={level},trust_dns_resolver={level},trust_dns_https={level}",
        level = level
    )
}

/// appends trust-dns-server debug to RUST_LOG
pub fn debug() {
    let mut rust_log = get_env();
    rust_log.push_str(&all_trust_dns("debug"));
    logger(&rust_log);
}

/// appends trust-dns-server info to RUST_LOG
pub fn default() {
    let mut rust_log = get_env();
    rust_log.push_str(&all_trust_dns("info"));
    logger(&rust_log);
}

/// appends trust-dns-server error to RUST_LOG
pub fn quiet() {
    let mut rust_log = get_env();
    rust_log.push_str(&all_trust_dns("error"));
    logger(&rust_log);
}

/// only uses the RUST_LOG environment variable.
pub fn env() {
    let rust_log = get_env();
    logger(&rust_log);
}

/// see env_logger docs
fn logger(config: &str) {
    let mut builder = env_logger::Builder::new();

    let log_formatter = plain_formatter;

    builder.format(log_formatter);
    builder.parse_filters(config);
    builder.target(env_logger::Target::Stdout);
    builder.init();
}
