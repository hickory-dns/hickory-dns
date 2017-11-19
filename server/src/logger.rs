// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Default logger configuration for the project

use std::env;
use std::fmt::Display;

#[cfg(feature = "colored")]
use colored::Colorize;
use env_logger::{LogBuilder, LogTarget};
use log::{LogLevel, LogRecord};

fn format<L, M, LN, A>(level: L, module: M, line: LN, args: A) -> String
where
    L: Display,
    M: Display,
    LN: Display,
    A: Display,
{
    // TODO: replace with String concatination...
    format!("{}:{}:{}:{}", level, module, line, args,)
}

fn plain_formatter(record: &LogRecord) -> String {
    format(
        record.level(),
        record.location().module_path(),
        record.location().line(),
        record.args(),
    )
}

fn color_formatter(record: &LogRecord) -> String {
    let color = match record.level() {
        LogLevel::Error => "red",
        LogLevel::Warn => "yellow",
        LogLevel::Info => "green",
        LogLevel::Trace => "magenta",
        LogLevel::Debug => "cyan",
    };

    format(
        record.level().to_string().color(color),
        record.location().module_path(),
        record.location().line(),
        record.args().to_string().color(color),
    )
}

fn get_env() -> String {
    env::var("RUST_LOG").unwrap_or(String::new())
}

fn all_trust_dns(level: &str) -> String {
    format!(",named={level},trust_dns_server={level},trust_dns_proto={level}", level=level)
}

/// appends trust-dns-server debug to RUST_LOG
pub fn debug(no_color: bool) {
    let mut rust_log = get_env();
    rust_log.push_str(&all_trust_dns("debug"));
    logger(&rust_log, no_color);
}

/// appends trust-dns-server info to RUST_LOG
pub fn default(no_color: bool) {
    let mut rust_log = get_env();
    rust_log.push_str(&all_trust_dns("info"));
    logger(&rust_log, no_color);
}

/// appends trust-dns-server info to RUST_LOG
pub fn quiet(no_color: bool) {
    let mut rust_log = get_env();
    rust_log.push_str(&all_trust_dns("info"));
    logger(&rust_log, no_color);
}

/// only uses the RUST_LOG environment variable.
pub fn env(no_color: bool) {
    let rust_log = get_env();
    logger(&rust_log, no_color);
}

/// see env_logger docs
fn logger(config: &str, no_color: bool) {
    let is_tty = env::var("TERM").ok().map_or(false, |_| true);

    let mut builder = LogBuilder::new();

    let log_formatter = if is_tty && !no_color {
        color_formatter
    } else {
        plain_formatter
    };

    builder.format(log_formatter);
    builder.parse(&config);
    builder.target(LogTarget::Stdout);
    builder.init().expect("could not initialize logger");
}
