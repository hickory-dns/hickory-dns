// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::env;

use clap::Parser;
use tracing::Level;
use tracing::metadata::LevelFilter;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

fn get_levels(bin: &str, cli_level: Option<Level>) -> String {
    let env_level = env::var("RUST_LOG").ok();

    let Some(cli_level) = cli_level else {
        return env_level.unwrap_or_default();
    };

    let level_str = format!(
        "{bin}={level},hickory={level}",
        level = cli_level.to_string().to_lowercase(),
    );

    match env_level {
        Some(env_level) => format!("{level_str},{env_level}"),
        None => level_str,
    }
}

/// Setup the logging for the given Level of output and all hickory-dns crates
///
/// # Panic
///
/// This will panic if the tracing subscriber can't be registered
pub fn logger(bin: &str, cli_level: Option<Level>) {
    // Setup tracing for logging based on input
    let subscriber = EnvFilter::builder()
        .with_default_directive(LevelFilter::OFF.into())
        .parse(get_levels(bin, cli_level))
        .expect("failed to configure tracing/logging");

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().compact())
        .with(subscriber)
        .init();
}

/// Common CLI configuration for tracing log levels
#[derive(Debug, Parser)]
pub struct LogConfig {
    /// Enable trace + debug + info + warning + error logging
    #[clap(long)]
    trace: bool,

    /// Enable debug + info + warning + error logging
    #[clap(long)]
    debug: bool,

    /// Enable info + warning + error logging
    #[clap(long)]
    info: bool,

    /// Enable warning + error logging
    #[clap(long)]
    warn: bool,

    /// Enable error logging
    #[clap(long)]
    error: bool,
}

impl LogConfig {
    pub fn level(&self) -> Option<Level> {
        Some(if self.trace {
            Level::TRACE
        } else if self.debug {
            Level::DEBUG
        } else if self.info {
            Level::INFO
        } else if self.warn {
            Level::WARN
        } else if self.error {
            Level::ERROR
        } else {
            return None;
        })
    }
}
