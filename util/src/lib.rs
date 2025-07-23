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

fn get_env() -> String {
    env::var("RUST_LOG").unwrap_or_default()
}

fn get_levels<T: ToString>(bin: &str, level: Option<T>) -> String {
    let hickory_crates = level.map(|level| {
        format!(
            "{bin}={level},hickory_dns={level}",
            bin = bin,
            level = level.to_string().to_lowercase(),
        )
    });

    if let Some(hickory_crates) = hickory_crates {
        format!(
            "{hickory_crates},{env}",
            hickory_crates = hickory_crates,
            env = get_env()
        )
    } else {
        get_env()
    }
}

/// Setup the logging for the given Level of output and all hickory-dns crates
///
/// # Panic
///
/// This will panic if the tracing subscriber can't be registered
pub fn logger(bin: &str, level: Option<Level>) {
    // Setup tracing for logging based on input
    let subscriber = EnvFilter::builder()
        .with_default_directive(LevelFilter::OFF.into())
        .parse(get_levels(bin, level))
        .expect("failed to configure tracing/logging");

    let formatter = tracing_subscriber::fmt::layer().compact();

    tracing_subscriber::registry()
        .with(formatter)
        .with(subscriber)
        .init();
}

/// Common CLI configuration for tracing log levels
#[derive(Debug, Parser)]
pub struct LogConfig {
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
        if self.debug {
            Some(Level::DEBUG)
        } else if self.info {
            Some(Level::INFO)
        } else if self.warn {
            Some(Level::WARN)
        } else if self.error {
            Some(Level::ERROR)
        } else {
            None
        }
    }
}
