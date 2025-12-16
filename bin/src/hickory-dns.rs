// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The `hickory-dns` binary for running a DNS server
//!
//! ```text
//! Usage: hickory-dns [options]
//!       hickory-dns (-h | --help | --version)
//!
//! Options:
//!       --validate           Test validation of configuration files
//!       --workers <WORKERS>  Number of runtime workers, defaults to the number of CPU cores
//!       -q, --quiet              Disable INFO messages, WARN and ERROR will remain
//!       -d, --debug              Turn on `DEBUG` messages (default is only `INFO`)
//!       -c, --config <NAME>      Path to configuration file of named server [default: /etc/named.toml]
//!       -z, --zonedir <DIR>      Path to the root directory for all zone files, see also config toml
//!       -p, --port <PORT>        Listening port for DNS queries, overrides any value in config file
//!           --disable-tcp        Disable TCP protocol, overrides any value in config file
//!           --disable-udp        Disable UDP protocol, overrides any value in config file
//!           --nsid <NSID>        Name server identifier (NSID) payload for EDNS responses. Use `0x` prefix for hex-encoded data. Mutually exclusive with --nsid-hostname
//!           --nsid-hostname      Use the system hostname as the name server identifier (NSID) payload for EDNS responses. Mutually exclusive with --nsid
//!       -h, --help               Print help
//!       -V, --version            Print version
//! ```

use clap::Parser;
use tokio::runtime;
use tracing::{Level, info};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use hickory_dns::DnsServer;

/// Main method for running the named server.
fn main() -> Result<(), String> {
    // this is essential for custom formatting the returned error message.
    // the displayed message of termination impl trait is not pretty.
    // https://doc.rust-lang.org/stable/src/std/process.rs.html#2439
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let args = DnsServer::parse();

    // TODO: this should be set after loading config, but it's necessary for initial log lines, no?
    let level = match (args.quiet, args.debug) {
        (true, _) => Level::ERROR,
        (_, true) => Level::DEBUG,
        _ => Level::INFO,
    };

    // Setup tracing for logging based on input
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(level.into())
                .from_env()
                .map_err(|err| {
                    format!("failed to parse environment variable for tracing: {err}")
                })?,
        )
        .init();

    info!("Hickory DNS {} starting...", env!("CARGO_PKG_VERSION"));

    let mut runtime = runtime::Builder::new_multi_thread();
    runtime.enable_all().thread_name("hickory-server-runtime");
    if let Some(workers) = args.workers {
        runtime.worker_threads(workers);
    }
    let runtime = runtime
        .build()
        .map_err(|err| format!("failed to initialize Tokio runtime: {err}"))?;

    runtime.block_on(args.run())
}
