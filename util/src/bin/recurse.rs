// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The recurse program

// BINARY WARNINGS
#![warn(
    clippy::default_trait_access,
    clippy::dbg_macro,
    clippy::unimplemented,
    missing_copy_implementations,
    missing_docs,
    non_snake_case,
    non_upper_case_globals,
    rust_2018_idioms,
    unreachable_pub
)]

use std::{net::IpAddr, time::Instant};

use clap::Parser;
use console::style;

use hickory_proto::{
    ROOTS,
    op::Query,
    rr::{Name, RecordType},
};
use hickory_recursor::Recursor;

/// A CLI interface for the hickory-dns-recursor.
///
/// This utility directly uses the hickory-dns-recursor to perform a recursive lookup
///   starting with a set of root dns servers, aka hints.
#[derive(Debug, Parser)]
#[clap(name = "recurse")]
struct Opts {
    /// Name to attempt to resolve, this is assumed to be fully-qualified
    domainname: Name,

    /// Type of query to issue, e.g. A, AAAA, NS, etc.
    #[clap(short = 't', long = "type", default_value = "A")]
    ty: RecordType,

    /// Specify the IP addresses of the root zone nameservers to use.
    ///
    /// Multiple IP addresses may be delimited with commas.
    #[clap(short = 'n', long, use_value_delimiter = true, value_delimiter(','))]
    nameservers: Vec<IpAddr>,

    /// Configure log verbosity.
    #[clap(flatten)]
    log_config: hickory_util::LogConfig,
}

/// Run the resolve program
#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut opts = Opts::parse();

    // enable logging early
    hickory_util::logger(env!("CARGO_BIN_NAME"), opts.log_config.level());

    // query parameters
    let mut name = opts.domainname;
    name.set_fqdn(true);
    let ty = opts.ty;

    if opts.nameservers.is_empty() {
        opts.nameservers = ROOTS.to_vec();
    }

    let recursor = Recursor::builder().build(&opts.nameservers)?;

    // execute query
    println!(
        "Recursing for {name} {ty} from roots",
        name = style(&name).yellow(),
        ty = style(ty).yellow(),
    );

    let now = Instant::now();
    let query = Query::query(name, ty);
    let response = recursor.resolve(query, now, false).await?;

    // report response, TODO: better display of errors
    println!(
        "{} for query {:#?}",
        style("Success").green(),
        style(&response).blue()
    );

    for r in response.all_sections().filter(|r| r.record_type() == ty) {
        println!(
            "\t{name} {ttl} {class} {ty} {rdata}",
            name = style(r.name()).blue(),
            ttl = style(r.ttl()).blue(),
            class = style(r.dns_class()).blue(),
            ty = style(r.record_type()).blue(),
            rdata = r.data()
        );
    }

    Ok(())
}
