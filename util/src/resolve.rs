// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use console::Term;
use structopt::StructOpt;

use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::TokioAsyncResolver;

/// A CLI interface for the trust-dns-resolver.
#[derive(Debug, StructOpt)]
struct Opts {
    /// Name to attempt to resolve, if followed by a '.' then it's a fully-qualified-domain-name.
    domainname: String,
    /// Type of query to issue, e.g. A, AAAA, NS, etc.
    #[structopt(short = "t", long = "type", default_value = "A")]
    ty: RecordType,
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts: Opts = Opts::from_args();

    let term = Term::stdout();

    let name = &opts.domainname;
    let config = ResolverConfig::default();
    let ty = opts.ty;

    let name_servers = config.name_servers().iter().map(|n| format!("{}", n)).fold(
        String::new(),
        |mut names, n| {
            if !names.is_empty() {
                names.push_str(", ")
            }

            names.push_str(&n);
            names
        },
    );

    term.write_line(&format!(
        "Querying for {} {} from {}",
        name, ty, name_servers
    ))?;

    let resolver = TokioAsyncResolver::tokio(config, ResolverOpts::default())?;

    let lookup = resolver
        .lookup(name.to_string(), ty, Default::default())
        .await?;

    term.write_line(&format!("{:?} succeeeded, records:", lookup.query()))?;

    for record in lookup.record_iter() {
        term.write_line(&format!("{:?}", record))?;
    }

    Ok(())
}
