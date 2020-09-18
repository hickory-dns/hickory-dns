// Copyright 2015-2020 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use console::Term;
use structopt::StructOpt;

use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::TokioAsyncResolver;

/// A CLI interface for the trust-dns-resolver.
#[derive(Debug, StructOpt)]
#[structopt(author = env!("CARGO_PKG_AUTHORS"))]
struct Opts {
    /// Name to attempt to resolve, if followed by a '.' then it's a fully-qualified-domain-name.
    domainname: String,

    /// Type of query to issue, e.g. A, AAAA, NS, etc.
    #[structopt(short = "t", long = "type", default_value = "A")]
    ty: RecordType,

    /// Use google resolvers, default, this can be combined with the other name servers
    #[structopt(long)]
    google: bool,

    /// Use cloudflare resolvers, this can be combined with the other name servers
    #[structopt(long)]
    cloudflare: bool,

    /// Use quad9 resolvers, this can be combined with the other name servers
    #[structopt(long)]
    quad9: bool,

    /// Use ipv4 addresses only, default is both ipv4 and ipv6
    #[structopt(long)]
    ipv4: bool,

    /// Use ipv6 addresses only, default is both
    #[structopt(long)]
    ipv6: bool,
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts: Opts = Opts::from_args();

    let term = Term::stdout();

    let name = &opts.domainname;
    let ty = opts.ty;

    let mut name_servers = NameServerConfigGroup::new();
    if opts.google {
        name_servers.merge(NameServerConfigGroup::google());
    }
    if opts.cloudflare {
        name_servers.merge(NameServerConfigGroup::cloudflare());
    }
    if opts.quad9 {
        name_servers.merge(NameServerConfigGroup::quad9());
    }
    if name_servers.is_empty() {
        name_servers.merge(NameServerConfigGroup::google());
    }

    let ipv4 = opts.ipv4 || !opts.ipv6;
    let ipv6 = opts.ipv6 || !opts.ipv4;

    name_servers
        .retain(|ns| (ipv4 && ns.socket_addr.is_ipv4()) || (ipv6 && ns.socket_addr.is_ipv6()));

    let config = ResolverConfig::from_parts(None, vec![], name_servers);

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
