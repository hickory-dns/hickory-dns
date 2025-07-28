use std::env;
use std::net::Ipv4Addr;
use std::sync::mpsc;

use dns_test::client::Client;
use dns_test::name_server::{Graph, NameServer, Sign};
use dns_test::record::RecordType;
use dns_test::zone_file::SignSettings;
use dns_test::{FQDN, Forwarder, Network, Resolver, Result};

fn main() -> Result<()> {
    let args = Args::from_env()?;

    let network = Network::new()?;
    let peer = &dns_test::PEER;

    println!("building nameserver docker image...");
    let leaf_ns = NameServer::new(peer, FQDN::TEST_DOMAIN, &network)?;
    println!("DONE");

    println!("setting up name servers...");
    let sign = if args.dnssec {
        Sign::Yes {
            settings: SignSettings::default(),
        }
    } else {
        Sign::No
    };
    let Graph {
        root,
        trust_anchor,
        nameservers,
    } = Graph::build(leaf_ns, sign)?;
    println!("DONE");

    let client = Client::new(&network)?;
    if args.dnssec {
        // this will send queries to the loopback address and fail because there's no resolver
        // but as a side-effect it will generate the `/etc/bind.keys` file we want
        // ignore the expected error
        let _ = client.delv(
            Ipv4Addr::LOCALHOST,
            RecordType::SOA,
            &FQDN::ROOT,
            trust_anchor.as_ref().unwrap(),
        )?;
    }

    println!("building resolver docker image...");
    let mut builder = Resolver::new(&network, root);
    if let Some(trust_anchor) = &trust_anchor {
        builder.trust_anchor(trust_anchor);
    }
    let resolver = builder.start()?;
    println!("DONE");

    println!("building forwarder docker image...");
    let mut builder = Forwarder::new(&network, &resolver);
    if let Some(trust_anchor) = &trust_anchor {
        builder.trust_anchor(trust_anchor);
    }
    let forwarder = builder.start()?;
    println!("DONE\n\n");

    let (tx, rx) = mpsc::channel();

    ctrlc::set_handler(move || tx.send(()).expect("could not forward signal"))?;

    for ns in &nameservers {
        println!("{} name server's IP address: {}", ns.zone(), ns.ipv4_addr());
        println!(
            "attach to this container with: `docker exec -it {} bash`\n",
            ns.container_name()
        );
    }

    let resolver_addr = resolver.ipv4_addr();
    println!("resolver's IP address: {resolver_addr}");
    println!(
        "attach to this container with: `docker exec -it {} bash`\n",
        resolver.container_name()
    );

    let forwarder_addr = forwarder.ipv4_addr();
    println!("forwarder's IP address: {forwarder_addr}");
    println!(
        "attach to this container with: `docker exec -it {} bash`\n",
        forwarder.container_name()
    );

    println!("client's IP address: {}", client.ipv4_addr());
    println!(
        "attach to this container with: `docker exec -it {} bash`\n\n",
        client.container_name()
    );

    println!("example queries (run these in the client container):\n");
    let adflag = if args.dnssec { "+adflag" } else { "+noadflag" };
    println!("`dig @{resolver_addr} {adflag} SOA .`\n");
    if args.dnssec {
        println!(
            "`delv -a /etc/bind.keys @{resolver_addr} SOA .` (you MUST use the `-a` flag with delv)\n\n"
        );
    }

    println!(
        "to print the DNS traffic flowing through the resolver run this command in
the resolver container before performing queries:\n"
    );
    println!("`tshark -f 'udp port 53' -O dns`\n\n");

    println!("press Ctrl+C to take down the network");

    rx.recv()?;

    println!("\ntaking down network...");

    Ok(())
}

struct Args {
    dnssec: bool,
}

impl Args {
    fn from_env() -> Result<Self> {
        let args: Vec<_> = env::args().skip(1).collect();
        let num_args = args.len();

        let dnssec = if num_args == 0 {
            false
        } else if num_args == 1 {
            if args[0] == "--dnssec" {
                true
            } else {
                return cli_error();
            }
        } else {
            return cli_error();
        };

        Ok(Self { dnssec })
    }
}

fn cli_error<T>() -> Result<T> {
    eprintln!(
        "usage: explore [--dnssec]
Options:
  --dnssec      sign zone files to enable DNSSEC"
    );

    Err("CLI error".into())
}
