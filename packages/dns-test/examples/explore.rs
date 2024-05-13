use std::env;
use std::net::Ipv4Addr;
use std::sync::mpsc;

use dns_test::client::Client;
use dns_test::name_server::NameServer;
use dns_test::record::RecordType;
use dns_test::zone_file::Root;
use dns_test::{Network, Resolver, Result, TrustAnchor, FQDN};

fn main() -> Result<()> {
    let args = Args::from_env()?;

    let network = Network::new()?;
    let peer = &dns_test::PEER;

    println!("building docker image...");
    let mut root_ns = NameServer::new(peer, FQDN::ROOT, &network)?;
    println!("DONE");

    println!("setting up name servers...");
    let mut com_ns = NameServer::new(peer, FQDN::COM, &network)?;

    let mut nameservers_ns = NameServer::new(peer, FQDN("nameservers.com.")?, &network)?;
    nameservers_ns.add(root_ns.a()).add(com_ns.a());

    let nameservers_ns = if args.dnssec {
        let nameservers_ns = nameservers_ns.sign()?;
        com_ns.add(nameservers_ns.ds().clone());
        nameservers_ns.start()?
    } else {
        nameservers_ns.start()?
    };

    com_ns.referral(
        nameservers_ns.zone().clone(),
        nameservers_ns.fqdn().clone(),
        nameservers_ns.ipv4_addr(),
    );

    let com_ns = if args.dnssec {
        let com_ns = com_ns.sign()?;
        root_ns.add(com_ns.ds().clone());
        com_ns.start()?
    } else {
        com_ns.start()?
    };

    root_ns.referral(FQDN::COM, com_ns.fqdn().clone(), com_ns.ipv4_addr());

    let mut trust_anchor = TrustAnchor::empty();
    let root_ns = if args.dnssec {
        let root_ns = root_ns.sign()?;
        let root_ksk = root_ns.key_signing_key();
        let root_zsk = root_ns.zone_signing_key();

        trust_anchor.add(root_ksk.clone());
        trust_anchor.add(root_zsk.clone());

        root_ns.start()?
    } else {
        root_ns.start()?
    };

    println!("DONE");

    let client = Client::new(&network)?;
    if args.dnssec {
        // this will send queries to the loopback address and fail because there's no resolver
        // but as a side-effect it will generate the `/etc/bind.keys` file we want
        // ignore the expected error
        let _ = client.delv(
            Ipv4Addr::new(127, 0, 0, 1),
            RecordType::SOA,
            &FQDN::ROOT,
            &trust_anchor,
        )?;
    }

    println!("building docker image...");
    let resolver = Resolver::new(
        &network,
        Root::new(root_ns.fqdn().clone(), root_ns.ipv4_addr()),
    )
    .trust_anchor(&trust_anchor)
    .start(&dns_test::SUBJECT)?;
    println!("DONE\n\n");

    let (tx, rx) = mpsc::channel();

    ctrlc::set_handler(move || tx.send(()).expect("could not forward signal"))?;

    println!(". (root) name server's IP address: {}", root_ns.ipv4_addr());
    println!(
        "attach to this container with: `docker exec -it {} bash`\n",
        root_ns.container_id()
    );

    println!("com. name server's IP address: {}", com_ns.ipv4_addr());
    println!(
        "attach to this container with: `docker exec -it {} bash`\n",
        com_ns.container_id()
    );

    println!(
        "nameservers.com. name server's IP address: {}",
        nameservers_ns.ipv4_addr()
    );
    println!(
        "attach to this container with: `docker exec -it {} bash`\n",
        nameservers_ns.container_id()
    );

    let resolver_addr = resolver.ipv4_addr();
    println!("resolver's IP address: {resolver_addr}",);
    println!(
        "attach to this container with: `docker exec -it {} bash`\n",
        resolver.container_id()
    );

    println!("client's IP address: {}", client.ipv4_addr());
    println!(
        "attach to this container with: `docker exec -it {} bash`\n\n",
        client.container_id()
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
