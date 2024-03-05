use std::sync::mpsc;

use dns_test::client::Client;
use dns_test::name_server::NameServer;
use dns_test::record::{Record, RecordType};
use dns_test::zone_file::Root;
use dns_test::{Network, Resolver, Result, TrustAnchor, FQDN};

fn main() -> Result<()> {
    let network = Network::new()?;
    let peer = dns_test::peer();

    println!("building docker image...");
    let mut root_ns = NameServer::new(&peer, FQDN::ROOT, &network)?;
    println!("DONE");

    println!("setting up name servers...");
    let mut com_ns = NameServer::new(&peer, FQDN::COM, &network)?;

    let mut nameservers_ns = NameServer::new(&peer, FQDN("nameservers.com.")?, &network)?;
    nameservers_ns
        .add(Record::a(root_ns.fqdn().clone(), root_ns.ipv4_addr()))
        .add(Record::a(com_ns.fqdn().clone(), com_ns.ipv4_addr()));
    let nameservers_ns = nameservers_ns.sign()?;
    let nameservers_ds = nameservers_ns.ds().clone();
    let nameservers_ns = nameservers_ns.start()?;

    com_ns
        .referral(
            nameservers_ns.zone().clone(),
            nameservers_ns.fqdn().clone(),
            nameservers_ns.ipv4_addr(),
        )
        .add(nameservers_ds);
    let com_ns = com_ns.sign()?;
    let com_ds = com_ns.ds().clone();
    let com_ns = com_ns.start()?;

    root_ns
        .referral(FQDN::COM, com_ns.fqdn().clone(), com_ns.ipv4_addr())
        .add(com_ds);
    let root_ns = root_ns.sign()?;
    let root_ksk = root_ns.key_signing_key().clone();
    let root_zsk = root_ns.zone_signing_key().clone();

    let root_ns = root_ns.start()?;
    println!("DONE");

    let trust_anchor = TrustAnchor::from_iter([root_ksk.clone(), root_zsk.clone()]);
    println!("building docker image...");
    let resolver = Resolver::new(
        &network,
        Root::new(root_ns.fqdn().clone(), root_ns.ipv4_addr()),
    )
    .trust_anchor(&trust_anchor)
    .start(&dns_test::subject())?;
    println!("DONE\n\n");

    let resolver_addr = resolver.ipv4_addr();
    let client = Client::new(&network)?;
    // generate `/etc/bind.keys`
    client.delv(resolver_addr, RecordType::SOA, &FQDN::ROOT, &trust_anchor)?;

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

    println!("resolver's IP address: {resolver_addr}");
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
    println!("`dig @{resolver_addr} SOA .`\n");
    println!(
        "`delv -a /etc/bind.keys @{resolver_addr} SOA .` (you MUST use the `-a` flag with delv)\n\n"
    );

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
