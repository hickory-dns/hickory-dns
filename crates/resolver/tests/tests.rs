use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    thread::sleep,
    time::Duration,
};

use futures_util::stream::{FuturesUnordered, StreamExt};
use test_support::{MockNetworkHandler, MockProvider, MockRecord, subscribe};

use hickory_resolver::{
    NameServer, NameServerPool, PoolContext, TlsConfig,
    config::{NameServerConfig, ProtocolConfig, ResolverOpts},
};

use hickory_proto::{
    ProtoError,
    op::{DnsRequestOptions, Message, Query, ResponseCode},
    rr::{Name, RecordType},
    xfer::{DnsHandle, FirstAnswer},
};

#[tokio::test]
async fn test_shared_lookup() -> Result<(), ProtoError> {
    subscribe();

    let query_name = Name::from_ascii("host.hickory-dns.testing.")?;
    let query_ip = IpAddr::from([10, 0, 0, 1]);

    let responses = vec![MockRecord::a(query_ip, &query_name, query_ip)];

    let counter = Arc::new(AtomicU8::new(0));
    let counter_copy = counter.clone();
    let mutator = Box::new(
        move |_destination: IpAddr, _protocol: ProtocolConfig, _msg: &mut Message| {
            counter_copy.fetch_add(1, Ordering::Relaxed);
            // Ensure the first query is still active when the second is polled
            sleep(Duration::from_millis(250));
        },
    );

    let handler = MockNetworkHandler::new(responses).with_mutation(mutator);

    let provider = MockProvider::new(handler);
    let mut opts = ResolverOpts::default();
    opts.case_randomization = true;
    let name_server = Arc::new(NameServer::new(
        [],
        NameServerConfig::udp(query_ip),
        &opts,
        provider,
    ));
    let pool = NameServerPool::from_nameservers(
        vec![name_server],
        Arc::new(PoolContext::new(opts, TlsConfig::new().unwrap())),
    );

    let mut futures = vec![
        pool.lookup(
            Query::query(query_name.clone(), RecordType::A),
            DnsRequestOptions::default(),
        )
        .first_answer(),
        pool.lookup(
            Query::query(query_name.clone(), RecordType::A),
            DnsRequestOptions::default(),
        )
        .first_answer(),
    ]
    .into_iter()
    .collect::<FuturesUnordered<_>>();

    let mut ok_count = 0;
    while let Some(Ok(response)) = futures.next().await {
        assert_eq!(response.response_code(), ResponseCode::NoError);
        ok_count += 1;
    }

    assert_eq!(ok_count, 2);
    assert_eq!(counter.load(Ordering::Relaxed), 1);
    Ok(())
}
