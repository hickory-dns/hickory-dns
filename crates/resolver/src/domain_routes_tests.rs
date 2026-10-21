//! Domain routing tests through the public resolver API and a mock network.

use std::net::IpAddr;

use test_support::{MockNetworkHandler, MockProvider, MockRecord};

use crate::{
    Resolver,
    config::{DomainRoute, LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig},
    proto::{
        op::ResponseCode,
        rr::{Name, RecordType},
    },
};

const DEFAULT: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
const PRIVATE: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2));
const SPECIFIC: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 3));
const ANSWER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1));

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

fn route(domain: &str, ip: IpAddr) -> DomainRoute {
    DomainRoute::new(name(domain), vec![NameServerConfig::udp(ip)])
}

fn builder(
    routes: Vec<DomainRoute>,
    provider: MockProvider,
) -> crate::ResolverBuilder<MockProvider> {
    let mut config = ResolverConfig::from_name_servers(vec![NameServerConfig::udp(DEFAULT)]);
    config.domain_routes = routes;
    let mut builder = Resolver::builder_with_config(config, provider);
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
    builder.options_mut().use_hosts_file = ResolveHosts::Never;
    builder.options_mut().attempts = 1;
    builder
}

#[tokio::test]
async fn routes_use_longest_suffix_case_insensitively_on_label_boundaries() {
    let cases = [
        ("host.corp.example.", PRIVATE),
        ("HOST.Dev.CoRp.ExAmPlE.", SPECIFIC),
        ("corp.example.", PRIVATE),
        ("host.notcorp.example.", DEFAULT),
        ("corp.example.attacker.test.", DEFAULT),
    ];
    let records = cases
        .iter()
        .map(|(host, server)| MockRecord::a(*server, &name(host), ANSWER))
        .collect();
    let provider = MockProvider::new(MockNetworkHandler::new(records));
    let resolver = builder(
        vec![
            route("corp.example.", PRIVATE),
            route("dev.corp.example.", SPECIFIC),
        ],
        provider.clone(),
    )
    .build()
    .unwrap();
    for (host, expected) in cases {
        assert_eq!(
            resolver.lookup_ip(host).await.unwrap().iter().next(),
            Some(ANSWER)
        );
        assert!(
            provider
                .queries(&expected)
                .iter()
                .any(|query| query.name == name(host))
        );
        for other in [DEFAULT, PRIVATE, SPECIFIC] {
            if other != expected {
                assert!(
                    !provider
                        .queries(&other)
                        .iter()
                        .any(|query| query.name == name(host))
                );
            }
        }
    }
}

#[tokio::test]
async fn failed_private_queries_never_reach_default_or_parent_routes() {
    let host = name("secret.dev.corp.example.");
    let records = vec![
        MockRecord::a(DEFAULT, &host, ANSWER),
        MockRecord::a(PRIVATE, &host, ANSWER),
        MockRecord::a(SPECIFIC, &host, ANSWER),
    ];
    let handler = MockNetworkHandler::new(records).with_mutation(Box::new(|_, _, response| {
        response.answers.clear();
        response.metadata.response_code = ResponseCode::NXDomain;
    }));
    let provider = MockProvider::new(handler);
    let resolver = builder(
        vec![
            route("corp.example.", PRIVATE),
            route("dev.corp.example.", SPECIFIC),
        ],
        provider.clone(),
    )
    .build()
    .unwrap();
    assert!(resolver.lookup_ip(host.clone()).await.is_err());
    assert!(!provider.queries(&SPECIFIC).is_empty());
    assert!(provider.queries(&DEFAULT).is_empty());
    assert!(provider.queries(&PRIVATE).is_empty());
}

#[tokio::test]
async fn empty_private_route_fails_closed() {
    let host = name("secret.corp.example.");
    let provider = MockProvider::new(MockNetworkHandler::new(vec![MockRecord::a(
        DEFAULT, &host, ANSWER,
    )]));
    let resolver = builder(
        vec![DomainRoute::new(name("corp.example."), vec![])],
        provider.clone(),
    )
    .build()
    .unwrap();
    assert!(resolver.lookup_ip(host).await.is_err());
    assert!(provider.queries(&DEFAULT).is_empty());
}

#[tokio::test]
async fn same_domain_configurations_follow_search_order() {
    let host = name("host.corp.example.");
    let handler = MockNetworkHandler::new(vec![
        MockRecord::a(PRIVATE, &host, ANSWER),
        MockRecord::a(SPECIFIC, &host, ANSWER),
    ])
    .with_mutation(Box::new(|server, _, response| {
        if server == PRIVATE {
            response.answers.clear();
            response.metadata.response_code = ResponseCode::NXDomain;
        }
    }));
    let provider = MockProvider::new(handler);
    let mut later = route("corp.example.", SPECIFIC);
    later.search_order = 200;
    let mut first = route("corp.example.", PRIVATE);
    first.search_order = 100;
    let resolver = builder(vec![later, first], provider.clone())
        .build()
        .unwrap();
    assert_eq!(
        resolver.lookup_ip(host).await.unwrap().iter().next(),
        Some(ANSWER)
    );
    assert!(!provider.queries(&PRIVATE).is_empty());
    assert!(!provider.queries(&SPECIFIC).is_empty());
    assert!(provider.queries(&DEFAULT).is_empty());
}

#[tokio::test]
async fn cname_targets_are_routed_and_dns_ttls_are_retained() {
    let host = name("alias.corp.example.");
    let target = name("target.public.example.");
    let provider = MockProvider::new(MockNetworkHandler::new(vec![
        MockRecord::cname(PRIVATE, &host, &target),
        MockRecord::a(DEFAULT, &target, ANSWER),
    ]));
    let resolver = builder(vec![route("corp.example.", PRIVATE)], provider.clone())
        .build()
        .unwrap();
    let result = resolver.lookup_ip(host.clone()).await.unwrap();
    assert_eq!(result.iter().next(), Some(ANSWER));
    assert!(
        result
            .as_lookup()
            .answers()
            .iter()
            .all(|record| record.ttl == 3600)
    );
    assert_eq!(provider.queries(&PRIVATE).len(), 1);
    assert_eq!(provider.queries(&DEFAULT).len(), 1);
    assert_eq!(provider.queries(&DEFAULT)[0].name, target);
    resolver.lookup_ip(host).await.unwrap();
    assert_eq!(provider.queries(&PRIVATE).len(), 1);
    assert_eq!(provider.queries(&DEFAULT).len(), 1);
}

#[tokio::test]
async fn generic_record_lookups_use_domain_routes() {
    let host = name("config.corp.example.");
    let provider = MockProvider::new(MockNetworkHandler::new(vec![MockRecord::txt(
        PRIVATE,
        &host,
        vec!["value".into()],
    )]));
    let resolver = builder(vec![route("corp.example.", PRIVATE)], provider.clone())
        .build()
        .unwrap();
    let lookup = resolver.lookup(host, RecordType::TXT).await.unwrap();
    assert_eq!(lookup.answers().len(), 1);
    assert!(provider.queries(&DEFAULT).is_empty());
}

#[tokio::test]
async fn address_filtering_remains_enforced_for_routed_answers() {
    let host = name("host.corp.example.");
    let provider = MockProvider::new(MockNetworkHandler::new(vec![MockRecord::a(
        PRIVATE, &host, ANSWER,
    )]));
    let mut builder = builder(vec![route("corp.example.", PRIVATE)], provider.clone());
    builder.options_mut().deny_answers = vec!["198.51.100.0/24".parse().unwrap()];
    assert!(builder.build().unwrap().lookup_ip(host).await.is_err());
    assert!(provider.queries(&DEFAULT).is_empty());
}

#[tokio::test]
async fn root_routes_replace_defaults_but_allow_more_specific_routes() {
    let host = name("public.example.");
    let private = name("host.corp.example.");
    let provider = MockProvider::new(MockNetworkHandler::new(vec![
        MockRecord::a(PRIVATE, &host, ANSWER),
        MockRecord::a(SPECIFIC, &private, ANSWER),
    ]));
    let resolver = builder(
        vec![route(".", PRIVATE), route("corp.example.", SPECIFIC)],
        provider.clone(),
    )
    .build()
    .unwrap();
    resolver.lookup_ip(host).await.unwrap();
    resolver.lookup_ip(private).await.unwrap();
    assert!(provider.queries(&DEFAULT).is_empty());
    assert_eq!(provider.queries(&PRIVATE).len(), 1);
    assert_eq!(provider.queries(&SPECIFIC).len(), 1);
}

#[cfg(feature = "serde")]
#[test]
fn existing_serialized_configuration_has_no_routes() {
    let config = ResolverConfig::from_name_servers(vec![NameServerConfig::udp(DEFAULT)]);
    let mut value = serde_json::to_value(config).unwrap();
    value.as_object_mut().unwrap().remove("domain_routes");
    let parsed: ResolverConfig = serde_json::from_value(value).unwrap();
    assert!(parsed.domain_routes.is_empty());
}

#[cfg(feature = "__dnssec")]
#[tokio::test]
async fn routed_answers_do_not_bypass_dnssec_validation() {
    let host = name("host.corp.example.");
    let provider = MockProvider::new(MockNetworkHandler::new(vec![MockRecord::a(
        PRIVATE, &host, ANSWER,
    )]));
    let mut builder = builder(vec![route("corp.example.", PRIVATE)], provider.clone());
    builder.options_mut().validate = true;
    assert!(builder.build().unwrap().lookup_ip(host).await.is_err());
    assert!(provider.queries(&DEFAULT).is_empty());
    assert!(provider.queries(&PRIVATE).len() > 1);
}

#[derive(Clone)]
struct PendingConnections {
    inner: MockProvider,
    pending: tokio::sync::watch::Receiver<bool>,
}

impl crate::connection_provider::ConnectionProvider for PendingConnections {
    type Conn = <MockProvider as crate::connection_provider::ConnectionProvider>::Conn;
    type FutureConn = <MockProvider as crate::connection_provider::ConnectionProvider>::FutureConn;
    type RuntimeProvider = MockProvider;

    fn runtime_provider(&self) -> &MockProvider {
        &self.inner
    }

    fn new_connection(
        &self,
        ip: IpAddr,
        config: &crate::config::ConnectionConfig,
        context: &crate::name_server_pool::PoolContext,
    ) -> Result<Self::FutureConn, crate::net::NetError> {
        let mut pending = self.pending.clone();
        let connection = self.inner.new_connection(ip, config, context)?;
        Ok(Box::pin(async move {
            while ip == PRIVATE && *pending.borrow_and_update() {
                pending
                    .changed()
                    .await
                    .map_err(|_| crate::net::NetError::from("test connection control closed"))?;
            }
            connection.await
        }))
    }
}

#[tokio::test(start_paused = true)]
async fn route_deadline_and_cancellation_release_shared_queries() {
    use std::time::Duration;
    let host = name("host.corp.example.");
    let inner = MockProvider::new(MockNetworkHandler::new(vec![MockRecord::a(
        PRIVATE, &host, ANSWER,
    )]));
    let (control, pending) = tokio::sync::watch::channel(true);
    let provider = PendingConnections {
        inner: inner.clone(),
        pending: pending.clone(),
    };
    let mut config = ResolverConfig::from_name_servers(vec![NameServerConfig::udp(DEFAULT)]);
    config.domain_routes = vec![route("corp.example.", PRIVATE)];
    let mut builder = Resolver::builder_with_config(config, provider);
    builder.options_mut().attempts = 0;
    builder.options_mut().use_hosts_file = ResolveHosts::Never;
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
    builder.options_mut().timeout = Duration::from_secs(5);
    let resolver = builder.build().unwrap();
    let start = tokio::time::Instant::now();
    assert!(matches!(
        resolver.lookup_ip(host.clone()).await,
        Err(crate::net::NetError::Timeout)
    ));
    assert_eq!(start.elapsed(), Duration::from_secs(5));
    tokio::select! {
        result = resolver.lookup_ip(host.clone()) => panic!("query completed before cancellation: {result:?}"),
        _ = tokio::time::sleep(Duration::from_secs(1)) => {}
    }
    control.send(false).unwrap();
    assert_eq!(
        resolver.lookup_ip(host).await.unwrap().iter().next(),
        Some(ANSWER)
    );
    assert!(inner.queries(&DEFAULT).is_empty());
}

#[tokio::test(start_paused = true)]
async fn unreachable_route_leaves_time_for_a_backup_for_the_same_domain() {
    use std::time::Duration;
    let host = name("host.corp.example.");
    let inner = MockProvider::new(MockNetworkHandler::new(vec![MockRecord::a(
        SPECIFIC, &host, ANSWER,
    )]));
    let (_control, pending) = tokio::sync::watch::channel(true);
    let provider = PendingConnections {
        inner: inner.clone(),
        pending,
    };
    let mut config = ResolverConfig::from_name_servers(vec![NameServerConfig::udp(DEFAULT)]);
    let mut backup = route("corp.example.", SPECIFIC);
    backup.search_order = 200;
    config.domain_routes = vec![route("corp.example.", PRIVATE), backup];
    let mut builder = Resolver::builder_with_config(config, provider);
    builder.options_mut().attempts = 0;
    builder.options_mut().use_hosts_file = ResolveHosts::Never;
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
    builder.options_mut().timeout = Duration::from_secs(5);
    let start = tokio::time::Instant::now();
    assert_eq!(
        builder
            .build()
            .unwrap()
            .lookup_ip(host)
            .await
            .unwrap()
            .iter()
            .next(),
        Some(ANSWER)
    );
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(inner.queries(&DEFAULT).is_empty());
}
