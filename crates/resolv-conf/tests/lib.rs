extern crate resolv_conf;

use resolv_conf::{Network, ScopedIp, Lookup, Family};
use std::path::Path;
use std::io::Read;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn test_comment() {
    resolv_conf::Config::parse("#").unwrap();
    resolv_conf::Config::parse(";").unwrap();
    resolv_conf::Config::parse("#junk").unwrap();
    resolv_conf::Config::parse("# junk").unwrap();
    resolv_conf::Config::parse(";junk").unwrap();
    resolv_conf::Config::parse("; junk").unwrap();
}

fn ip(s: &str) -> ScopedIp {
    s.parse().unwrap()
}

fn parse_str(s: &str) -> resolv_conf::Config {
    resolv_conf::Config::parse(s).unwrap()
}

#[test]
fn test_basic_options() {
    assert_eq!(
        parse_str("nameserver 127.0.0.1").nameservers,
        vec![ip("127.0.0.1")]
    );
    assert_eq!(
        parse_str("search localnet.*").get_search(),
        Some(vec!["localnet.*".to_string()]).as_ref()
    );
    assert_eq!(
        parse_str("domain example.com.").get_domain(),
        Some(String::from("example.com.")).as_ref()
    );
}

#[test]
fn test_trust_ad() {
    assert_eq!(
        parse_str("options edns0 trust-ad").trust_ad,
        true
    );
}

#[test]
fn test_no_reload() {
    assert_eq!(
        parse_str("options no-reload").no_reload,
        true
    );
}

#[test]
fn test_extra_whitespace() {
    assert_eq!(
        parse_str("domain       example.com.").get_domain(),
        Some(String::from("example.com.")).as_ref()
    );
    assert_eq!(
        parse_str("domain   example.com.   ").get_domain(),
        Some(String::from("example.com.")).as_ref()
    );
    // hard tabs
    assert_eq!(
        parse_str("	domain		example.com.		").get_domain(),
        Some(String::from("example.com.")).as_ref()
    );
    // hard tabs + spaces
    assert_eq!(
        parse_str(" 	domain  		example.com.	 	").get_domain(),
        Some(String::from("example.com.")).as_ref()
    );
}

#[test]
fn test_invalid_lines() {
    assert!(resolv_conf::Config::parse("nameserver 10.0.0.1%1").is_err());
    assert!(resolv_conf::Config::parse("nameserver 10.0.0.1.0").is_err());
    assert!(resolv_conf::Config::parse("Nameserver 10.0.0.1").is_err());
    assert!(resolv_conf::Config::parse("nameserver 10.0.0.1 domain foo.com").is_err());
    assert!(resolv_conf::Config::parse("invalid foo.com").is_err());
    assert!(resolv_conf::Config::parse("options ndots:1 foo:1").is_err());
}

#[test]
fn test_empty_line() {
    assert_eq!(parse_str(""), resolv_conf::Config::new());
}

#[test]
fn test_multiple_options_on_one_line() {
    let config = parse_str("options ndots:8 attempts:8 rotate inet6 no-tld-query timeout:8");
    assert_eq!(config.ndots, 8);
    assert_eq!(config.timeout, 8);
    assert_eq!(config.attempts, 8);
    assert_eq!(config.rotate, true);
    assert_eq!(config.inet6, true);
    assert_eq!(config.no_tld_query, true);
}

#[test]
fn test_ip() {
    let parsed = ip("FE80::C001:1DFF:FEE0:0%eth0");
    let address = Ipv6Addr::new(0xfe80, 0, 0, 0, 0xc001, 0x1dff, 0xfee0, 0);
    let scope = "eth0".to_string();
    assert_eq!(parsed, ScopedIp::V6(address, Some(scope)));

    let parsed = ip("FE80::C001:1DFF:FEE0:0%1");
    let address = Ipv6Addr::new(0xfe80, 0, 0, 0, 0xc001, 0x1dff, 0xfee0, 0);
    let scope = "1".to_string();
    assert_eq!(parsed, ScopedIp::V6(address, Some(scope)));

    let parsed = ip("FE80::C001:1DFF:FEE0:0");
    let address = Ipv6Addr::new(0xfe80, 0, 0, 0, 0xc001, 0x1dff, 0xfee0, 0);
    assert_eq!(parsed, ScopedIp::V6(address, None));

    assert!("10.0.0.1%1".parse::<ScopedIp>().is_err());
    assert!("10.0.0.1%eth0".parse::<ScopedIp>().is_err());
    assert!("FE80::C001:1DFF:FEE0:0%".parse::<ScopedIp>().is_err());
    assert!("FE80::C001:1DFF:FEE0:0% ".parse::<ScopedIp>().is_err());

    let parsed = ip("192.168.10.1");
    let address = Ipv4Addr::new(192, 168, 10, 1);
    assert_eq!(parsed, ScopedIp::V4(address));
}

#[test]
fn test_nameserver() {
    assert_eq!(
        parse_str("nameserver 127.0.0.1").nameservers[0],
        ip("127.0.0.1")
    );
    assert_eq!(
        parse_str("nameserver 127.0.0.1#comment").nameservers[0],
        ip("127.0.0.1")
    );
    assert_eq!(
        parse_str("nameserver 127.0.0.1;comment").nameservers[0],
        ip("127.0.0.1")
    );
    assert_eq!(
        parse_str("nameserver 127.0.0.1 # another comment").nameservers[0],
        ip("127.0.0.1")
    );
    assert_eq!(
        parse_str("nameserver 127.0.0.1  ; ").nameservers[0],
        ip("127.0.0.1")
    );
    assert_eq!(parse_str("nameserver ::1").nameservers[0], ip("::1"));
    assert_eq!(
        parse_str("nameserver 2001:db8:85a3:8d3:1319:8a2e:370:7348").nameservers[0],
        ip("2001:db8:85a3:8d3:1319:8a2e:370:7348")
    );
    assert_eq!(
        parse_str("nameserver ::ffff:192.0.2.128").nameservers[0],
        ip("::ffff:192.0.2.128")
    );
}

fn parse_file<P: AsRef<Path>>(path: P) -> resolv_conf::Config {
    let mut data = String::new();
    let mut file = File::open(path).unwrap();
    file.read_to_string(&mut data).unwrap();
    resolv_conf::Config::parse(&data).unwrap()
}

#[test]
fn test_parse_simple_conf() {
    let mut config = resolv_conf::Config::new();
    config
        .nameservers
        .push(ScopedIp::V4(Ipv4Addr::new(8, 8, 8, 8)));
    config
        .nameservers
        .push(ScopedIp::V4(Ipv4Addr::new(8, 8, 4, 4)));
    assert_eq!(config, parse_file("tests/resolv.conf-simple"));
}

#[test]
fn test_parse_linux_conf() {
    let mut config = resolv_conf::Config::new();
    config.set_domain(String::from("example.com"));
    config.set_search(vec!["example.com".into(), "sub.example.com".into()]);
    config.nameservers = vec![
        ScopedIp::V6(
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
            None,
        ),
        ScopedIp::V6(
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844),
            None,
        ),
        ScopedIp::V4(Ipv4Addr::new(8, 8, 8, 8)),
        ScopedIp::V4(Ipv4Addr::new(8, 8, 4, 4)),
    ];
    config.ndots = 8;
    config.timeout = 8;
    config.attempts = 8;
    config.rotate = true;
    config.inet6 = true;
    config.no_tld_query = true;
    config.sortlist = vec![
        Network::V4(
            Ipv4Addr::new(130, 155, 160, 0),
            Ipv4Addr::new(255, 255, 240, 0),
        ),
        // This fails currently
        Network::V4(Ipv4Addr::new(130, 155, 0, 0), Ipv4Addr::new(255, 255, 0, 0)),
    ];
    assert_eq!(config, parse_file("tests/resolv.conf-linux"));
}

#[test]
fn test_parse_macos_conf() {
    let mut config = resolv_conf::Config::new();
    config.set_domain(String::from("example.com."));
    config.set_search(vec!["example.com.".into(), "sub.example.com.".into()]);
    config.nameservers = vec![
        ScopedIp::V6(
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
            None,
        ),
        ScopedIp::V6(
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844),
            None,
        ),
        ScopedIp::V4(Ipv4Addr::new(8, 8, 8, 8)),
        ScopedIp::V4(Ipv4Addr::new(8, 8, 4, 4)),
    ];
    config.ndots = 8;
    config.timeout = 8;
    config.attempts = 8;
    assert_eq!(config, parse_file("tests/resolv.conf-macos"));
}

#[test]
fn test_openbsd_conf() {
    let mut config = resolv_conf::Config::new();
    config.nameservers = vec![
        ScopedIp::V4(Ipv4Addr::new(8, 8, 8, 8)),
        ScopedIp::V4(Ipv4Addr::new(8, 8, 4, 4)),
    ];
    config.lookup = vec![Lookup::File, Lookup::Bind];
    assert_eq!(config, parse_file("tests/resolv.conf-openbsd"));
}

#[test]
fn test_openbsd_grammar() {
    let mut config = resolv_conf::Config::new();
    config.lookup = vec![Lookup::File, Lookup::Bind];
    assert_eq!(resolv_conf::Config::parse("lookup file bind").unwrap(), config);

    let mut config = resolv_conf::Config::new();
    config.lookup = vec![Lookup::Bind];
    assert_eq!(resolv_conf::Config::parse("lookup bind").unwrap(), config);

    let mut config = resolv_conf::Config::new();
    config.lookup = vec![Lookup::Extra(String::from("unexpected"))];
    assert_eq!(resolv_conf::Config::parse("lookup unexpected").unwrap(), config);

    let mut config = resolv_conf::Config::new();
    config.family = vec![Family::Inet4, Family::Inet6];
    assert_eq!(resolv_conf::Config::parse("family inet4 inet6").unwrap(), config);

    let mut config = resolv_conf::Config::new();
    config.family = vec![Family::Inet4];
    assert_eq!(resolv_conf::Config::parse("family inet4").unwrap(), config);

    let mut config = resolv_conf::Config::new();
    config.family = vec![Family::Inet6];
    assert_eq!(resolv_conf::Config::parse("family inet6").unwrap(), config);

    assert!(resolv_conf::Config::parse("family invalid").is_err());
}

#[test]
fn test_glibc_normalize() {
    let mut config = resolv_conf::Config::new();
    config.nameservers = vec![
        ScopedIp::V6(
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
            None,
        ),
        ScopedIp::V6(
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844),
            None,
        ),
        ScopedIp::V4(Ipv4Addr::new(8, 8, 8, 8)),
        ScopedIp::V4(Ipv4Addr::new(8, 8, 4, 4)),
    ];

    config.set_search(vec![
        "a.example.com".into(),
        "b.example.com".into(),
        "c.example.com".into(),
        "d.example.com".into(),
        "e.example.com".into(),
        "f.example.com".into(),
        "g.example.com".into(),
        "h.example.com".into(),
    ]);

    config.glibc_normalize();
    assert_eq!(
        vec![
            ScopedIp::V6(
                Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
                None,
            ),
            ScopedIp::V6(
                Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844),
                None,
            ),
            ScopedIp::V4(Ipv4Addr::new(8, 8, 8, 8)),
        ],
        config.nameservers
    );

    assert_eq!(
        Some(&vec![
            "a.example.com".into(),
            "b.example.com".into(),
            "c.example.com".into(),
            "d.example.com".into(),
            "e.example.com".into(),
            "f.example.com".into()
        ]),
        config.get_search()
    );
}

#[test]
fn test_get_nameservers_or_local() {
    let config = resolv_conf::Config::new();
    assert_eq!(
        vec![
            ScopedIp::from(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            ScopedIp::from(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
        ],
        config.get_nameservers_or_local()
    );
}

#[test]
#[cfg(feature = "system")]
#[ignore]
fn test_get_system_domain() {
    let config = resolv_conf::Config::new();
    assert_eq!(Some("lan".into()), config.get_system_domain());
}

#[test]
fn test_default_display() {
    let original_config = resolv_conf::Config::new();
    let output = original_config.to_string();
    let restored_config = resolv_conf::Config::parse(&output).unwrap();

    assert_eq!(original_config, restored_config);
}

#[test]
fn test_non_default_display() {
    let mut original_config = resolv_conf::Config::new();

    original_config.nameservers = vec![
        ip("192.168.0.94"),
        ip("fe80::0123:4567:89ab:cdef"),
        ip("fe80::0123:4567:89ab:cdef%zone"),
    ];

    original_config.sortlist = vec![
        Network::V4(
            "192.168.1.94".parse().unwrap(),
            "255.255.252.0".parse().unwrap(),
        ),
        Network::V6("fe80::0123".parse().unwrap(), "fe80::cdef".parse().unwrap()),
    ];

    original_config.set_domain("my.domain".to_owned());

    original_config.set_search(
        vec!["my.domain", "alt.domain"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    );

    original_config.debug = true;
    original_config.ndots = 4;
    original_config.timeout = 20;
    original_config.attempts = 5;
    original_config.rotate = true;
    original_config.no_check_names = true;
    original_config.inet6 = true;
    original_config.ip6_bytestring = true;
    original_config.ip6_dotint = true;
    original_config.edns0 = true;
    original_config.single_request = true;
    original_config.single_request_reopen = true;
    original_config.no_tld_query = true;
    original_config.use_vc = true;

    let output = original_config.to_string();
    println!("Output:\n\n{}", output);
    let restored_config = resolv_conf::Config::parse(&output).unwrap();

    assert_eq!(original_config, restored_config);
}

#[test]
fn test_display_preservers_last_search() {
    let mut original_config = resolv_conf::Config::new();

    original_config.set_search(
        vec!["my.domain", "alt.domain"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    );

    original_config.set_domain("my.domain".to_owned());

    let output = original_config.to_string();
    println!("Output:\n\n{}", output);
    let restored_config = resolv_conf::Config::parse(&output).unwrap();

    assert_eq!(original_config, restored_config);
}
