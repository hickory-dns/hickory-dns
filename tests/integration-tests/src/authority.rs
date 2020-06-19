use std::str::FromStr;

use trust_dns_client::rr::*;

use trust_dns_server::authority::ZoneType;
use trust_dns_server::store::in_memory::InMemoryAuthority;

#[allow(unused)]
#[allow(clippy::unreadable_literal)]
pub fn create_example() -> InMemoryAuthority {
    use std::net::*;
    use trust_dns_client::rr::rdata::*;

    let origin: Name = Name::parse("example.com.", None).unwrap();
    let mut records = InMemoryAuthority::empty(origin.clone(), ZoneType::Primary, false);

    // example.com.		3600	IN	SOA	sns.dns.icann.org. noc.dns.icann.org. 2015082403 7200 3600 1209600 3600
    records.upsert(
        Record::new()
            .set_name(origin.clone())
            .set_ttl(3600)
            .set_rr_type(RecordType::SOA)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::SOA(SOA::new(
                Name::parse("sns.dns.icann.org.", None).unwrap(),
                Name::parse("noc.dns.icann.org.", None).unwrap(),
                2015082403,
                7200,
                3600,
                1209600,
                3600,
            )))
            .clone(),
        0,
    );

    records.upsert(
        Record::new()
            .set_name(origin.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::NS)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::NS(Name::parse("a.iana-servers.net.", None).unwrap()))
            .clone(),
        0,
    );
    records.upsert(
        Record::new()
            .set_name(origin.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::NS)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::NS(Name::parse("b.iana-servers.net.", None).unwrap()))
            .clone(),
        0,
    );

    // example.com.		60	IN	TXT	"v=spf1 -all"
    //records.upsert(origin.clone(), Record::new().name(origin.clone()).ttl(60).rr_type(RecordType::TXT).dns_class(DNSClass::IN).rdata(RData::TXT{ txt_data: vec!["v=spf1 -all".to_string()] }).clone());
    // example.com.		60	IN	TXT	"$Id: example.com 4415 2015-08-24 20:12:23Z davids $"
    records.upsert(
        Record::new()
            .set_name(origin.clone())
            .set_ttl(60)
            .set_rr_type(RecordType::TXT)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::TXT(TXT::new(vec![
                "$Id: example.com 4415 2015-08-24 \
                 20:12:23Z davids $"
                    .to_string(),
            ])))
            .clone(),
        0,
    );

    // example.com.		86400	IN	A	93.184.216.34
    records.upsert(
        Record::new()
            .set_name(origin.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 34)))
            .clone(),
        0,
    );

    // example.com.		86400	IN	AAAA	2606:2800:220:1:248:1893:25c8:1946
    records.upsert(
        Record::new()
            .set_name(origin)
            .set_ttl(86400)
            .set_rr_type(RecordType::AAAA)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::AAAA(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            )))
            .clone(),
        0,
    );

    // TODO support these later...

    // example.com.		3600	IN	RRSIG	NSEC 8 2 3600 20150926015219 20150905040848 54108 example.com. d0AXd6QRITqLeiYbQUlJ5O0Og9tSjk7IlxQr9aJO+r+rc1g0dW9i9OCc XXQxdC1/zyubecjD6kSs3vwxzzEEupivaKHKtNPXdnDZ5UUiaIC1VU9l 9h/ik+AR4rCTY6dYPCI6lafD/TlqQLbpEnb34ywkRpl5G3pasPrwEY7b nrAndEY=
    // example.com.		3600	IN	NSEC	www.example.com. A NS SOA TXT AAAA RRSIG NSEC DNSKEY
    // example.com.		86400	IN	RRSIG	NS 8 2 86400 20150915033148 20150824191224 54108 example.com. O2TCB5/v/b1XGlTQEj0/oGKp7dTueQ7zRmCtADDEDWrzLdWrKcmDGF37 mgKejcAlSYVhWLxyLlet7KqJhLu+oQcDTNf/BT3vNX/Ivx3sKhUUMpfi 8Mn5zhRqM9gbzZVCS/toJIYqOBqvAkS7UpkmpLzl0Zt2h4j0Gp/8GwRb ZU67l6M=
    // example.com.		86400	IN	RRSIG	AAAA 8 2 86400 20150914212400 20150824191224 54108 example.com. AHd2BDNjtg4jPRQwyT4FHtlVTZDZ6IIusYVGCzWfnt5SZOoizyXnJhqX 44MeVTqi1/2cskpKvRkK3bkYnVUcjZiFgSaa9xJHmXrslaTr5mOmXt9s 6k95N1daYKhDKKcr0M4TXLUgdnBr+/pMFiLsyOoDb8GJDT8Llmpk52Ie ysJX8BY=
    // example.com.		86400	IN	RRSIG	A 8 2 86400 20150914083326 20150824191224 54108 example.com. La1p2R7GPMrXEm3kcznSJ70sOspmfSDsgOZ74GlzgaFfMRveA20IDUnZ /HI9M95/tBWbHdHBtm9aCK+4n7EluhNPTAT1+88V6xK7Lc7pcBfBXIHg DAdUoj26VIh7NRml/0QR0dFu4PriA/wLNe+d1Q961qf0JZP80TU4IMBC X/W6Ijk=
    // example.com.		60	IN	RRSIG	TXT 8 2 60 20150914201612 20150824191224 54108 example.com. Be/bPvaVVK/o66QOHJZMFBDCQVhP44jptS9sZe8Vpfmzd72/v+1gwn1z u2+xisePSpAMtDZsFJgqsCjpbLFvmhNdh8ktlq/kuCME5hZs7qY7DZIB VwkSTsJPIq8qhX22clfIbqzaypuIX9ajWr+5i0nGQLNekMB07t4/GCoJ q5QpQoE=
    // example.com.		3600	IN	RRSIG	DNSKEY 8 2 3600 20150914090528 20150824071818 31406 example.com. rZJRBwHhYzCDwkDEXqECHNWezTNj2A683I/yHHqD1j9ytGHGskGEEyJC i5fk70YCm64GqDYKu70kgv7hCFqc4OM3aD88QDe3L4Uv7ZXqouNbjTEO 3BEBI13GetRkK5qLndl30Y/urOBASQFELQUJsvQBR2gJMdQsb6G0mHIW rubY2SxAGa9rQW7yehRQNK4ME37FqINBDuIV9o7kULPhn9Ux1Qx62prd 9nikzamGxFL+9dFDOfnYVw2C/OgGJNIXh5QyKMG4qXmXb6sB/V3P+FE+ +vkt3RToE2xPN5bf1vVIlEJof6LtojrowwnZpiphTXFJF/BJrgiotGt3 Gsd8Cw==
    // example.com.		3600	IN	DNSKEY	256 3 8 AwEAAcZMEndf6/+kG6Dp7re/grJ9f5CP5bQplBGokyxbM4oPNeBfWMIC +xY+ICgTyJarVB4aPYNMV7znsHM4XwU8hfpZ3ZcmT+69KyGqs+tt2pc/ si30dnUpPo/AMnN7Kul2SgqT9g1bb5O0D/CH2txo6YXr/BbuNHLqAh/x mof1QYkl6GoP
    // example.com.		3600	IN	DNSKEY	256 3 8 AwEAAeZFCLkW/sztmJmpmZo/udvAyqshiLO34zHzzkVPrhuUBA/xb3wk YeCvMO6iBxCD+/Dk7fWEAT1NR21bDKHySVHE5cre+fqnXI+9NCjkMoBE 193j8G5HscIpWpG1qgkelBhmucfUPv+R4AIhpfjc352eh1q/SniYUGR4 fytlDZVXCLhL
    // example.com.		3600	IN	DNSKEY	257 3 8 AwEAAbOFAxl+Lkt0UMglZizKEC1AxUu8zlj65KYatR5wBWMrh18TYzK/ ig6Y1t5YTWCO68bynorpNu9fqNFALX7bVl9/gybA0v0EhF+dgXmoUfRX 7ksMGgBvtfa2/Y9a3klXNLqkTszIQ4PEMVCjtryl19Be9/PkFeC9ITjg MRQsQhmB39eyMYnal+f3bUxKk4fq7cuEU0dbRpue4H/N6jPucXWOwiMA kTJhghqgy+o9FfIp+tR/emKao94/wpVXDcPf5B18j7xz2SvTTxiuqCzC MtsxnikZHcoh1j4g+Y1B8zIMIvrEM+pZGhh/Yuf4RwCBgaYCi9hpiMWV vS4WBzx0/lU=
    // example.com.		3600	IN	RRSIG	SOA 8 2 3600 20150926132522 20150905040848 54108 example.com. q8psdDPaJVo9KPVgMNR2N1by3LMEci+3HyTmN/Xv3DgDFG5MqNlX9Dfj dUBIMbvYmkUUPQ9fIWYA+ldmDHiRBiHIcvvk/LYD8mODWL6RoF+GEsW0 zm43RNBnbE41wtNrch5WU/q1ko2svB98ooqePWWuFzmdyPpidtLCgSCz FCiCiVQ=

    // www
    let www_name: Name = Name::parse("www.example.com.", None).unwrap();

    // www.example.com.	86400	IN	TXT	"v=spf1 -all"
    records.upsert(
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::TXT)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::TXT(TXT::new(vec!["v=spf1 -all".to_string()])))
            .clone(),
        0,
    );

    // www.example.com.	86400	IN	A	93.184.216.34
    records.upsert(
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 34)))
            .clone(),
        0,
    );

    // www.example.com.	86400	IN	AAAA	2606:2800:220:1:248:1893:25c8:1946
    records.upsert(
        Record::new()
            .set_name(www_name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::AAAA)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::AAAA(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
            )))
            .clone(),
        0,
    );

    // alias 86400 IN www
    records.upsert(
        Record::new()
            .set_name(Name::from_str("alias.example.com.").unwrap())
            .set_ttl(86400)
            .set_rr_type(RecordType::CNAME)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::CNAME(www_name))
            .clone(),
        0,
    );

    // alias2 86400 IN www, multiple cname chains
    records.upsert(
        Record::new()
            .set_name(Name::from_str("alias2.example.com.").unwrap())
            .set_ttl(86400)
            .set_rr_type(RecordType::CNAME)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::CNAME(Name::from_str("alias.example.com.").unwrap()))
            .clone(),
        0,
    );

    // www.example.com.	3600	IN	RRSIG	NSEC 8 3 3600 20150925215757 20150905040848 54108 example.com. ZKIVt1IN3O1FWZPSfrQAH7nHt7RUFDjcbh7NxnEqd/uTGCnZ6SrAEgrY E9GMmBwvRjoucphGtjkYOpPJPe5MlnTHoYCjxL4qmG3LsD2KD0bfPufa ibtlQZRrPglxZ92hBKK3ZiPnPRe7I9yni2UQSQA7XDi7CQySYyo490It AxdXjAo=
    // www.example.com.	3600	IN	NSEC	example.com. A TXT AAAA RRSIG NSEC
    // www.example.com.	86400	IN	RRSIG	TXT 8 3 86400 20150914142952 20150824191224 54108 example.com. LvODnPb7NLDZfHPBOrr/qLnOKA670vVYKQSk5Qkz3MPNKDVAFJqsP2Y6 UYcypSJZfcSjfIk2mU9dUiansU2ZL80OZJUsUobqJt5De748ovITYDJ7 afbohQzPg+4E1GIWMkJZ/VQD3B2pmr7J5rPn+vejxSQSoI93AIQaTpCU L5O/Bac=
    // www.example.com.	86400	IN	RRSIG	AAAA 8 3 86400 20150914082216 20150824191224 54108 example.com. kje4FKE+7d/j4OzWQelcKkePq6DxCRY/5btAiUcZNf+zVNlHK+o57h1r Y76ZviWChQB8Np2TjA1DrXGi/kHr2KKE60H5822mFZ2b9O+sgW4q6o3G kO2E1CQxbYe+nI1Z8lVfjdCNm81zfvYqDjo2/tGqagehxG1V9MBZO6br 4KKdoa4=
    // www.example.com.	86400	IN	RRSIG	A 8 3 86400 20150915023456 20150824191224 54108 example.com. cWtw0nMvcXcYNnxejB3Le3KBfoPPQZLmbaJ8ybdmzBDefQOm1ZjZZMOP wHEIxzdjRhG9mLt1mpyo1H7OezKTGX+mDtskcECTl/+jB/YSZyvbwRxj e88Lrg4D+D2MiajQn3XSWf+6LQVe1J67gdbKTXezvux0tRxBNHHqWXRk pxCILes=

    records
}

#[cfg(feature = "dnssec")]
#[allow(unused)]
pub fn create_secure_example() -> InMemoryAuthority {
    use chrono::Duration;
    use openssl::rsa::Rsa;
    use trust_dns_client::rr::dnssec::*;
    use trust_dns_server::authority::Authority;

    let mut authority = create_example();
    let rsa = Rsa::generate(2048).unwrap();
    let key = KeyPair::from_rsa(rsa).unwrap();
    let dnskey = key.to_dnskey(Algorithm::RSASHA256).unwrap();
    let signer = Signer::dnssec(
        dnskey,
        key,
        authority.origin().clone().into(),
        Duration::weeks(1),
    );

    authority.add_zone_signing_key(signer);
    authority.secure_zone();

    authority
}
