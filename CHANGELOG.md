# Change Log: Hickory DNS (formerly, Trust-DNS)

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/).

All notes should be prepended with the location of the change, e.g. `(proto)` or `(resolver)`.

## 0.25.0

### Fixed

- (recursor) send DS queries to the parent zone #2203 by japaric
- (docs) add RFC2931 SIG(0) as supported #2216 by bluejekyll
- (recursor) respect DO bit in incoming queries #2196 by japaric
- (docs) doc: fix misc typos in md files #2198 by divagant-martian
- (test) update ip of example.com #2187 by situ2001
- (all) Update mio to 0.8.11 to fix RUSTSEC-2024-0019 #2166 by marcus0x62
- (proto) Fix formatting issue in crates/proto/src/op/message.rs #2165 by marcus0x62
- (proto) fix internal representation of OPT #2151 by esensar
- (proto) ECH service parameter key corrected from  "echconfig" to "ech" #2183 by cpu
- (proto) SVCB/HTTPS record parsing fixes (quoted values, arbitrary numeric keys, lists containing delim) #2183 by cpu

### Changed

- (proto) dns-test: make NameServer's FQDN more stable #2235 by japaric
- (proto) refactor the Resource data structure #2231 by japaric
- (tests) Add just recipes to clean leftover containers and networks #2232 by pvdrz
- (tests) ci: pin nightly version #2224 by japaric
- (server) cargo: Enable LTO on release build #2141 by jpds
- (resolver) Retry tcp on udp io errors #2215 by bluejekyll
- (recursor) tweaks for security awareness #2208 by djc
- (all) address new clippy lint assigning-clones #2205 by divagant-martian
- (proto) error: wrap io::Error in Arc for clone #2181 by cpu
- (resolver) err for dns-over-rustls w/o roots #2179 by cpu
- (resolver) Forward hickory-dns's root cert features to hickory-resolver #2153 by hch12907
- (proto) Better DNSSEC proofs #2084 by bluejekyll
- (proto) update version for http/h2/h3 #2138 by zh-jq
- (server) Use cargo environment variables for path to executable #2130 by sjbronner
- (proto) Only DNSKEY zone keys are allowed to match DS RR #2131 by justahero
- (docs) Fix a typo in crate description #2132 by wiktor-k
- (all) Gate tests on required features #2114 by alexanderkjall
- (resolver) Fixup lookup docs #2123 by bluejekyll
- (proto) when comparing IP addresses for UDP, only check IP and Port #2124 by bluejekyll
- (recursor) Recursor: make nameserver and record cache sizes configurable #2117 by marcus0x62
- (proto) Validate response query section #2118 by marcus0x62
- (proto) Increase source port entropy in UDP client #2116 by marcus0x62
- (all) get(0) to first() and zerocopy package updates to fix clippy and cargo audit errors #2121 by marcus0x62
- (resolver) Add getters for resolver config and options #2093 by hoxxep
- (client) updated h2_client_connection and web-pki-roots config #2088 by marcbrevoort-cyberhive
- (proto) EchConfig renamed to EchConfigList to match content #2183 by cpu
- (proto) EchConfigList updated to wrap TLS presentation language encoding of content #2183 by cpu

### Added

- (tests) import DNSSEC conformance test suite repository #2222 by japaric
- (client) Adds deref call in assertion for hickory-client README example #2173 by akappel
- (proto) Make hickory_proto::h3::H3ClientStream Clonable #2182 by 0xffffharry
- (proto) Make hickory_proto::quic::QuicClientStream Clonable #2176 by 0xffffharry
- (proto) feat: add setter methods for Message struct to improve configurability #2147 by situ2001
- (proto) add getter/setter methods to ClientSubnet #2146 by leshow
- (server) Add option to specify a restricted set of networks capable of accessing the Hickory DNS server #2126 by bluejekyll
- (recursor) Bailiwick checking for the recursor #2119 by marcus0x62
- (proto) Support getting and setting the EDNS Z flags #2111 by mattias-p

### Removed

- (all) Remove broken mtls code to fix CI #2218 by djc
- (proto) Remove generic Error from DnsHandle #2094 by bluejekyll

## 0.24.1

### Fixed

- (proto) Break when socket is unexpectedly shut down #2171 by dlon

## 0.24.0

**NOTICE** This project has been rebranded to Hickory DNS and has been moved to the https://github.com/hickory-dns/hickory-dns organization and repo, from 0.24.0 onward. This [blog post](https://bluejekyll.github.io/blog/posts/announcing-hickory-dns/) explains the reasoning behind this move.

### Changed

- (proto) Make DnsHandle::send &self instead of &mut self #2018 by ibigbug
- (all) Update dependencies (avoid vulnerability), optional TOML, remove unused dependencies #2028 by djc
- (server) Privatize the Lexer API #2040 by djc
- (server) Use consistent error type for read_system_conf() #2047 by djc
- (server) Optimized shutdown_gracefully() #2041 by caobug

### Added

- (server) add register with rustls server config #2004 by yaotthaha
- (all) Add webpki-roots and native-certs crate features #2005 by daxpedda
- (bin) add run-example target to justfile to simply start trust-dns for manual testing #2020 by bluejekyll
- (all) DoH3 support #1987 by daxpedda

### Fixed

- (bin) Add root certificates to the binary crate #2059 by daxpedda
- (proto) proto/rr: do not deserialize ClientSubnets with invalid prefixes #2057 by 00xc
- (resolver) Fix the resolver version warning in the workspace #2013 by bluejekyll
- (proto) Forward serde-config feature to the proto crate #2019 by cetanu
- (server) Prevent task reaping from blocking #2023 by lpraneis
- (proto) Dont panic on nsec without dnssec #2025 by bluejekyll
- (server) Spawn H2 Data frame processing into a separate task #2033 by yaroslavros
- (proto) DoQ default configuration #2036 by daxpedda
- (resolver) caching bug when CNAME leads to negative response #2053 by Clendenin

### Removed

- (resolver) Remove Copy from ResolverOpts #2029 by daxpedda

## 0.23.1, NOTE: Before this point the project was formerly known as Trust-DNS

### Changed

- (all) **NOTICE** This project has been rebranded to Hickory DNS and has been moved to the https://github.com/hickory-dns/hickory-dns organization and repo, from 0.24.0 onward.

## 0.23.0

### Fixed

- (resolver) Malformed label: -- when parsing resolv.conf #1985 by Jake-Shadle
- (proto) Fix truncation for UDP #1975 by nmittler 
- (proto) avoid panicking in parse_time() #1964 by djc
- (server) Merge up deny response in requests to server #1954 by djc
- (proto) remove duplicate is_soa function #1948 by mattsse
- (resolver) Fix minimal tokio version requirement #1931 by Gelbpunkt
- (all) Fix bench errors in rust-analyzer #1777 by jeff-hiner
- (all) Regenerate the test SSL certificates #1781 by ssinger
- (all) Fix some spelling errors #1783 by nhurley3
- (proto) proto: only allow ASCII characters in CAA key/value data #1796 by djc
- (proto) [rfc8659] CAA RR Change references to RFC 6844 to 8659 #1798 by darnuria
- (all) Fixed some clippy warning #1801 by darnuria
- (all) Fix links to client documentation #1808 by clint-white
- (all) fix cleanliness for 1.65 #1821 by bluejekyll
- (proto) Fix stuck of dns over tls with clear text SNI #1826 by mokeyish
- (all) Fix enabling only dns-over-* feature #1833 by NobodyXu
- (proto) OpenSSL 3.0 compliant #1841 by HLFH
- (server) FIX WIP: Zone Parser panics when hostname entry has a leading whitespace. #1842 by wuerges
- (server) Fix $TTL not taken into account with wildcard from zonefile. #1850 by darnuria
- (all) Some cargo clippy fix #1851 by darnuria
- (all) Fix #1835 RUSTSEC-2021-0145 Update clap to 4.0.29. #1853 by darnuria
- (docs) fix DNSSEC typo #1858 by HLFH
- (all) clippy updates for Rust 1.66 #1862 by bluejekyll
- (tests) ignore truncation for fuzz comparison #1872 by bluejekyll
- (tests) fix fuzz build failure #1875 by manunio
- (proto) docs: fix truncated rustdoc TODO on LowerName. #1897 by cpu
- (tests) Fix: invalid benchmark #1900 by XOR-op
- (proto) Fix panics in ClientSubnet conversions #1909 by djc
- (tests) Fix fuzz build #1911 by manunio
- (proto) Fix PTR.to_string() stack overflow #1912 by mokeyish
- (proto) Fix audit upgrade openssl #1914 by mokeyish
- (proto) Fix panic of unexpected close of UDP socket #1915 by mokeyish
- (proto) Lazily reap finished connections in TokioHandle on spawn_bg #1917 by jeff-hiner

### Changed

- (resolver) fix(resolver): correct ttl from lru cache #1984 by iberryful
- (ci) Use dtolnay/rust-toolchain #1993 by waywardmonkeys
- (all) update the minimum required openssl version #1979 by bluejekyll
- (bin) Print offending bind error in panic message #1971 by wprzytula
- (resolver) Provider API Redesign #1938 by XOR-op
- (all) create default rules for justfile (changed from cargo-make to justfiles) #1951 by bluejekyll
- (all) Bump log to v0.4.18 #1949 by daxpedda
- (proto) Make RData::read() API public #1945 by djc
- (all) Replace lazy_static with once_cell #1944 by daxpedda
- (resolver) Return Self from AsyncResolver::new() #1942 by daxpedda
- (all) Use default-features = false for quinn #1941 by daxpedda
- (all) remove the direct dependency to quinn-udp #1935 by zh-jq
- (resolver) Order name servers by SRTT #1784 by nhurley3
- (resolver) resolver: use errors' Display impl #1785 by hdhoang
- (proto) NameIter use a u8 for start/end. #1787 by darnuria
- (proto) name.rs use DomainNameTooLong in place of Message. #1788 by darnuria
- (proto) Explicit test for label max len and use ProtoErrorKind. #1789 by darnuria
- (cli) Port to clap4 #1791 by darnuria
- (proto) Improve CAA rdata display #1794 by wuerges
- (all) fix #1767 Update tracing-subscriber to 0.3.16 #1797 by darnuria
- (proto) Simplify interface between BinEncoder and MaximalBuf #1802 by djc
- (proto) proto: allow unrestricted length character length in SVCB param values #1806 by djc
- (all) bump MSRV to 1.60 #1813 by bluejekyll
- (all) Lazily reap finished tasks from inner_join_set #1818 by jeff-hiner
- (proto) proto: upgrade to Quinn 0.9 #1822 by djc
- (resolve) Preserve intermediates for TXT records #1828 by schultetwin1
- (all) Feature gate tokio features on mdns crate #1831 by jxs
- (test) python3-ply rather than python-ply #1846 by HLFH
- (docs) Replace http: links with https: #1848 by msrd0
- (docs) Make homepage link simpler for end users #1857 by HLFH
- (resolver) Don't retry authoritative NOERROR with an empty set, from trusted resolvers #1861 by jeff-hiner
- (server) authority: parse with default record class IN. #1874 by cpu
- (resolver) API-breaking change: Deprecate ConnectionProvider with new RuntimeProvider #1876 by XOR-op
- (proto) deps: upgrade Tokio 1.21.0 -> 1.24.1 #1877 by cpu
- (proto) Move client code used by server code down into proto #1879 by djc
- (proto) proto: clean up error logging #1881 by hawkw
- (resolver) Make dns_hostname optional to disable verify #1907 by mokeyish
- (all) Introduce central crate version management #1908 by mokeyish
- (resolver) remove use of time in recursor and client #1918 by zh-jq

### Removed

- (server) remove named binary #1859 by HLFH
- (docs) project: remove refs. to removed 'named' binary #1873 by cpu

### Added

- (server) Graceful Shutdown of Server #1869 by theduke
- (resolver) Add Google DoT and DoH to ResolverConfig #1989 by daxpedda
- (server) Adding graceful shutdown to server #1977 by nmittler
- (all) add an html coverage report for local review of coverage data #1959 by bluejekyll
- (resolver) Add the possibility to shuffle NameServers #1920 by Edu4rdSHL
- (resolver) add test for connecting DoH with pure IP Address #1936 by mokeyish
- (resolver) add NameServerConfigGroup::from_ips_quic #1929 by zh-jq
- (resolve) Add --reverse, --file and --interval to util/resolve #1807 by cunha
- (client) TSIG documenting client tsig code + update rfc link #1810 by darnuria
- (client) Create dedicated Errors types for Tsig error case #1811 by darnuria
- (all) Also declare MSRV in Cargo.toml #1820 by glts
- (proto) Add wireformat buffer to DnsResponse #1855 by mattias-p #1885 by cpu
- (client) client: rm zone parse optional class arg.
- (proto) Implement EDNS Client Subnet ECS reading and writing #1906 by mokeyish

## 0.22.1

### Fixed

- (server) drop response messages #1952 by @djc

## 0.22.0

### Removed

- (deps) don't pull in env_logger if we aren't actually a binary #1701 by @Noah-Kennedy

### Added

- (resolver) Add option to use a provided name server order #1766 by @nhurley3
- (proto) Add invalid utf8 output test for TXT::fmt. #1755 by darnuria
- (proto) Support 0-RTT in DNS over QUIC #1716 by msoxzw
- (recursor) *new* A Trust DNS based Recursor!!! #1710 by @bluejekyll
- (resolver) Allow customizing the static hosts configuration #1705 by @fantix
- (proto/server) Support loading pkcs#1 private key as well #1704 by @lisongmin
- (util) Trust `dns` client cli (like `dig`) #1680 by @bluejekyll

### Fixed

- (proto) Only retry UDP socket bind if it returned EADDRINUSE #1761 by @peterthejohnston
- (all) Add necessary conditional compilation cfgs #1752 by @trevor-crypto
- (server) Populate name_pointers correctly via MessageResponseBuilder request #1744 by @jeff-hiner
- (resolver) Do not fail parse_resolv_conf on invalid hostname #1740 by @schultetwin1
- (all) doc: Fix warnings reported by cargo doc #1737 by @wiktor-k
- (proto) Use `u16::*_be_bytes` represent length field (fixes DoQ) #1715 by @msoxzw
- (proto) Prevent invalid 0-length labels via from_raw_bytes #1700 by @jonasbb
- (proto/server) Drop UDP packets on send failure #1696 by @jeff-hiner
- (all) removed `.max(0)`, unnecessary with `u32`'s #1691 by @bluejekyll
- (server) sanitize all addresses received by the server before attempting any r… #1690 by @bluejekyll
- (server) Remove forced (unecessary) Mutex from handler #1679 by @jeff-hiner
- (proto) Fix `SvcParamKey::Unknown` parsing #1678 by @jeff-hiner

### Changed

- (all) Minimum Rust Version now 1.59 #1771 by bluejekyll
- (client) Parser panic to result #1758 by darnuria
- (client) Avoid 3 unwrap() call inc Parser::flush_record. #1757 by @darnuria
- (client) Cleanup lex #1756 by darnuria
- (resovler) Make maximum request depth configurable #1749 by @wiktor-k
- (server) Clean up ForwardAuthority api #1748 by @chotchki
- (resolver) Relax mut requirements for resolver.clear_cache() and add cache flushing example #1747 by @dns2utf8
- (resolver) Lookup access Records list directly #1746 by @izissise
- (proto) Pass DnsRequestOptions to DNSSEC validating routines #1742 by @wiktor-k
- (proto) Increase the maximum request depth to 26 #1736 by @wiktor-k
- (server) Mark ForwardLookup as public #1729 by @chotchki
- (all) upgrade windows openssl version to 1_1_1p #1728 by @bluejekyll
- (all) Converted to `tracing` from `log` #1706 by @erikh and @bluejekyll
- (server) Move logger setup code into binary #1703 by @djc
- (proto) ignore errors when disconnected #1695 by @edevil
- (server) RequestInfo derives Clone trait. #1693 by @humb1t
- (proto/server) make doq transport settings more consistent with RFC #1682 by @bluejekyll
- (all) Included githubactions in the dependabot config #1681 by @naveensrinivasan
- (proto) deprecated `edns` methods on request and replaced with `extensions` and better scemantics #1675 by @leshow

## 0.21.2

### Added

- (proto) add PartialEq+Hash derives, #1661 by @leshow

### Fixed

- (server) fix panic when tcp connect goes away before handling, #1668
- (server) crates/server, InMemoryStore: Use a RwLock instead of a Mutex to manage inner storage, #1665 by @erikh
- (all) fix audit regex failure, #1658
- (resolver) Stop searching for additional records when encountering a name already seen, #1657 by @Mossop
- (proto) fix time txt parsing in SOA records, #1656

### Removed

- (all) remove old crates (the ones moved into proto, tag v0.21.1 can get if needed for crates.io), #1655

### Changed

- (resolver) keep any address records included in the response to an NS query, #1672 by @db48x
- (resolver) force forwarder to preserve_intermediates, #1660 by @vlmutolo
- (resolver) make constructors for AsyncResolver with custom providers public, #1654 by @Noah-Kennedy

## 0.21.1

### Fixed

- (util) fixed feature build issue in `resolve` #1649

## 0.21.0

### Added

- (client) Parse DS records (@kmkaplan) #1635
- (fuzz) Added fuzzing configuration (@saethlin) #1626
- (resolver) Add `resolver.clear_cache()` sync and async (dns2utf8) #1611
- (proto) Add CDS/CDNSKEY records from RFC7344 (frelon) #1595
- (resolver) Configuration of outbound bind address for resolver (@surban) #1586
- (proto) Add `CSYNC` record from RFC7477 (@frelon) #1583
- (proto) trust_dns_proto::rr::Record now serializable (@mvforell) #1536
- (client) new `zone_transfer` method for `AXFR` and `IXFR` use cases, client only (@trinity-1686a) #1478
- (client) Flag for `use_edns` configuration on `AsyncClient` (@astro) #1492
- (client) support for `TSIG` authentication (@trinity-1686a) #1459

### Changed

- (util) openssl is no longer default enabled in trust-dns-utils, bins marked as required as necessary #1644
- (proto) deprecate outdated dnssec algorithms #1640
- (resolver) *BREAKING* removed `DnsRequestOptions` parameter from `AsyncResolver::lookup`, this is derived from `ResolverOpts`
- (server) pass RequestInfo into Authority on search #1620
- (proto) SSHFP: Ed448 is assigned algorithm 6 in RFC 8709 #1604
- (resolver) Do not retry the same name server on a negative response (@peterthejohnston) #1589
- (all) `with-backtrace` feature renamed to `backtrace` (@pinkisemils) #1577
- (resolver) TCP for truncated message responses, but not for other failures on responses (switch for old behavior `try_tcp_on_error`) ( @peterthejohnston) #1562
- (server) Multiple queries in a message will always result in a FormError now #1554
- (server) `ServerFuture` and other `Catalog` related API changes #1554
- (server) By default, the server will now only log a single log line based for a given request (debug will be needed for more details) #1554
- (server) `ResponseHandler` now must return a `ResponseInfo` to allow for more consistent logging #1554
- (resolver) Correct behavior around trust_nx_responses (@peterthejohnston) #1556
- (server) `ResponseHandler` trait is now `async_trait`, requires all impls to be annotated with `#[async_trait]` #1550
- (server) `Authority` impls required to be internally modifiable and `Send + Sync` #1550
- (server) Most `Authority` methods changes to `async fn` rather than returning custom `Future` impls #1550
- (server) `Authority` trait is now `async_trait`, requires all impls to be annotated with `#[async_trait]` #1550
- (proto) Header now stores ResponseCode instead of just u8 #1537
- (client) improved async client example documentation (@ErwanDL) #1539
- (resolver) on `REFUSED` (and other negative) response(s), fall back to other nameservers (@peterthejohnston) #1513 #1526
- (client) the feature `dnssec` is no longer enabled by default, use `dnssec-ring` or `dnssec-openssl` #1506
- (server) dnssec functions of `Authority` moved into `DnsSecAuthority` #1506
- (all) Most public enum types are now marked `#[non_exaustive]` #1426
- (resolver) DnsRequestOptions and ResolverOpts now `#[non_exaustive]` #1426
- (proto) all I/O Streams now use `BufDnsStreamHandle` rather than generic `DnsStreamHandle` #1433
- (proto) `DnsResponse` response now contains only a single Response #1433
- (proto) `Name::append_name` and `Name::append_domain` now properly fallible when name is too long #1448
- (resolver) special handling of the `onion.` TLD added to static resolution with negative responses (@trinity-1686a) #1479
- (proto) internal Futures converted to Streams to support multiple responses, e.g. `AXFR` (@trinity-1686a) #1478
- (proto) renamed `Signer` to `SigSigner` to differentiate from `TSigner` #1498

### Removed

- (all) removed `structopt` dependency #1644
- (all) removed `chrono` dependency #1569
- (client) Remove AsyncClientConnect and AsyncSecureClientConnect (future impls) in favor of async constructors (@ErwanDL) #1541
- (proto) removed `RecordType::DNSSEC` and moved all variants of `DNSSECRecordType` into `RecordType` #1506
- (proto) removed `BufStreamHandle` and `StreamHandle` #1433
- (response) disabled `mdns` to work on a new solution #1433

### Fixed

- (proto) fix CAA .to_string() crash and format (@hartshorne) #1631
- (proto) fix DoubleEndedIterator impl for Name #1639
- (client) Fix AsyncClient::clone always setting use_edns (@ecton) #1598
- (resolver) Use stream connections if datagram connections are not available (@pinkisemils) #1592
- (server) Release resources when a server future is dropped (@pinkisemils) #1587
- (proto) Panic when name exceeds maximal domain name length during display #1447

## 0.20.4

### Fixed

- (all) updated tokio dependencies to 1.16 #1623
- (all) removed audit chrono due to rustsec audit failure (backport) #1623

### Changed

- (all) Increased MSRV to 1.51

## 0.20.3

### Fixed

- (resolver) Fix Windows build without system-config feature (@stephank) #1481

## 0.20.2

### Fixed

- (proto) Panic on bad length in SVCB for record length #1465

## 0.20.1

### Added

- (proto) HINFO record type support (@vlad20012) #1361
- (proto) proto: add into_parts methods (@leshow) #1397
- (proto) new HTTPS and SVCB record types #1402
- (resolver) predefined Quad9 HTTPS resolver configuration (@zonyitoo) #1413

### Fixed

- (proto) Don't kill a DnsExchangeBackground if a receiver is gone (see #1276) (@djc) #1356
- (proto) Take the current header truncated bit into account (@ilaidlaw) #1384

### Changed

- (async-std-resolver) Re-export AsyncStdConnection(Provider) (@romanb) #1354
- (proto) Mutate edns & remove edns options (@leshow) #1363
- (proto) Change Edns set_* to -> &mut Self (@leshow) #1369
- (resolver) Enable RuntimeProvider in DoT implementations (@chengyuhui) #1373
- (proto) Optimize name parsing (@saethlin) #1388
- (proto) Remove a lot of bounds checks in BinDecoder by tracking position with a second slice (@saethlin) #1399
- (proto) Make errors/error reporting more lightweight (@saethlin) #1409

## 0.20.0

### Changed

- (all) upgraded to Tokio 1.0 (@messense) #1330 (0.3 updates in #1262)
- (proto) Add serde support for the RecordType in the proto crate (@LEXUGE) #1319
- (https) dns_hostname args all are `Arc<str>` rather than `Arc<String>`, use `Arc::from`
- (proto) Set TCP_NODELAY when building a TCP connection (@djc) #1249
- (all) *BREAKING* The `UdpSocket` trait has grown an associated `Time` type.
- (all) *BREAKING* The `Connect` trait has lost its
`Transport` associated type, instead relying on the `Self` type.
- (all) *BREAKING* Introduced a new `DnsTcpStream` trait, which is now a
bound for implementing the `Connect` trait.
- (resolver) *BREAKING* Move `CachingClient` from `lookup_state` to `caching_client` module
- (resolver) *BREAKING* Move `ResolverOpts::distrust_nx_responses` to `NameServerConfig::trust_nx_responses` (@djc) #1212
- (proto) `data-encoding` is now a required dependency #1208
- (all) minimum rustc version now `1.45`
- (resolver) For all NxDomain and NoError/NoData responses, `ResolveErrorKind::NoRecordsFound` will be returned #1197
- (server) Support for lowercase DNSClass and RecordType fields in zonefiles (@zhanif3) #1186
- (resolver) Make EDNS optional for resolvers (@CtrlZvi) #1173
- (all) Fully support *ring* for all DNSSEC operations. #1145
- (all) No more `master` (branch, moved to `main`) slave, in honor of Juneteenth #1141
- (all) Minimize `futures` dependencies (@JohnTitor) #1109
- (proto) increases the UDP buffer size from 2048 to 4096 to allow larger payloads (@DevQps) #1096
- (resolver) use IntoName trait on synchronous resolver interface (@krisztian-kovacs) #1095
- (resolver) *BREAKING* removed async for `AsyncResolver::new` (@balboah) #1077 #1056
- (server) *BREAKING* removed `Runtime` from `ServerFuture::register_socket` (@LucioFranco) #1088 #1087
- (proto) *Breaking* Adjust the return value from `ResponseCode::high` from u16 to u8 #1202

### Fixed

- (client) Support reading the root hints file (@mattias-p) #1261
- (resolver) Fix Glue records resolving (@wavenator) #1188
- (resolver) Only fall back on TCP if cons are available (@lukaspustina) #1181
- (proto) fix empty option at end of edns (@jonasbb) #1143, #744
- (resolver) Return `REFUSED` instead of `NXDOMAIN` when server is not an authority (@AnIrishDuck) #1137
- (resolver) forwarder: return NXDomain on `e.is_nx_domain()` (@balboah) #1123
- (resolver) Regards NXDomain and NoError empty responses as errors (continues searching for records), #1086 #933

### Added

- (util) *new* Add resolve.rs as CLI for trust-dns-resolver #1208
- (proto) Added proper zone display to all RData as an impl of Display #1208
- (proto) `xfer::dns_response::NegativeType` and `DnsResponse::negative_type` to classify negative response type #1197
- (proto) `DnsResponse::contains_answer` to determine if a response message has data related to the query #1197
- (proto) `RecordType::is_soa` and `RecordType::is_ns` to easily check for these types #1197
- (proto) `Message::all_sections` to allow iteration over all `Records` in all sections in a Message #1197
- (proto) `Message::take_queries` to remove from a Message without requiring clone #1197
- (proto) `DnsHandle::Error` associated type to support generic errors across trust-dns libraries #1197
- (resolver) Add support for tlsa RRs in trust_dns_resolver (@smutt) #1189
- (resolver) Support pointer ending label compression (@jacoblin1994) #1182
- (proto) Keep OS error information on `io::Error` (@brunowonka) #1163
- (proto) Support mDNS cache-flush bit (@fluxxu) #1144
- (proto) Allow creating TXT Rdata with binary data (@bltavares) #1125
- (proto) Add mutable access to Message fields (@leshow) #1118
- (proto) Add Name.parse_ptr_name, to IP address (@Mygod) #1107
- (resolver) Allow HTTPS to be generic over Runtime (@balboah) #1077 #1074

## 0.19.7

### Changed

- make `backtrace` an optional dependency, backported from 0.20 (@jmagnuson) #1387

## 0.19.6

### Fixed

- bump resolv-conf from 0.6.0 to 0.7.0, fixes system resolv.conf parse issue (@wg) #1285

## 0.19.5

### Fixed

- (server) updated rusqlite to 0.23.1 #1082

## 0.19.4

### Fixed

- (resolver) properly reuse connections, for TCP, TLS, and HTTPS #1058

### Added

- (resolver) option to include intermediate (CNAME) records in results (@balboah) #1028
- (async-std-resolver) added implementation for async-std! woohoo! (@belak) #1067 #1051 #926
- (server) add support for $INCLUDE in zone files (@kachayev) #1027
- (proto) exposed LabelIter from Name (@avitex) #1064

### Changed

- (all) updated rustls to 0.17
- (all) updated tokio-rustls to 0.13
- (all) min rustc compiler version now 1.40

## 0.19.3

### Changes

- (all) update all dependencies
- (all) minimize `futures` dependency to `std` features (@antonylsg) #1003
- (all) cleanup clippy warnings for Rust v.1.41 #1008
- (proto) make all fields public on `ResolverOpts` for ease of use (@ackintosh) #1009

## 0.19.2

### Changes

- (resolver) make system config loading optional to support fuchsia (@chunyingw) #996

## 0.19.1

### Changes

- (resolver) dependency on `trust-dns-proto` no is no-default-features (@chunyingw) #993

## 0.19.0

### Changes

- (resolver) AsyncResolver abstract over `RuntimeProvider` (@chunyingw) #975
- (resolver) TokioAsyncResolver implementation now has default methods that have a default Handle::current set `TokioAsyncResolver::tokio`

### Added

- (resolver) testing module for generic tests across generic async runtime impls (@chunyingw) #979
- (proto) support for building into WASM (@moshevds) #987 #990 #991

### Removed

- (all) failure is no longer used for error types, std::Error impls only

## 0.18.1

### Fixes

- (server) Fix issue when MX or other records collect additionals based of `.`, root, targets #980

## 0.18.0

### Changes

- (all) CHANGELOG.md is now merged from the Resolver crate and the top-level. All notes from the Resolver CHANGELOG were merged into this changelog, with the format `## {version} (Resolver)` and the existing notes from the top-level are formatted as `## {version} (Client/Server`. This should make notes on releases easier. Going forward the scope of changes across crates will be captured as `- ({crate}) {note}` where all is used for across the board updates.
- (all) After the 0.18 release, all crates will be versioned uniformally, and released at the same time, this will resolve some issues around consistency with releases. The final Resolver release before this was `0.12`.
- *breaking* Generally, any interface that took a 0.1 Future, now returns or consumes a std::future::Future
- *breaking* (client) rebranded from `trust-dns` to `trust-dns-client`
- *breaking* (named) moved from `trust-dns-server` to `trust-dns`, in bin/**
- *breaking* (all) all internals updated to std::future and async/await (requires `Rust 1.39` minimum)
- *breaking* (client) AsyncClient now returns a connect future which resolves to the client and it's background.
- *breaking* (resolver) AsyncResolver::new changed to AsyncResolver::connect, requires awaiting the returned future
- (client) ClientFuture renamed to AsyncClient
- (resolver) AsyncResolver now requires a ConnectionProvider type parameter, see TokioAsyncResolver as a predefined type without it
- (resolver) Now returns a connect future to connect the start all background tasks
- (proto, resolver) renamed the `tokio-compat` feature to `tokio-runtime`
- (all) added cargo-make Makefile.toml to support all automation in Github workflow
- (proto) renamed `SecureDnsHandle` to `DnssecDnsHandle`
- (client) renamed `SecureSyncClient` to `SyncDnssecClient`
- Abstractions around Tokio for generic Executors #960 (@chunyingw)
- Enable early data on tokio-rustls #911 (@daareiza)

### Fixes

- (proto) Removed deadlock from UDPSocket stream impl
- (named) made tests a little more resilient to port stealing
- (proto) Unknown ResponseCodes will no longer cause a panic

### Removed

- (client) client::BasicClientHandle, ClientFuture no longer requires Background or the separate Handle, this can generally be replaced with just ClientFuture itself in most use cases.
- *breaking* (resolver) Background type removed
- (resolver) removed deprecated AsyncResolver::lookup_service, see AsyncResolver::lookup_srv
- (client) removed all deprecated reexports from trust_dns_proto
- (proto) removed unused xfer::BasicDnsHandle, xfer::MessageStreamHandle
- (resolver) removed all unused custom LookupFuture types SrvLookupFuture, ReverseLookupFuture, Ipv4LookupFuture, Ipv6LookupFuture, MxLookupFuture, TxtLookupFuture, SoaLookupFuture, NsLookupFuture
- (resolver) removed Background, BackgroundLookup, and BackgroundLookupIp
- (resolver|client) DoH no longer sends User-Agent header #962 (@quininer)

### Added

- (proto) proto now has a `testing` feature to allow dependencies that might want access to some of the testing harnesses. #936 (@chunyingw)

## 0.17.0 (Client/Server)

### Added

- (all) Licenses copied into all crates #832 (@divinerapier)
- `UdpSocket` for compatibility with Tokio, when not using non-Tokio executors #824 (@chunyingw)
- `Connect` for Tcp connection compatibility with Tokio, when not using non-Tokio executors #794 (@chunyingw)

### Changes

- *breaking* (client) TcpClientConnect requires generic stream param #794 (@chunyingw)
- *breaking* (client) UdpClientStream requires generic socket param #824 (@chunyingw)
- *breaking* (proto) UdpStream and UdpClientStream requires generic socket #824 (@chunyingw)
- *breaking* (proto) TcpStream and TcpClientStream require generic stream param #794 (@chunyingw)
- Algorithm::from_u8 is now infallible #800 (@zackangelo)
- Algorithm::hash_len now returns Option #800 (@zackangelo)

### Removed

- `byteorder` dep dropped in favor of `std` implementations #844 (@lukaslueg)

## 0.16.1 (Client/Server)

- disables the `socket2/reuseport` feature except when `mdns` is enabled

## 0.16.0 (Client/Server)

### Fixed

- (proto) UDP Sockets not being properly closed in timeout scenarios #635
- (server) CNAME resolutions #720
- (server) NSEC evaluation for NODATA and NXDOMAIN responses #697
- (server) Call add_update_auth_key in named.rs #683 (@Darkspirit)

### Added

- (proto) support for the OPENPGPKEY and SSHFP record types #646 #647
- (server/client) support ECDSA signing with ring #688 (@Darkspirit)
- (server) forwarding support in server with trust-dns-resolver (default feature) #674
- (server) Authority trait for generic Authorities (File, Sqlite, Forwarder) #674
- (server) ANAME resolutions #720
- (server) Additional section processing for ANAME, CNAME, MX, NS, and SRV #720
- (server) Added endpoint name config to DoH and DoT TLS endpoint #714
- (proto) NAPTR record data (no additional record processing support) #731
- (server) Added support for wildcard lookups, i.e. `*.example.com` in zone files

### Changed

- *breaking* (proto) UdpClientStream and UdpClientConnection refactored to associate UDP sockets to single requests #635
- *breaking* (server) configuration for sqlite dynamic update different, see dnssec_with_update.toml for example #622
- *breaking* (util)/dnskey_to_pem has been renamed to bind_dnskey_to_pem for clarity #622
- *breaking* (proto) Record::from_rdata no longer requires RecordType parameter #674
- *breaking* (server) AuthLookup inner types simplified #674
- *breaking* (server) RequestHandler now requires associated type for Future results of lookups #674
- *breaking* (server) ResponseHandler now requires Clone and 'static #674
- *breaking* (server) Catalog::lookup takes ownership of MessageRequest and returns a LookupFuture #674
- *breaking* (server) MessageRequest and Queries no longer carrying lifetime parameters #674

## 0.15.0 (Client/Server)

### Fixed

- Fix two separate integer overflows from subtractions #585 (@oherrala)
- strictly enforce name and label lengths during label parsing #584
- enforce that only prior labels are used in label expansion, decompression #578 (@oherrala)
- CAA now properly performs case-insensitive compares #587 (@oherrala)
- overhauled rdata parsers with Restrict type to reduce potential of overflowing operations #586

### Added

- feature `dns-over-rustls` to `trust-dns-server` (server) and `trust-dns` (client)
- feature `dns-over-https-rustls` *experimental* #557
- new configuration options for tls, see `server/tests/named_test_configs/dns_over_tls_rustls_and_openssl.toml`
- new utility for querying root key-signing-keys, `util/get-root-ksks`
- updated root trust-anchor to include new `20326` RSA root ksk

### Changed

- Make trust_dns_server::server::ResponseHandler Send #593 (sticnarf)
- Wrap types in Restrict and force validation before usage from streams #586
- *breaking* Overhauled all `ClientFuture` implementations to align with new `DnsExchange` and `DnsMultiplexer` components in proto.
- *breaking* `ClientFuture` after construction, now returns a "background" `ClientFuture` and a "foreground" `BasicClientHandle`
- *breaking* `Client` has more type parameters, these match with the same types returned by the `*ClientConnection` constructors
- *breaking* all default features, removed: "dns-over-openssl", "dnssec-openssl". Use --features=dns-over-openssl,dnssec-openssl to enable
- *breaking* `named` configuration now has AXFR disabled by default.
- *breaking* Migrated from error_chain to Failure #474 (@silwol)
- feature `tls` renamed to `dns-over-openssl`
- upgraded `native-tls` and `tokio-tls` to 0.2
- upgraded `rusqlite` to 0.15

## 0.14.0 (Client/Server)

### Changed

- Updated `trust-dns-proto` to `0.3`, which brings in better `Name` and `Label` impls
- rusqlite updated to 0.13 #331 (@oherrala)
- Many serialization improvements #317
- Use tokio-timer (part of tokio upgrade) @justinlatimer #411
- Backtrace now optional @briansmith #416
- Use tokio-tcp (part of tokio upgrade) @Keruspe #426
- Use tokio-udp (part of tokio upgrade) @Keruspe #426
- Upgrade to tokio-executor (tokio upgrade) @Keruspe and @justinlatimer #438
- Send (Sync where applicable) enforced on all DnsHandle::send and other interfaces #460
- ClientHandle api return Send @ariwaranosai #465

### Added

- `Name` and `Label` now support idna, punycode, see `Name::from_str`
- `trust_dns::rr::ZoneUsage` for detecting restrictions on `Name`s and their associated zones

### Fixed

- octal escapes fixed in `Name` parsing #330
- `NULL` record type incorrectly valued at `0` to proper `10` #329 (@jannic)
- BinEncoder panic on record sets of extreme sizes #352
- Panic when oneshot channel receiver goes away #356
- Hung server on UDP due to bad data #407

### Removed

- usage of tokio-core::Core @Keruspe #446

## 0.13.0 (Client/Server)

### Added

- Trust-DNS Proto crate to separate server management from base operations #222
- Trust-DNS Util crate for dnssec management tools (@briansmith)
- Integration tests for Server to validate all supported DNSSEC key types
- *breaking* Common features `dnssec-ring`, `dnssec-openssl`, and `dnssec` across all crates (replaces `openssl` and `ring` features)
- Clarified `tls` feature with `tls-openssl`, and `tls` in server (in preparation for `tls-rustls`)
- Support for rfc6844, CAA record type #234
- Support for rfc6698, TLSA record type #285
- Clippy validation in CI #288 (@little-dude)

### Changed

- DNSKEY is now self-signed
- Internal API changes to `client` calling into `proto` for actual implementations
- Large refactoring of internal APIs to more cleanly support \*ring\* and OpenSSL features (@briansmith)
- `ClientHandle::send` moved to `trust_dns_proto::DnsHandle::send` (internal API)
- Many interfaces moved from `client::ClientStreamHandle` to `trust_dns_proto::DnsStreamHandle`
- `Message::sign` has been renamed and change to the more general method `Message::finalize`
- Some `io::Error`s have been converted to `trust_dns_proto::ProtoError`
- `SyncClient` and `SecureSyncClient` are now `Send + Sync` #245
- Unknown RecordTypes and RDatas will no longer error #294

### Fixed

- Server: signing issues when loading from persistence
- Server: When SupportedAlgorithms (rfc6975) not supplied default to returning all signatures #215
- Proto: u16::from(DNSClass) now enforces OPT is greater than/or 512 per spec #303
- Improve usage of Rand for message ids and port assignment #291 & #292
- NxDomain and empty NoData responses to be compliant #286 (lots of help from @Darkspirit)

### Removed

- Removed the `NativeTls` and `OpenSSL` `ClientConnection` variants, use the Rustls impls or the tokio based `TlsClientStream` instead. This was required for `SyncClient` being `Send + Sync`
- Server: no longer auto-generate keys on startup #218
- All deprecated APIs removed from -proto #262
- Server: removed deprecated RSA config loading options, see reference test cargo.tomls #276 (@briansmith)

## 0.12.0 (Resolver)

- Internal updates related to generification of executors

## 0.12.0 (Client/Server)

### Fixed

- Server was not properly signing zone after fresh start

### Added

- RSA and ECDSA validation with *ring* for DNSSEC, removes dependency on openssl (@briansmith)
- `lookup` to `ClientHandle`, simpler form with `Query`
- `query` to `Query` for ease of Query creation

### Changed

- Large celanup of signing and verification paths in DNSSEC (@briansmith)
- *breaking* changed `TrustAnchor::insert_trust_anchor` to more safely consume `PublicKey` rather than `Vec<u8>`

## 0.11.2 (Client/Server)

(README.md documentation changes for crates.io)

## 0.11.1 (Resolver)

- disables the `socket2/reuseport` feature except when `mdns` is enabled

## 0.11.1 (Client/Server)

### Changed

- Updates to `Name::is_fqdn` for more accuracy (@rushmorem)

### Added

- per project Readme.md for crates.io

## 0.11 (Resolver)

### Fixed

- Ignore UDP responses not from target src address #629 #630 #631 (@aep)
- Improved NSEC validation of responses #697

### Added

- New option to execute queries concurrently, default is 2 #615
- Lookup::record_iter for listing all records returned in request #674
- NAPTR record data (no additional record processing support) #731

### Changed

- Added option to distrust Nameservers on SERVFAIL responses, continue resolution #613
- *breaking* Record::from_rdata no longer requires RecordType parameter #674
- LRU cache is now based on Query rather than just name #674

## 0.11.0 (Client/Server)

### Added

- `Name::FromStr` for simpler parsing, specify trailing `.` for FQDN
- `Name::append_label` for clearer usage while appending labels to a Name
- `Name::append_name` for clearer usage while appending one name to another
- `Name::append_domain` alias for append_name and marking as FQDN

### Changed

- *breaking* all `&mut self` methods on `Name` deprecated as unsafe, Name labels are now immutable.
- *breaking* All `ClientHandle` traits now take `&Handle` instead of `Handle` (@rushmorem)
- *warning* `Name` now tracks if it is a fully qualified domain name, slightly changes name parsing rules, allowing `www.example.com` without the trailing `.`, which means that FQDN names are not enforced.

### Removed

- *deprecated* `Name::with_labels` see `Name::from_labels`
- *deprecated* `Name::append` wasn't clean, see `Name::append_name`
- *deprecated* `Name::add_label` exposed internal data structure, see `Name::append_label`
- *deprecated* `Name::label` unclear usage/name, see `Name::append_label`
- *deprecated* `Name::prepend_label` exposed internal data structure, unclear usage *no replacement*
- *deprecated* `Record::add_name` unclear usage *no replacement*

## 0.10.5 (Client/Server)

### Added

- Library documentation, examples for client query and update

### Changed

- ServerFuture now Accepts generic RequestHandler (@Antti)

## 0.10.4 (Client/Server)

### Added

- Allow more options with Key and KeyUsage
- Initial Resolver implementation

### Fixed

- NSEC coverage bitmap overflow in nightly
- Name::zone_of panic (@SAPikachu)

## 0.10.3 (Client/Server)

### Fixed

- Proper TCP connection timeout
- Fixed signature format of ECDSA (@SAPikachu) #141

## 0.10.2 (Resolver)

### Fixed

- all optional dependencies updated #640

## 0.10.2 (Client/Server)

### Fixed

- Fixed format of ED25519 keys (@briansmith) #129

### Changed

- Revamped signer and keypair to better deal with public key (possible breaking change)
- Upgraded *ring* to 0.9.x series, requires pkcs8 for key storage
- Dropped support for dangerous private key byte access (possible breaking change)
- Upgraded tokio-rustls and rustls dependencies to support *ring* updates

### Added

- PublicKey and Verifier for verifying with zero copy from KEY and DNSKEY (possible breaking change)
- Pkcs8 as a supported KeyFormat for storage (possible breaking change)

## 0.10.1 (Resolver)

### Fixed

- UDP Sockets not being properly closed in timeout scenarios #635

## 0.10.1 (Client/Server)

### Added

- Added `From<IpAddr>` for Name (reverse DNS) #105
- AppVeyor support #103
- rustls client tls support (separate crate)
- full support for KEY RR in client
- compatibility tests with BIND for SIG0 updates
- Added full implementation of KEY type

### Changed

- Updated TLS documentation, added more elsewhere, docs required; fixes #102
- Upgraded tokio-core and moved to tokio-io
- *Important* Some `Server` types have been migrated to [RFC#344](https://github.com/aturon/rfcs/blob/conventions-galore/active/0000-conventions-galore.md#gettersetter-apis) style. `get_field()` -> `field()`; `field()` -> `set_field()`
- Moved native-tls client impl to separate crate
- Defaulted to OpenSSL for tls implementation

### Fixed

- key_tag calculation for DNSKEY and KEY now correct #118 (@jannic)
- SIG0 signing fixed to match RFC and BIND #120 (@jannic)

## 0.10 (Resolver)

### Fixed

- Fix two separate integer overflows from subtractions #585 (@oherrala)
- strictly enforce name and label lengths during label parsing #584
- enforce that only prior labels are used in label expansion, decompression #578 (@oherrala)
- CAA now properly performs case-insensitive compares #587 (@oherrala)
- overhauled rdata parsers with Restrict type to reduce potential of overflowing operations #586
- Propagate TTLs for NXDOMAIN responses #485 (@hawkw)
- LookupIpFuture implementation to be proper in regards to loop control #480 (@hawkw)
- max query depth tracking in Resolver #469

### Changed

- Wrap types in Restrict and force validation before usage from streams #586
- Delays all connections until actual use #566
- Relax parsing rules for CAA issuer keys and values #517
- `ResolverFuture` renamed to `AsyncResolver` #487 (@hawkw)
- *breaking* `AsyncResolver::new` returns a tuple of an `AsyncResolver` and a future that drives DNS lookups in the background #487 (@hawkw)
- *breaking* All `AsyncResolver` lookup methods return `BackgroundLookup<T>` rather than `T` #487 (@hawkw)
- *breaking* Migrated from error_chain to Failure #474 (@silwol)
- improve truncation to always return records #497

### Added

- updated root trust-anchor to include new `20326` RSA root ksk
- DNS over HTTPS support #520

## 0.10.0 (Client/Server)

### Changed

- *Important* Possible breaking API change, the original Client has been renamed.

In an attempt to reduce the overhead of managing the project. The original
Client has now been revamped to essentially be a synchronous Client over the
ClientFuture implementation. The ClientFuture has proven to be a more stable
and reliable implementation. It was attempted to make the move seamless,
but two new types were introduced, `SyncClient` and `SecureSyncClient`, which
are both synchronous implementations of the old Client function interfaces.
Please read those docs on those new types and the Client trait.

- When EDNS option is present, return only the digest understood matching RRSETs
- All code reformatted with rustfmt
- *Important* breaking change, all `Record` and associated types have been migrated to [RFC#344](https://github.com/aturon/rfcs/blob/conventions-galore/active/0000-conventions-galore.md#gettersetter-apis) style. `get_field()` -> `field()`; `field()` -> `set_field()`

### Removed

- *Important* The original Server implementation was removed entirely.

Please use the ServerFuture implementation from now on. Sorry for the inconvenience,
but this is necessary to make sure that the software remains at a high quality
and there is no easy way to migrate the original Server to use ServerFuture.

### Added

- Initial support for ECDSAP256SHA256, ECDSAP384SHA384 and ED25519 (client and server)
- additional config options for keys to named, see `tests/named_test_configs/example.toml`
- Added DNS over TLS support, RFC 7858, #38
- Added native-tls with support for macOS and Linux (DNS over TLS)
- matrixed tests for all features to Travis

## 0.9.3 (Client/Server)

### Changed

- updated to rust-openssl 0.9.x series
- restructured dnssec code to better support alternate key formats

## 0.9.2 (Client/Server)

### Changed

- mio_client is now an optional feature in favor of the futures-rs ClientFuture

## 0.9.1 (Resolver)

### Fixes

- Fixes the MAX TTL being outside the bounds of 32bit systems, reduces max to 1 day #528

## 0.9.1 (Client/Server)

### Changed

- OpenSSL is now an optional feature for the client

## 0.9 (Resolver)

### Added

- DNS-over-TLS configurations (requires one of `dns-over-native-tls` or `dns-over-rustls` features) #396
- Experimental DNS-SD, service discovery (RFC 6763, `mdns` feature required) #363
- Experimental mDNS, multicast DNS, known issues persist (RFC 6762, `mdns` feature required) #337
- Exposed TTLs on `Lookup` objects @hawkw #444
- Added global resolver example #460

### Changed

- Use tokio-timer (part of tokio upgrade) @justinlatimer #411
- Backtrace now optional @briansmith #416
- Upgrade to tokio-tcp (tokio upgrade) @Keruspe #426
- Upgrade to tokio-udp (tokio upgrade) @Keruspe #427
- Upgrade to tokio-executor (tokio upgrade) @Keruspe and @justinlatimer #438
- Always reattempt nameserver reconnections regardless of time #457
- Defaulted type parameter for LookupFuture, removed InnerLookupFuture #459

### Fixed

- BinEncoder panic on record sets of extreme sizes #352
- Panic when oneshot channel receiver goes away #356
- Incorrect IPv6 configuration for Google nameservers #358
- Properly yield on failure to acquire lock #372
- Correct order of search list with ndots variable #410
- Send (Sync where applicable) enforced on all DnsHandle::send and other interfaces #460
- Properly track max query depth as a `task_local` not `thread_local` #460, #469
- IPv4 like name resolution in lookup_ip with search order #467

### Removed

- usage of tokio-core::Core @Keruspe #446

## 0.9.0 (Client/Server)

### Added

- new ServerFuture tokio and futures based server, #61
- UdpStream & TcpSteam to support stream of messages with src address
- TimeoutStream to wrap TcpStreams to help guard against malicious clients
- Added Notify support to ClientFuture
- Added IntoRecordSet and conversion impls for RecordSet and Record

### Changed

- Split Server and Client into separate crates, #43
- Moved many integration tests to `tests` from `src`, #52
- Migrated all handles to new futures::sync::mpsc impls
- Modified all requisite client methods for IntoRecordSet.
- All client methods now support multiple records per query, update, notify and delete

### Fixed

- Flush TcpStream after fully sending Message
- Recognize no bytes read as closed TcpStream

## 0.8.1 (Resolver)

### Changed

- Make read_system_conf() function public #338 (@oherrala)
- Hosts map was not properly reference counted #342

### Fixed

- Panic in edge case of label compression #341 (@SAPikachu)
- Fix `localhost` lookup and no longer panic on no names #343

## 0.8.1 (Client/Server)

### Fixed

- Fix build on rustc 1.11, #66

## 0.8.0 (Resolver)

### Changed

- Updated `trust-dns-proto` to `0.3`, which brings in better `Name` and `Label` impls
- Dropped LALRPOP `resolv.conf` parser in favor of the `resolv-conf` #335 (@cssivision & @little-dude)
- Improved message serialization #311 (@little-dude)
- Many serialization improvements #317
- Dependencies updated #334 (@oherrala)

### Added

- `Name` and `Label` now support idna, punycode, see `Name::from_str`
- Clippy added to build #304! (@neosilky)
- `from_system_conf` on now supported on Windows 32bit targets (previously just 64bit) #313 (@liranringel)

### Fixed

- octal escapes fixed in `Name` parsing #330
- `NULL` record type incorrectly valued at `0` to proper `10` #329 (@jannic)

## 0.8.0 (Client/Server)

### Added

- SecureClientHandle, for future based DNSSEC validation.
- ClientFuture, futures based client implementation, #32

### Fixed

- Randomized ports for client connections and message ids, #23
- OpCode::From for u8 removed, added OpCode::from_u8(), #36
- Fix for named startup related to ipv6, #56

### Changed

- Upgraded OpenSSL to 0.8.* #50
- Cleaned up the Server implementation to isolate connection handlers
- Deprecated old Client will possibly remove in the future

## 0.7.3 (Client/Server 2016-08-12)

### Fixed

- Issue #27: label case sensitivity revisited for RRSIG signing, RFC 6840
- TCP reregister on would-block errors

## 0.7.2 (Client/Server 2016-08-10)

### Fixed

- Issue #28: RRSIG validation of wildcards, label length > wildcard length

## 0.7.1 (Client/Server 2016-08-09)

### Fixed

- Issue #27: remove implicit case conversion of labels (fixes NSEC validation)

## 0.7.0 (Resolver)

### Changed

- Resolver no longer depends on Client
- *breaking* Resolver no longer returns io:Errors, use `From<ResolveError>` for `io::Error`
- Resolver is now `Send`
- DNSSEC now disabled by default in Resolver, see `dnssec-ring` or `dnssec-openssl` features #268
- CNAME chaining was cleaned up #271 (@briansmith)
- On hostname parsing to IpAddr, return without lookup #302 (@cssivision)
- Change default `LookupIpStrategy` from `Ipv4AndIpv6` to `Ipv4thenIpv6` #301 (@cssivision)

### Added

- ResolveError and associated types

### Fixed

- Cleaned up CNAME chained lookups, better TTL enforcement, etc #298

## 0.7.0 (Client/Server 2016-06-20)

### Added

- Added recovery from journal to named startup
- SQLite journal for dynamic update persistence
- Private Key generation during startup, for dnssec zones
- Read private key from filesystem during start and registers to zone

### Changed

- Removed many of the unwraps in named binary
- Reworked all errors to use error-chain
- Adjusted interface for Signer to use duration
- All `#[cfg(ftest)]` tests now `#[ignore]`

### Fixed

- TXT record case sensitivity

## 0.6.0 (Resolver)

### Changed

- Split UDP and TCP into different NS pools, prefer UDP lookups first
- On truncated UDP responses, promote to TCP for resolution

### Added

- 64bit Windows support for reading DNS configuration! (@liranringel)
- CNAME chain resolution (where CNAME results are not returned in the same query)
- Resolution prefers `/etc/hosts` before querying (@cssivision)

## 0.6.0 (Client/Server 2016-06-01)

### Added

- Documentation on all modules, and many standard RFC types
- Authority zone signing now complete, still need to load/save private keys
- DNSKEYs auto inserted for added private keys
- New mocked network client tests, to verify zone signing
- NSEC record creation for zone, with tests
- SIG0 validation for Authentication on for dynamic updates
- Client CQADDD operations, delete_by_rdata, delete_rrset, delete_all
- Client compare_and_swap operation... atomics are here!

### Fixed

- Added loop on TCP accept requests
- Added loop on UDP reads
- Upgraded to mio 0.5.1 for some bug fixes
- Not returning RRSIGs with SOA records on authoritative answers

### Changed

- Internal representation of record sets now a full data structure
- Better rrset keys for fewer clones
- Removed many excessive clones (should make requests even faster)
- Cleaned up authority upsert and lookup interfaces
- All authorities default to IN DNSCLASS now (none others currently supported)
- Cleaned up the Signer interface to support zone signing
- Simplified RData variant implementations
- Improved ENDS and SIG0 parsing on Message deserialization

## 0.5.3 (Client/Server 2016-04-07)

### Fixed

- [Linux TCP server mio issues](https://github.com/bluejekyll/trust-dns/issues/9)

### Changed

- combined the TCP client and server handlers
- reusing buffer in TCP handler between send and receive (performance)

## 0.5.2 (Client/Server 2016-04-04)

### Changed

- updated mio to 0.5.0
- updated chrono to 0.2.21
- updated docopt to 0.6.78
- updated log to 0.3.5
- updated openssl to 0.7.8
- updated openssl-sys to 0.7.8
- updated rustc-serialize to 0.3.18
- updated toml to 0.1.28

## 0.5.1 (Client/Server 2016-03-30)

### Added

- NSEC3 resolver validation
- data-ecoding as a dependency (base32hex)
- trust-dns banner on boot of server

### Changed

- Changed the bin.rs to named.rs, more accurate, allow for other binaries

## 0.5.0 (Resolver)

### Changed

- *breaking* `LookupIp` now returns an iterator over owned data (IpAddr is Copy + Clone ref not necessary)
- *breaking* `Resolver::lookup` will now return an Err on NxDomain and NoData responses
- rewrote much of the caching and lookup functionality for generic RecordType lookups
- removed &mut from resolver fn interfaces, make it easier to use

### Added

- Generic record type lookup
- reverse_lookup for IP to Name lookups
- ipv4_lookup for looking up *only* ipv4 (lookup_ip has options for dual-stack)
- ipv6_lookup for looking up *only* ipv6 (lookup_ip has options for dual-stack)
- mx_lookup for querying mail exchanges
- srv_lookup for service records and also a specialized form for ease of use lookup_service
- txt_lookup for text record lookups

## 0.5.0 (Client/Server 2016-03-22)

### Added

- Updated rust-openssl to 0.7.8 which include new RSA creation bindings
- NSEC resolver validation
- NSEC3 parsing support
- DNSSEC validation of RRSIG and DNSKEY records back to root cert
- Integration with OpenSSL (depends on fork until rust-openssl 0.7.6+ is cut)
- Binary serialization and deserialization of all DNSSEC RFC4034 record types
- EDNS support
- Coveralls support added
- Partial implementation of SIG0 support for dynamic update
- SRV record support

### Changed

- Dual licensed with MIT (and Apache 2.0)
- Abstracted Client over TCP and UDP for common implementation of queries

### Fixed

- Binary Serialization and Deserialization of NSEC3
- AXFR SOA ordering
- Travis build failing

### Deprecated

- See updated trust_dns::client::Client API

## 0.4.0 (Resolver)

### Removed

- *breaking* impl `Iterator` removed from `LookupIp` result type, see `LookupIp::iter` for replacement

### Added

- Support for DNSSEC validation
- LRU Cache

## 0.4.0 (Client/Server 2015-10-17)

### Added

- Added AXFR support
- Dynamic update support

### Fixed

- Name pointer support

## 0.3.1 (Client/Server 2015-10-04)

### Fixed

- Removed buffer clone during label pointer decoding (speed/memory)
- Removed a lot of unnecessary clones, heavier use of Rc
- Binary server bugs (fully functional)

## 0.3.0 (Resolver)

### Added

- `options attempts:N` aka `ResolverOpts::attempts` support, aka retries
- Google IPv6 nameservers as defaults for `ResolverConfig::default`
- support for domain name search in `ResolverConfig` and `LookupIpFuture`
- support for search names in `ResolverConfig` and `LookupIpFuture`
- `LookupIpFuture` type alias to `LookupIpFuture<NameServerPool>` *compatibility*

### Changed

- *breaking* `LookupIpFuture` renamed to `LookupIpFuture`
- *breaking* `LookupIpFuture` now takes a generic parameter, generally `<NameServerPool>`

## 0.3.0 (Client/Server 2015-09-27)

### Added

- Zone files support BIND time formats, e.g. #h#d
- Toml config file support (not compatible with BIND)

## 0.2.1 (Client/Server 2015-09-17)

### Added

- Functional tests to verify against other DNS servers

### Changed

- mio replaced std::net operators

## 0.2.0 (Resolver)

### Added

- ipv6 parallel lookup
- multiple ipv4 and ipv6 lookup strategies
- library documentation examples
- test coverage for resolver

## 0.2.0 (Client/Server 2015-09-07)

### Added

- Server support with catalog and tests for example.com
- Parsing example rfc1035 zone file
- new lexer for zone files with simplified FSM
- Travis CI testing support
- Supported Client with operational query
- Writers for Record Data
- All RFC1035 fields parsing!
- label parsing with UTF8 support
- DNS Class and RecordType enums

### Fixed

- Crates.io keywords, etc.

### Changed

- Cleaned up binary encoders and decoders with objects

## 0.1.0 (Resolver 2017-6-27)

### Added

- Initial release of the Trust-DNS Resolver

## 0.1.0 (Client/Server 2015-08-07)

### Added

- Started parsing resource records
- Initial Commit!
