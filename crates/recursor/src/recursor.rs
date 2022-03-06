use std::{fmt, time::Instant};

use log::debug;

use trust_dns_proto::rr::{RecordSet, RecordType};
use trust_dns_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    error::ResolveError,
    lookup::Lookup,
    name_server::NameServerPool,
    IntoName, Name, TokioAsyncResolver, TokioConnection, TokioConnectionProvider,
};

use crate::Error;
/// A top down recursive resolver which operates off a list of "hints", this is often the root nodes.
pub struct Recursor {
    hints: TokioAsyncResolver,
    opts: ResolverOpts,
}

impl Recursor {
    /// Construct a new recursor using the list of NameServerConfigs for the hint list
    pub fn new(hints: impl Into<NameServerConfigGroup>) -> Result<Self, ResolveError> {
        // configure the trust-dns-resolver
        let mut config = ResolverConfig::new();
        let hints: NameServerConfigGroup = hints.into();

        for hint in hints.into_inner() {
            config.add_name_server(hint);
        }

        let opts = recursor_opts();
        let hints = TokioAsyncResolver::tokio(config, opts)?;

        Ok(Self { hints, opts })
    }

    /// Permform a recursive resolution
    ///
    /// [RFC 1034](https://datatracker.ietf.org/doc/html/rfc1034#section-5.3.3), Domain Concepts and Facilities, November 1987
    ///
    /// ```text
    /// 5.3.3. Algorithm
    ///
    /// The top level algorithm has four steps:
    ///
    ///    1. See if the answer is in local information, and if so return
    ///       it to the client.
    ///
    ///    2. Find the best servers to ask.
    ///
    ///    3. Send them queries until one returns a response.
    ///
    ///    4. Analyze the response, either:
    ///
    ///          a. if the response answers the question or contains a name
    ///             error, cache the data as well as returning it back to
    ///             the client.
    ///
    ///          b. if the response contains a better delegation to other
    ///             servers, cache the delegation information, and go to
    ///             step 2.
    ///
    ///          c. if the response shows a CNAME and that is not the
    ///             answer itself, cache the CNAME, change the SNAME to the
    ///             canonical name in the CNAME RR and go to step 1.
    ///
    ///          d. if the response shows a servers failure or other
    ///             bizarre contents, delete the server from the SLIST and
    ///             go back to step 3.
    ///
    /// Step 1 searches the cache for the desired data. If the data is in the
    /// cache, it is assumed to be good enough for normal use.  Some resolvers
    /// have an option at the user interface which will force the resolver to
    /// ignore the cached data and consult with an authoritative server.  This
    /// is not recommended as the default.  If the resolver has direct access to
    /// a name server's zones, it should check to see if the desired data is
    /// present in authoritative form, and if so, use the authoritative data in
    /// preference to cached data.
    ///
    /// Step 2 looks for a name server to ask for the required data.  The
    /// general strategy is to look for locally-available name server RRs,
    /// starting at SNAME, then the parent domain name of SNAME, the
    /// grandparent, and so on toward the root.  Thus if SNAME were
    /// Mockapetris.ISI.EDU, this step would look for NS RRs for
    /// Mockapetris.ISI.EDU, then ISI.EDU, then EDU, and then . (the root).
    /// These NS RRs list the names of hosts for a zone at or above SNAME.  Copy
    /// the names into SLIST.  Set up their addresses using local data.  It may
    /// be the case that the addresses are not available.  The resolver has many
    /// choices here; the best is to start parallel resolver processes looking
    /// for the addresses while continuing onward with the addresses which are
    /// available.  Obviously, the design choices and options are complicated
    /// and a function of the local host's capabilities.  The recommended
    /// priorities for the resolver designer are:
    ///
    ///    1. Bound the amount of work (packets sent, parallel processes
    ///       started) so that a request can't get into an infinite loop or
    ///       start off a chain reaction of requests or queries with other
    ///       implementations EVEN IF SOMEONE HAS INCORRECTLY CONFIGURED
    ///       SOME DATA.
    ///
    ///    2. Get back an answer if at all possible.
    ///
    ///    3. Avoid unnecessary transmissions.
    ///
    ///    4. Get the answer as quickly as possible.
    ///
    /// If the search for NS RRs fails, then the resolver initializes SLIST from
    /// the safety belt SBELT.  The basic idea is that when the resolver has no
    /// idea what servers to ask, it should use information from a configuration
    /// file that lists several servers which are expected to be helpful.
    /// Although there are special situations, the usual choice is two of the
    /// root servers and two of the servers for the host's domain.  The reason
    /// for two of each is for redundancy.  The root servers will provide
    /// eventual access to all of the domain space.  The two local servers will
    /// allow the resolver to continue to resolve local names if the local
    /// network becomes isolated from the internet due to gateway or link
    /// failure.
    ///
    /// In addition to the names and addresses of the servers, the SLIST data
    /// structure can be sorted to use the best servers first, and to insure
    /// that all addresses of all servers are used in a round-robin manner.  The
    /// sorting can be a simple function of preferring addresses on the local
    /// network over others, or may involve statistics from past events, such as
    /// previous response times and batting averages.
    ///
    /// Step 3 sends out queries until a response is received.  The strategy is
    /// to cycle around all of the addresses for all of the servers with a
    /// timeout between each transmission.  In practice it is important to use
    /// all addresses of a multihomed host, and too aggressive a retransmission
    /// policy actually slows response when used by multiple resolvers
    /// contending for the same name server and even occasionally for a single
    /// resolver.  SLIST typically contains data values to control the timeouts
    /// and keep track of previous transmissions.
    ///
    /// Step 4 involves analyzing responses.  The resolver should be highly
    /// paranoid in its parsing of responses.  It should also check that the
    /// response matches the query it sent using the ID field in the response.
    ///
    /// The ideal answer is one from a server authoritative for the query which
    /// either gives the required data or a name error.  The data is passed back
    /// to the user and entered in the cache for future use if its TTL is
    /// greater than zero.
    ///
    /// If the response shows a delegation, the resolver should check to see
    /// that the delegation is "closer" to the answer than the servers in SLIST
    /// are.  This can be done by comparing the match count in SLIST with that
    /// computed from SNAME and the NS RRs in the delegation.  If not, the reply
    /// is bogus and should be ignored.  If the delegation is valid the NS
    /// delegation RRs and any address RRs for the servers should be cached.
    /// The name servers are entered in the SLIST, and the search is restarted.
    ///
    /// If the response contains a CNAME, the search is restarted at the CNAME
    /// unless the response has the data for the canonical name or if the CNAME
    /// is the answer itself.
    ///
    /// Details and implementation hints can be found in [RFC-1035].
    ///
    /// 6. A SCENARIO
    ///
    /// In our sample domain space, suppose we wanted separate administrative
    /// control for the root, MIL, EDU, MIT.EDU and ISI.EDU zones.  We might
    /// allocate name servers as follows:
    ///
    ///
    ///                                    |(C.ISI.EDU,SRI-NIC.ARPA
    ///                                    | A.ISI.EDU)
    ///              +---------------------+------------------+
    ///              |                     |                  |
    ///             MIL                   EDU                ARPA
    ///              |(SRI-NIC.ARPA,       |(SRI-NIC.ARPA,    |
    ///              | A.ISI.EDU           | C.ISI.EDU)       |
    ///        +-----+-----+               |     +------+-----+-----+
    ///        |     |     |               |     |      |           |
    ///       BRL  NOSC  DARPA             |  IN-ADDR  SRI-NIC     ACC
    ///                                    |
    ///        +--------+------------------+---------------+--------+
    ///        |        |                  |               |        |
    ///       UCI      MIT                 |              UDEL     YALE
    ///                 |(XX.LCS.MIT.EDU, ISI
    ///                 |ACHILLES.MIT.EDU) |(VAXA.ISI.EDU,VENERA.ISI.EDU,
    ///             +---+---+              | A.ISI.EDU)
    ///             |       |              |
    ///            LCS   ACHILLES +--+-----+-----+--------+
    ///             |             |  |     |     |        |
    ///             XX            A  C   VAXA  VENERA Mockapetris
    ///
    /// In this example, the authoritative name server is shown in parentheses
    /// at the point in the domain tree at which is assumes control.
    ///
    /// Thus the root name servers are on C.ISI.EDU, SRI-NIC.ARPA, and
    /// A.ISI.EDU.  The MIL domain is served by SRI-NIC.ARPA and A.ISI.EDU.  The
    /// EDU domain is served by SRI-NIC.ARPA. and C.ISI.EDU.  Note that servers
    /// may have zones which are contiguous or disjoint.  In this scenario,
    /// C.ISI.EDU has contiguous zones at the root and EDU domains.  A.ISI.EDU
    /// has contiguous zones at the root and MIL domains, but also has a non-
    /// contiguous zone at ISI.EDU.
    /// ```
    pub async fn resolve<N: IntoName>(
        &self,
        domain: N,
        ty: RecordType,
        request_time: Instant,
    ) -> Result<Lookup, ResolveError> {
        let domain = domain.into_name()?;

        // wild guess on number fo lookups needed
        let mut lookups = Vec::<RecursiveQuery>::with_capacity(10);
        lookups.push((domain.clone(), ty).into());

        // collect all the nameservers we need.
        let mut next_ns = domain;
        loop {
            let ns = next_ns.base_name();
            if ns.is_root() {
                break;
            }

            lookups.push((ns.clone(), RecordType::NS).into());
            next_ns = ns;
        }

        for to_resolve in lookups {
            debug!("resolving: {}", to_resolve);
        }

        todo!();
    }

    async fn lookup(
        &self,
        domain: &Name,
        ty: RecordType,
        ns: &NameServerPool<TokioConnection, TokioConnectionProvider>,
    ) -> Result<RecordSet, Error> {
        unimplemented!()
    }
}

struct RecursiveQuery {
    name: Name,
    ty: RecordType,
}

impl From<(Name, RecordType)> for RecursiveQuery {
    fn from(name_ty: (Name, RecordType)) -> Self {
        Self {
            name: name_ty.0,
            ty: name_ty.1,
        }
    }
}

impl fmt::Display for RecursiveQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "({},{})", self.name, self.ty)
    }
}

fn recursor_opts() -> ResolverOpts {
    let mut options = ResolverOpts::default();
    options.ndots = 0;
    options.edns0 = true;
    options.validate = false; // we'll need to do any dnssec validation differently in a recursor (top-down rather than bottom-up)
    options.preserve_intermediates = true;
    options.recursion_desired = false;

    options
}

enum RecursiveLookup {
    Found(RecordSet),
    Forward(RecordSet),
}
