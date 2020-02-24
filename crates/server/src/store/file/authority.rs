// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! All authority related types

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::pin::Pin;

use futures::future::Future;

use trust_dns_client::op::LowerQuery;
use trust_dns_client::proto::rr::dnssec::rdata::key::KEY;
use trust_dns_client::rr::dnssec::{DnsSecResult, Signer, SupportedAlgorithms};
use trust_dns_client::rr::{LowerName, Name, RecordSet, RecordType, RrKey};

use crate::authority::{Authority, LookupError, MessageRequest, UpdateResult, ZoneType};
use crate::store::file::FileConfig;
use crate::store::in_memory::InMemoryAuthority;

use trust_dns_client::serialize::txt::{Lexer, Parser, Token};

/// FileAuthority is responsible for storing the resource records for a particular zone.
///
/// Authorities default to DNSClass IN. The ZoneType specifies if this should be treated as the
/// start of authority for the zone, is a slave, or a cached zone.
pub struct FileAuthority(InMemoryAuthority);

/// TODO: should be configurable
const MAX_INCLUDE_LEVEL: u8 = 32;

/// Inner state of master file loader, tracks depth of $INCLUDE
/// loads as well as visited previously files, so the loader
/// is able to abort e.g. when cycle is detected
///
/// TODO: implemented visited files tracking and cycles detection
struct FileReaderState {
    level: u8,
}

impl FileReaderState {
    fn new() -> Self {
        FileReaderState { level: 0 }
    }
}

impl FileAuthority {
    /// Creates a new Authority.
    ///
    /// # Arguments
    ///
    /// * `origin` - The zone `Name` being created, this should match that of the `RecordType::SOA`
    ///              record.
    /// * `records` - The map of the initial set of records in the zone.
    /// * `zone_type` - The type of zone, i.e. is this authoritative?
    /// * `allow_update` - If true, then this zone accepts dynamic updates.
    /// * `is_dnssec_enabled` - If true, then the zone will sign the zone with all registered keys,
    ///                         (see `add_zone_signing_key()`)
    ///
    /// # Return value
    ///
    /// The new `Authority`.
    pub fn new(
        origin: Name,
        records: BTreeMap<RrKey, RecordSet>,
        zone_type: ZoneType,
        allow_axfr: bool,
    ) -> Result<Self, String> {
        InMemoryAuthority::new(origin, records, zone_type, allow_axfr).map(Self)
    }

    /// Read given file line by line and recursively invokes reader for
    /// $INCLUDE directives
    ///
    /// TODO: it looks hacky as far we effectively duplicate parser's functionallity
    /// (at least partially) and performing lexing twice.
    /// Better solution requires us to change lexer to deal
    /// with Lines-like iterator instead of String buf (or capability to combine a few
    /// lexer instances into a single lexer).
    ///
    /// TODO: $INCLUDE could specify domain name -- to support on-flight swap for Origin
    /// value we definitely need to rethink and rework loader/parser/lexer
    fn read_file(
        zone_path: PathBuf,
        buf: &mut String,
        state: FileReaderState,
    ) -> Result<(), String> {
        let file = File::open(&zone_path)
            .map_err(|e| format!("failed to read {}: {:?}", zone_path.display(), e))?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let content = line.unwrap();
            let mut lexer = Lexer::new(&content);

            match (lexer.next_token(), lexer.next_token()) {
                (Ok(Some(Token::Include)), Ok(Some(Token::CharData(include_path)))) => {
                    // RFC1035 (section 5) does not specify how filename for $INCLUDE
                    // should be resolved into file path. The underlying code implements the
                    // following:
                    // * if the path is absolute (relies on Path::is_absolute), it uses normalized path
                    // * otherwise, it joins the path with parent root of the current file
                    //
                    // TODO: Inlining files specified using non-relative path might potentially introduce
                    // security issue in some cases (e.g. when working with zone files from untrusted sources)
                    // and should probably be configurable by user.
                    let include_path = Path::new(&include_path);
                    let include_zone_path = if include_path.is_absolute() {
                        include_path.to_path_buf()
                    } else {
                        let parent_dir =
                            zone_path.parent().expect("file has to have parent folder");
                        parent_dir.join(include_path)
                    };

                    if state.level >= MAX_INCLUDE_LEVEL {
                        return Err(format!("Max depth level for nested $INCLUDE is reached at {}, trying to include {}", zone_path.display(), include_zone_path.display()));
                    }

                    let mut include_buf = String::new();

                    info!(
                        "including file {} into {}",
                        include_zone_path.display(),
                        zone_path.display()
                    );

                    FileAuthority::read_file(
                        include_zone_path,
                        &mut include_buf,
                        FileReaderState {
                            level: state.level + 1,
                        },
                    )?;
                    buf.push_str(&include_buf);
                }
                _ => {
                    buf.push_str(&content);
                }
            }

            buf.push('\n');
        }
        Ok(())
    }

    /// Read the Authority for the origin from the specified configuration
    pub fn try_from_config(
        origin: Name,
        zone_type: ZoneType,
        allow_axfr: bool,
        root_dir: Option<&Path>,
        config: &FileConfig,
    ) -> Result<Self, String> {
        let root_dir_path = root_dir.map(PathBuf::from).unwrap_or_else(PathBuf::new);
        let zone_path = root_dir_path.join(&config.zone_file_path);

        info!("loading zone file: {:?}", zone_path);

        let mut buf = String::new();

        // TODO: this should really use something to read line by line or some other method to
        //  keep the usage down. and be a custom lexer...
        FileAuthority::read_file(zone_path, &mut buf, FileReaderState::new())
            .map_err(|e| format!("failed to read {}: {:?}", &config.zone_file_path, e))?;

        let lexer = Lexer::new(&buf);
        let (origin, records) = Parser::new()
            .parse(lexer, Some(origin))
            .map_err(|e| format!("failed to parse {}: {:?}", config.zone_file_path, e))?;

        info!(
            "zone file loaded: {} with {} records",
            origin,
            records.len()
        );
        debug!("zone: {:#?}", records);

        FileAuthority::new(origin, records, zone_type, allow_axfr)
    }

    /// Unwrap the InMemoryAuthority
    pub fn unwrap(self) -> InMemoryAuthority {
        self.0
    }
}

impl Deref for FileAuthority {
    type Target = InMemoryAuthority;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FileAuthority {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Authority for FileAuthority {
    type Lookup = <InMemoryAuthority as Authority>::Lookup;
    type LookupFuture = <InMemoryAuthority as Authority>::LookupFuture;

    /// What type is this zone
    fn zone_type(&self) -> ZoneType {
        self.0.zone_type()
    }

    /// Return true if AXFR is allowed
    fn is_axfr_allowed(&self) -> bool {
        self.0.is_axfr_allowed()
    }

    /// Perform a dynamic update of a zone
    fn update(&mut self, _update: &MessageRequest) -> UpdateResult<bool> {
        use proto::op::ResponseCode;
        Err(ResponseCode::NotImp)
    }

    /// Get the origin of this zone, i.e. example.com is the origin for www.example.com
    fn origin(&self) -> &LowerName {
        self.0.origin()
    }

    /// Looks up all Resource Records matching the giving `Name` and `RecordType`.
    ///
    /// # Arguments
    ///
    /// * `name` - The `Name`, label, to lookup.
    /// * `rtype` - The `RecordType`, to lookup. `RecordType::ANY` will return all records matching
    ///             `name`. `RecordType::AXFR` will return all record types except `RecordType::SOA`
    ///             due to the requirements that on zone transfers the `RecordType::SOA` must both
    ///             precede and follow all other records.
    /// * `is_secure` - If the DO bit is set on the EDNS OPT record, then return RRSIGs as well.
    ///
    /// # Return value
    ///
    /// None if there are no matching records, otherwise a `Vec` containing the found records.
    fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        Box::pin(self.0.lookup(name, rtype, is_secure, supported_algorithms))
    }

    /// Using the specified query, perform a lookup against this zone.
    ///
    /// # Arguments
    ///
    /// * `query` - the query to perform the lookup with.
    /// * `is_secure` - if true, then RRSIG records (if this is a secure zone) will be returned.
    ///
    /// # Return value
    ///
    /// Returns a vectory containing the results of the query, it will be empty if not found. If
    ///  `is_secure` is true, in the case of no records found then NSEC records will be returned.
    fn search(
        &self,
        query: &LowerQuery,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        Box::pin(self.0.search(query, is_secure, supported_algorithms))
    }

    /// Get the NS, NameServer, record for the zone
    fn ns(
        &self,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        self.0.ns(is_secure, supported_algorithms)
    }

    /// Return the NSEC records based on the given name
    ///
    /// # Arguments
    ///
    /// * `name` - given this name (i.e. the lookup name), return the NSEC record that is less than
    ///            this
    /// * `is_secure` - if true then it will return RRSIG records as well
    fn get_nsec_records(
        &self,
        name: &LowerName,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        self.0
            .get_nsec_records(name, is_secure, supported_algorithms)
    }

    /// Returns the SOA of the authority.
    ///
    /// *Note*: This will only return the SOA, if this is fulfilling a request, a standard lookup
    ///  should be used, see `soa_secure()`, which will optionally return RRSIGs.
    fn soa(&self) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        self.0.soa()
    }

    /// Returns the SOA record for the zone
    fn soa_secure(
        &self,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
        self.0.soa_secure(is_secure, supported_algorithms)
    }

    /// Add a (Sig0) key that is authorized to perform updates against this authority
    fn add_update_auth_key(&mut self, name: Name, key: KEY) -> DnsSecResult<()> {
        self.0.add_update_auth_key(name, key)
    }

    /// Add Signer
    fn add_zone_signing_key(&mut self, signer: Signer) -> DnsSecResult<()> {
        self.0.add_zone_signing_key(signer)
    }

    /// Sign the zone for DNSSEC
    fn secure_zone(&mut self) -> DnsSecResult<()> {
        Authority::secure_zone(&mut self.0)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use futures::executor::block_on;
    use trust_dns_client::rr::RData;

    use super::*;
    use crate::authority::ZoneType;

    #[test]
    fn test_load_zone() {
        let config = FileConfig {
            zone_file_path: "../../tests/test-data/named_test_configs/example.com.zone".to_string(),
        };
        let authority = FileAuthority::try_from_config(
            Name::from_str("example.com.").unwrap(),
            ZoneType::Master,
            false,
            None,
            &config,
        )
        .expect("failed to load file");

        let lookup = block_on(Authority::lookup(
            &authority,
            &LowerName::from_str("www.example.com.").unwrap(),
            RecordType::A,
            false,
            SupportedAlgorithms::new(),
        ))
        .expect("lookup failed");

        match lookup
            .into_iter()
            .next()
            .expect("A record not found in authity")
            .rdata()
        {
            RData::A(ip) => assert_eq!(Ipv4Addr::new(127, 0, 0, 1), *ip),
            _ => panic!("wrong rdata type returned"),
        }

        /// some options how to make it happen:
        /// 1. parser:parse_file that builds lexer's as it needs
        ///    (mut lexer should be replaced with current_lexer and
        ///    stack of "previous" lexer's, swap when we finished with
        ///    the lexer)
        /// 2. pub function to "prepare" file before building lexer,
        ///    going line by line and simply injecting content of a different
        ///    file before even creating lexer
        let include_lookup = block_on(Authority::lookup(
            &authority,
            &LowerName::from_str("include.alias.example.com.").unwrap(),
            RecordType::A,
            false,
            SupportedAlgorithms::new(),
        ))
        .expect("INCLUDE lookup failed");

        match include_lookup
            .into_iter()
            .next()
            .expect("A record not found in authity")
            .rdata()
        {
            RData::A(ip) => assert_eq!(Ipv4Addr::new(127, 0, 0, 5), *ip),
            _ => panic!("wrong rdata type returned"),
        }
    }
}
