/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::collections::BTreeMap;
use std::str::FromStr;

use error::*;
use rr::{DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType, RrKey};
use serialize::txt::master_lex::{Lexer, Token};
use serialize::txt::parse_rdata::RDataParser;

/// ```text
/// 5. MASTER FILES
///
/// Master files are text files that contain RRs in text form.  Since the
/// contents of a zone can be expressed in the form of a list of RRs a
/// master file is most often used to define a zone, though it can be used
/// to list a cache's contents.  Hence, this section first discusses the
/// format of RRs in a master file, and then the special considerations when
/// a master file is used to create a zone in some name server.
///
/// 5.1. Format
///
/// The format of these files is a sequence of entries.  Entries are
/// predominantly line-oriented, though parentheses can be used to continue
/// a list of items across a line boundary, and text literals can contain
/// CRLF within the text.  Any combination of tabs and spaces act as a
/// delimiter between the separate items that make up an entry.  The end of
/// any line in the master file can end with a comment.  The comment starts
/// with a ";" (semicolon).
///
/// The following entries are defined:
///
///     <blank>[<comment>]
///
///     $ORIGIN <domain-name> [<comment>]
///
///     $INCLUDE <file-name> [<domain-name>] [<comment>]
///
///     <domain-name><rr> [<comment>]
///
///     <blank><rr> [<comment>]
///
/// Blank lines, with or without comments, are allowed anywhere in the file.
///
/// Two control entries are defined: $ORIGIN and $INCLUDE.  $ORIGIN is
/// followed by a domain name, and resets the current origin for relative
/// domain names to the stated name.  $INCLUDE inserts the named file into
/// the current file, and may optionally specify a domain name that sets the
/// relative domain name origin for the included file.  $INCLUDE may also
/// have a comment.  Note that a $INCLUDE entry never changes the relative
/// origin of the parent file, regardless of changes to the relative origin
/// made within the included file.
///
/// The last two forms represent RRs.  If an entry for an RR begins with a
/// blank, then the RR is assumed to be owned by the last stated owner.  If
/// an RR entry begins with a <domain-name>, then the owner name is reset.
///
/// <rr> contents take one of the following forms:
///
///     [<TTL>] [<class>] <type> <RDATA>
///
///     [<class>] [<TTL>] <type> <RDATA>
///
/// The RR begins with optional TTL and class fields, followed by a type and
/// RDATA field appropriate to the type and class.  Class and type use the
/// standard mnemonics, TTL is a decimal integer.  Omitted class and TTL
/// values are default to the last explicitly stated values.  Since type and
/// class mnemonics are disjoint, the parse is unique.  (Note that this
/// order is different from the order used in examples and the order used in
/// the actual RRs; the given order allows easier parsing and defaulting.)
///
/// <domain-name>s make up a large share of the data in the master file.
/// The labels in the domain name are expressed as character strings and
/// separated by dots.  Quoting conventions allow arbitrary characters to be
/// stored in domain names.  Domain names that end in a dot are called
/// absolute, and are taken as complete.  Domain names which do not end in a
/// dot are called relative; the actual domain name is the concatenation of
/// the relative part with an origin specified in a $ORIGIN, $INCLUDE, or as
/// an argument to the master file loading routine.  A relative name is an
/// error when no origin is available.
///
/// <character-string> is expressed in one or two ways: as a contiguous set
/// of characters without interior spaces, or as a string beginning with a "
/// and ending with a ".  Inside a " delimited string any character can
/// occur, except for a " itself, which must be quoted using \ (back slash).
///
/// Because these files are text files several special encodings are
/// necessary to allow arbitrary data to be loaded.  In particular:
///
///                 of the root.
///
/// @               A free standing @ is used to denote the current origin.
///
/// \X              where X is any character other than a digit (0-9), is
///                 used to quote that character so that its special meaning
///                 does not apply.  For example, "\." can be used to place
///                 a dot character in a label.
///
/// \DDD            where each D is a digit is the octet corresponding to
///                 the decimal number described by DDD.  The resulting
///                 octet is assumed to be text and is not checked for
///                 special meaning.
///
/// ( )             Parentheses are used to group data that crosses a line
///                 boundary.  In effect, line terminations are not
///                 recognized within parentheses.
///
/// ;               Semicolon is used to start a comment; the remainder of
///                 the line is ignored.
/// ```
#[derive(Default)]
pub struct Parser;

impl Parser {
    /// Returns a new Zone file parser
    pub fn new() -> Self {
        Parser
    }

    /// Parse a file from the Lexer
    ///
    /// # Return
    ///
    /// A pair of the Zone origin name and a map of all Keys to RecordSets
    pub fn parse(
        &mut self,
        lexer: Lexer,
        origin: Option<Name>,
    ) -> ParseResult<(Name, BTreeMap<RrKey, RecordSet>)> {
        let mut lexer = lexer;
        let mut records: BTreeMap<RrKey, RecordSet> = BTreeMap::new();

        let mut fields = ParserFields::new(origin);
        let mut state = State::StartLine;

        while let Some(t) = lexer.next_token()? {
            state = match state {
                State::StartLine => {
                    // current_name is not reset on the next line b/c it might be needed from the previous
                    fields.drop_rtype();

                    match t {
                        // if Dollar, then $INCLUDE or $ORIGIN or $TTL
                        Token::Include => unimplemented!(),
                        Token::Origin => State::Origin,
                        Token::Ttl => State::Ttl,

                        // if CharData, then Name then ttl_class_type
                        Token::CharData(data) => {
                            let name = fields.parse_name(&data)?;
                            fields.set_current_name(name);
                            State::TtlClassType
                        }

                        // @ is a placeholder for specifying the current origin
                        Token::At => {
                            fields.flush_current_name();
                            State::TtlClassType
                        }

                        // if blank, then nothing or ttl_class_type
                        Token::Blank => State::TtlClassType,
                        Token::EOL => State::StartLine, // probably a comment
                        _ => return Err(ParseErrorKind::UnexpectedToken(t).into()),
                    }
                }
                State::Ttl => match t {
                    Token::CharData(data) => {
                        fields.set_ttl(Self::parse_time(&data)?);
                        State::StartLine
                    }
                    _ => return Err(ParseErrorKind::UnexpectedToken(t).into()),
                },
                State::Origin => {
                    match t {
                        Token::CharData(data) => {
                            // TODO an origin was specified, should this be legal? definitely confusing...
                            let origin = fields.parse_name(&data)?;
                            fields.set_origin(origin);
                            State::StartLine
                        }
                        _ => return Err(ParseErrorKind::UnexpectedToken(t).into()),
                    }
                }
                State::Include => unimplemented!(),
                State::TtlClassType => {
                    match t {
                        // if number, TTL
                        // Token::Number(ref num) => ttl = Some(*num),
                        // One of Class or Type (these cannot be overlapping!)
                        Token::CharData(data) => {
                            // if it's a number it's a ttl
                            match Self::parse_time(&data) {
                                Ok(ttl) => {
                                    fields.set_ttl(ttl);
                                    State::TtlClassType
                                }
                                Err(_) => {
                                    match DNSClass::from_str(&data) {
                                        Ok(cls) => {
                                            fields.set_class(cls);
                                            State::TtlClassType
                                        }
                                        Err(_) => {
                                            let rtype = RecordType::from_str(&data)?;
                                            fields.set_rtype(rtype);
                                            State::Record(vec![])
                                        }
                                    }
                                }
                            }
                        }
                        // could be nothing if started with blank and is a comment, i.e. EOL
                        Token::EOL => {
                            State::StartLine // next line
                        }
                        _ => return Err(ParseErrorKind::UnexpectedToken(t).into()),
                    }
                }
                State::Record(record_parts) => {
                    // b/c of ownership rules, perhaps, just collect all the RData components as a list of
                    //  tokens to pass into the processor
                    match t {
                        Token::EOL => {
                            Self::flush_record(
                                record_parts,
                                &mut fields,
                                &mut records,
                            )?;
                            State::StartLine
                        }
                        Token::CharData(part) => {
                            let mut record_parts = record_parts;
                            record_parts.push(part);
                            State::Record(record_parts)
                        }
                        // TODO: we should not tokenize the list...
                        Token::List(list) => {
                            let mut record_parts = record_parts;
                            record_parts.extend(list);
                            State::Record(record_parts)
                        }
                        _ => return Err(ParseErrorKind::UnexpectedToken(t).into()),
                    }
                }
            }
        }

        //Extra flush at the end for the case of missing endline
        if let State::Record(record_parts) = state {
            Self::flush_record(
                record_parts,
                &mut fields,
                &mut records,
            )?;
        }

        //
        // build the Authority and return.
        let origin = fields.origin.ok_or_else(|| {
            ParseError::from(ParseErrorKind::Message("$ORIGIN was not specified"))
        })?;
        Ok((origin, records))
    }

    fn flush_record(
        record_parts: Vec<String>,
        fields: &mut ParserFields,
        records: &mut BTreeMap<RrKey, RecordSet>,
    ) -> ParseResult<()> {

        let record = fields.make_record(record_parts)?;

        // add to the map
        let key = RrKey::new(LowerName::new(record.name()), record.rr_type());
        match record.rr_type() {
            RecordType::SOA => {
                let set = record.into();
                if records.insert(key, set).is_some() {
                    return Err(ParseErrorKind::Message("SOA is already specified").into());
                }
            }
            _ => {
                // add a Vec if it's not there, then add the record to the list
                let set = records
                    .entry(key)
                    .or_insert_with(|| RecordSet::new(record.name(), record.rr_type(), 0));
                set.insert(record, 0);
            }
        }
        Ok(())
    }

    /// parses the string following the rules from:
    ///  https://tools.ietf.org/html/rfc2308 (NXCaching RFC) and
    ///  http://www.zytrax.com/books/dns/apa/time.html
    ///
    /// default is seconds
    /// #s = seconds = # x 1 seconds (really!)
    /// #m = minutes = # x 60 seconds
    /// #h = hours   = # x 3600 seconds
    /// #d = day     = # x 86400 seconds
    /// #w = week    = # x 604800 seconds
    ///
    /// returns the result of the parsing or and error
    ///
    /// # Example
    /// ```
    /// use trust_dns::serialize::txt::Parser;
    ///
    /// assert_eq!(Parser::parse_time("0").unwrap(),  0);
    /// assert_eq!(Parser::parse_time("s").unwrap(),  0);
    /// assert_eq!(Parser::parse_time("0s").unwrap(), 0);
    /// assert_eq!(Parser::parse_time("1").unwrap(),  1);
    /// assert_eq!(Parser::parse_time("1S").unwrap(), 1);
    /// assert_eq!(Parser::parse_time("1s").unwrap(), 1);
    /// assert_eq!(Parser::parse_time("1M").unwrap(), 60);
    /// assert_eq!(Parser::parse_time("1m").unwrap(), 60);
    /// assert_eq!(Parser::parse_time("1H").unwrap(), 3600);
    /// assert_eq!(Parser::parse_time("1h").unwrap(), 3600);
    /// assert_eq!(Parser::parse_time("1D").unwrap(), 86400);
    /// assert_eq!(Parser::parse_time("1d").unwrap(), 86400);
    /// assert_eq!(Parser::parse_time("1W").unwrap(), 604800);
    /// assert_eq!(Parser::parse_time("1w").unwrap(), 604800);
    /// assert_eq!(Parser::parse_time("1s2d3w4h2m").unwrap(), 1+2*86400+3*604800+4*3600+2*60);
    /// assert_eq!(Parser::parse_time("3w3w").unwrap(), 3*604800+3*604800);
    /// ```
    pub fn parse_time(ttl_str: &str) -> ParseResult<u32> {
        let mut value: u32 = 0;
        let mut collect: u32 = 0;

        for c in ttl_str.chars() {
            match c {
                // TODO, should these all be checked operations?
                '0'...'9' => {
                    collect *= 10;
                    collect += c.to_digit(10)
                        .ok_or_else(|| ParseErrorKind::CharToInt(c))?;
                }
                'S' | 's' => {
                    value += collect;
                    collect = 0;
                }
                'M' | 'm' => {
                    value += collect * 60;
                    collect = 0;
                }
                'H' | 'h' => {
                    value += collect * 3_600;
                    collect = 0;
                }
                'D' | 'd' => {
                    value += collect * 86_400;
                    collect = 0;
                }
                'W' | 'w' => {
                    value += collect * 604_800;
                    collect = 0;
                }
                _ => return Err(ParseErrorKind::ParseTime(ttl_str.to_string()).into()),
            }
        }

        Ok(value + collect) // collects the initial num, or 0 if it was already collected
    }
}


struct ParserFields {
    current_name: Option<Name>,
    origin: Option<Name>,
    rtype: Option<RecordType>,
    ttl: Option<u32>,
    class: Option<DNSClass>,
}

impl ParserFields {
    fn new(origin: Option<Name>) -> Self {
        Self {
            origin,
            current_name: None,
            rtype: None,
            ttl: None,
            class: None,
        }
    }

    fn drop_rtype(&mut self) {
        self.rtype = None
    }

    fn set_class(&mut self, cls: DNSClass) {
        self.class = Some(cls)
    }

    fn set_rtype(&mut self, rtype: RecordType) {
        self.rtype = Some(rtype)
    }

    fn set_current_name(&mut self, name: Name) {
        self.current_name = Some(name)
    }

    //Sets current name to origin
    //not sure about naming
    fn flush_current_name(&mut self) {
        self.current_name = self.origin.as_ref().cloned()
    }

    fn set_ttl(&mut self, ttl: u32) {
        self.ttl = Some(ttl)
    }

    fn set_origin(&mut self, origin: Name) {
        self.origin = Some(origin)
    }

    fn parse_name(&self, data: &str) -> ParseResult<Name> {
        //Using `?` to convert ProtoError to ParseError
        Ok(Name::parse(&data, self.origin.as_ref())?)
    }

    fn make_record(&mut self, record_parts: Vec<String>) -> ParseResult<Record> {
        let mut record = Record::new();
        let rtype = self.rtype.ok_or_else(|| {
            ParseError::from(ParseErrorKind::Message("record type not specified"))
        })?;
        record.set_rr_type(rtype);

        record.set_name(
            self.current_name
                .as_ref()
                .cloned()
                .ok_or_else(|| {
                    ParseError::from(ParseErrorKind::Message("record name not specified"))
                })?
        );

        record.set_dns_class(self.class.ok_or_else(|| {
            ParseError::from(ParseErrorKind::Message("record class not specified"))
        })?);

        let rdata = RData::parse(
            rtype,
            record_parts.iter().map(|s| s.as_ref()),
            self.origin.as_ref(),
        )?;

        let ttl: u32 = match rtype {
            RecordType::SOA =>  {
                if let RData::SOA(ref soa) = rdata {
                    //using soa.expire as default TTL until specified otherwise
                    if self.ttl.is_none() {
                        self.set_ttl(soa.expire() as u32)
                    }
                    soa.minimum()
                } else {
                    //Maybe embed RData into RecordType to make it impossible?
                    panic!("Invalid RData here, expected SOA: {:?}", rdata);
                }
            }
            _ => {
                self.ttl.ok_or_else(|| {
                    ParseErrorKind::Message("record ttl is not specified")
                })?
            }
        };
        record.set_rdata(rdata);
        record.set_ttl(ttl);

        // verify that we have everything we need for the record

        Ok(record)
    }
}

#[allow(unused)]
enum State {
    StartLine,    // start of line, @, $<WORD>, Name, Blank
    TtlClassType, // [<TTL>] [<class>] <type>,
    Ttl,          // $TTL <time>
    Record(Vec<String>),
    Include, // $INCLUDE <filename>
    Origin,
}
