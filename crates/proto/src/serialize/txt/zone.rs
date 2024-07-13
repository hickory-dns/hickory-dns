// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{
    borrow::Cow,
    collections::BTreeMap,
    fs, mem,
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::{
    rr::{DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType, RrKey},
    serialize::txt::{
        parse_rdata::RDataParser,
        zone_lex::{Lexer, Token},
        ParseError, ParseErrorKind, ParseResult,
    },
};

/// ```text
/// 5. ZONE FILES
///
/// Zone files are text files that contain RRs in text form.  Since the
/// contents of a zone can be expressed in the form of a list of RRs a
/// Zone File is most often used to define a zone, though it can be used
/// to list a cache's contents.  Hence, this section first discusses the
/// format of RRs in a Zone File, and then the special considerations when
/// a Zone File is used to create a zone in some name server.
///
/// 5.1. Format
///
/// The format of these files is a sequence of entries.  Entries are
/// predominantly line-oriented, though parentheses can be used to continue
/// a list of items across a line boundary, and text literals can contain
/// CRLF within the text.  Any combination of tabs and spaces act as a
/// delimiter between the separate items that make up an entry.  The end of
/// any line in the Zone File can end with a comment.  The comment starts
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
/// <domain-name>s make up a large share of the data in the Zone File.
/// The labels in the domain name are expressed as character strings and
/// separated by dots.  Quoting conventions allow arbitrary characters to be
/// stored in domain names.  Domain names that end in a dot are called
/// absolute, and are taken as complete.  Domain names which do not end in a
/// dot are called relative; the actual domain name is the concatenation of
/// the relative part with an origin specified in a $ORIGIN, $INCLUDE, or as
/// an argument to the Zone File loading routine.  A relative name is an
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
pub struct Parser<'a> {
    lexers: Vec<(Lexer<'a>, Option<PathBuf>)>,
    origin: Option<Name>,
}

impl<'a> Parser<'a> {
    /// Returns a new Zone file parser
    ///
    /// The `path` argument's parent directory is used to resolve relative `$INCLUDE` paths.
    /// Relative `$INCLUDE` paths will yield an error if `path` is `None`.
    pub fn new(
        input: impl Into<Cow<'a, str>>,
        path: Option<PathBuf>,
        origin: Option<Name>,
    ) -> Self {
        Self {
            lexers: vec![(Lexer::new(input), path)],
            origin,
        }
    }

    /// Parse a file from the Lexer
    ///
    /// # Return
    ///
    /// A pair of the Zone origin name and a map of all Keys to RecordSets
    pub fn parse(mut self) -> ParseResult<(Name, BTreeMap<RrKey, RecordSet>)> {
        let mut origin = self.origin;
        let mut records: BTreeMap<RrKey, RecordSet> = BTreeMap::new();
        let mut class: DNSClass = DNSClass::IN;
        let mut current_name: Option<Name> = None;
        let mut rtype: Option<RecordType> = None;
        let mut ttl: Option<u32> = None;
        let mut state = State::StartLine;
        let mut stack = self.lexers.len();

        'outer: while let Some((lexer, path)) = self.lexers.last_mut() {
            while let Some(t) = lexer.next_token()? {
                state = match state {
                    State::StartLine => {
                        // current_name is not reset on the next line b/c it might be needed from the previous
                        rtype = None;

                        match t {
                            // if Dollar, then $INCLUDE or $ORIGIN
                            Token::Include => State::Include(None),
                            Token::Origin => State::Origin,
                            Token::Ttl => State::Ttl,

                            // if CharData, then Name then ttl_class_type
                            Token::CharData(data) => {
                                current_name = Some(Name::parse(&data, origin.as_ref())?);
                                State::TtlClassType
                            }

                            // @ is a placeholder for specifying the current origin
                            Token::At => {
                                current_name.clone_from(&origin); // TODO a COW or RC would reduce copies...
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
                            ttl = Some(Self::parse_time(&data)?);
                            State::StartLine
                        }
                        _ => return Err(ParseErrorKind::UnexpectedToken(t).into()),
                    },
                    State::Origin => {
                        match t {
                            Token::CharData(data) => {
                                // TODO an origin was specified, should this be legal? definitely confusing...
                                origin = Some(Name::parse(&data, None)?);
                                State::StartLine
                            }
                            _ => return Err(ParseErrorKind::UnexpectedToken(t).into()),
                        }
                    }
                    State::Include(include_path) => match (t, include_path) {
                        (Token::CharData(data), None) => State::Include(Some(data)),
                        (Token::EOL, Some(include_path)) => {
                            // RFC1035 (section 5) does not specify how filename for $INCLUDE
                            // should be resolved into file path. The underlying code implements the
                            // following:
                            // * if the path is absolute (relies on Path::is_absolute), it uses normalized path
                            // * otherwise, it joins the path with parent root of the current file
                            //
                            // TODO: Inlining files specified using non-relative path might potentially introduce
                            // security issue in some cases (e.g. when working with zone files from untrusted sources)
                            // and should probably be configurable by user.

                            if stack > MAX_INCLUDE_LEVEL {
                                return Err(ParseErrorKind::Message(
                                    "Max depth level for nested $INCLUDE is reached",
                                )
                                .into());
                            }

                            let include = Path::new(&include_path);
                            let include = match (include.is_absolute(), path) {
                                (true, _) => include.to_path_buf(),
                                (false, Some(path)) => path
                                    .parent()
                                    .expect("file has to have parent folder")
                                    .join(include),
                                (false, None) => {
                                    return Err(ParseErrorKind::Message(
                                        "Relative $INCLUDE is not supported",
                                    )
                                    .into());
                                }
                            };

                            let input = fs::read_to_string(&include)?;
                            let lexer = Lexer::new(input);
                            self.lexers.push((lexer, Some(include)));
                            stack += 1;
                            state = State::StartLine;
                            continue 'outer;
                        }
                        (Token::CharData(_), Some(_)) => {
                            return Err(ParseErrorKind::Message(
                                "Domain name for $INCLUDE is not supported",
                            )
                            .into());
                        }
                        (t, _) => {
                            return Err(ParseErrorKind::UnexpectedToken(t).into());
                        }
                    },
                    State::TtlClassType => {
                        match t {
                            // if number, TTL
                            // Token::Number(ref num) => ttl = Some(*num),
                            // One of Class or Type (these cannot be overlapping!)
                            Token::CharData(mut data) => {
                                // if it's a number it's a ttl
                                let result: ParseResult<u32> = Self::parse_time(&data);
                                if result.is_ok() {
                                    ttl = result.ok();
                                    State::TtlClassType // hm, should this go to just ClassType?
                                } else {
                                    // if can parse DNSClass, then class
                                    data.make_ascii_uppercase();
                                    let result = DNSClass::from_str(&data);
                                    if let Ok(parsed) = result {
                                        class = parsed;
                                        State::TtlClassType
                                    } else {
                                        // if can parse RecordType, then RecordType
                                        rtype = Some(RecordType::from_str(&data)?);
                                        State::Record(vec![])
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
                                    &origin,
                                    &current_name,
                                    rtype,
                                    &mut ttl,
                                    class,
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
                };
            }

            // Extra flush at the end for the case of missing endline
            if let State::Record(record_parts) = mem::replace(&mut state, State::StartLine) {
                Self::flush_record(
                    record_parts,
                    &origin,
                    &current_name,
                    rtype,
                    &mut ttl,
                    class,
                    &mut records,
                )?;
            }

            stack -= 1;
            self.lexers.pop();
        }

        //
        // build the Authority and return.
        let origin = origin.ok_or_else(|| {
            ParseError::from(ParseErrorKind::Message("$ORIGIN was not specified"))
        })?;
        Ok((origin, records))
    }

    fn flush_record(
        record_parts: Vec<String>,
        origin: &Option<Name>,
        current_name: &Option<Name>,
        rtype: Option<RecordType>,
        ttl: &mut Option<u32>,
        class: DNSClass,
        records: &mut BTreeMap<RrKey, RecordSet>,
    ) -> ParseResult<()> {
        // call out to parsers for difference record types
        // all tokens as part of the Record should be chardata...
        let rtype = rtype.ok_or_else(|| {
            ParseError::from(ParseErrorKind::Message("record type not specified"))
        })?;
        let rdata = RData::parse(
            rtype,
            record_parts.iter().map(AsRef::as_ref),
            origin.as_ref(),
        )?;

        // verify that we have everything we need for the record
        // TODO COW or RC would reduce mem usage, perhaps Name should have an intern()...
        //  might want to wait until RC.weak() stabilizes, as that would be needed for global
        //  memory where you want
        let name = current_name.clone().ok_or_else(|| {
            ParseError::from(ParseErrorKind::Message("record name not specified"))
        })?;

        // slightly annoying, need to grab the TTL, then move rdata into the record,
        //  then check the Type again and have custom add logic.
        let set_ttl = match rtype {
            RecordType::SOA => {
                // TTL for the SOA is set internally...
                // expire is for the SOA, minimum is default for records
                if let RData::SOA(ref soa) = rdata {
                    // TODO, this looks wrong, get_expire() should be get_minimum(), right?
                    let set_ttl = soa.expire() as u32; // the spec seems a little inaccurate with u32 and i32
                    if ttl.is_none() {
                        *ttl = Some(soa.minimum());
                    } // TODO: should this only set it if it's not set?
                    set_ttl
                } else {
                    let msg = format!("Invalid RData here, expected SOA: {rdata:?}");
                    return ParseResult::Err(ParseError::from(ParseErrorKind::Msg(msg)));
                }
            }
            _ => ttl.ok_or_else(|| {
                ParseError::from(ParseErrorKind::Message("record ttl not specified"))
            })?,
        };

        // TODO: validate record, e.g. the name of SRV record allows _ but others do not.

        // move the rdata into record...
        let mut record = Record::from_rdata(name, set_ttl, rdata);
        record.set_dns_class(class);

        // add to the map
        let key = RrKey::new(LowerName::new(record.name()), record.record_type());
        match rtype {
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
                    .or_insert_with(|| RecordSet::new(record.name(), record.record_type(), 0));
                set.insert(record, 0);
            }
        }
        Ok(())
    }

    /// parses the string following the rules from:
    ///  <https://tools.ietf.org/html/rfc2308> (NXCaching RFC) and
    ///  <https://www.zytrax.com/books/dns/apa/time.html>
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
    /// use hickory_proto::serialize::txt::Parser;
    ///
    /// assert_eq!(Parser::parse_time("0").unwrap(),  0);
    /// assert!(Parser::parse_time("s").is_err());
    /// assert!(Parser::parse_time("").is_err());
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
    /// assert!(Parser::parse_time("7102w").is_err());
    /// ```
    pub fn parse_time(ttl_str: &str) -> ParseResult<u32> {
        if ttl_str.is_empty() {
            return Err(ParseErrorKind::ParseTime(ttl_str.to_string()).into());
        }

        let (mut state, mut value) = (None, 0_u32);
        for (i, c) in ttl_str.chars().enumerate() {
            let start = match (state, c) {
                (None, '0'..='9') => {
                    state = Some(i);
                    continue;
                }
                (Some(_), '0'..='9') => continue,
                (Some(start), 'S' | 's' | 'M' | 'm' | 'H' | 'h' | 'D' | 'd' | 'W' | 'w') => start,
                _ => return Err(ParseErrorKind::ParseTime(ttl_str.to_string()).into()),
            };

            // All allowed chars are ASCII, so using char indexes to slice &[u8] is OK
            let number = u32::from_str(&ttl_str[start..i])
                .map_err(|_| ParseErrorKind::ParseTime(ttl_str.to_string()))?;

            let multiplier = match c {
                'S' | 's' => 1,
                'M' | 'm' => 60,
                'H' | 'h' => 3_600,
                'D' | 'd' => 86_400,
                'W' | 'w' => 604_800,
                _ => unreachable!(),
            };

            value = number
                .checked_mul(multiplier)
                .and_then(|add| value.checked_add(add))
                .ok_or_else(|| ParseErrorKind::ParseTime(ttl_str.to_string()))?;

            state = None;
        }

        if let Some(start) = state {
            // All allowed chars are ASCII, so using char indexes to slice &[u8] is OK
            let number = u32::from_str(&ttl_str[start..])
                .map_err(|_| ParseErrorKind::ParseTime(ttl_str.to_string()))?;
            value = value
                .checked_add(number)
                .ok_or_else(|| ParseErrorKind::ParseTime(ttl_str.to_string()))?;
        }

        Ok(value)
    }
}

#[allow(unused)]
enum State {
    StartLine,    // start of line, @, $<WORD>, Name, Blank
    TtlClassType, // [<TTL>] [<class>] <type>,
    Ttl,          // $TTL <time>
    Record(Vec<String>),
    Include(Option<String>), // $INCLUDE <filename>
    Origin,
}

/// Max traversal depth for $INCLUDE files
const MAX_INCLUDE_LEVEL: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::uninlined_format_args)]
    fn test_zone_parse() {
        let domain = Name::from_str("parameter.origin.org.").unwrap();

        let zone_data = r#"$ORIGIN parsed.zone.origin.org.
 faulty-record-type 60 IN A 1.2.3.4
"#;

        let result = Parser::new(zone_data, None, Some(domain)).parse();
        assert!(
            result.is_err()
                & result
                    .as_ref()
                    .unwrap_err()
                    .to_string()
                    .contains("FAULTY-RECORD-TYPE"),
            "unexpected success: {:#?}",
            result
        );
    }
}
