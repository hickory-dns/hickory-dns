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

use std::collections::HashMap;
use std::io::Read;
use std::fs::File;

use ::error::*;
use ::rr::Name;
use ::rr::RecordType;
use ::rr::Record;
use ::rr::DNSClass;
use ::rr::RData;

use super::master_lex::{Lexer, Token};

 // 5. MASTER FILES
 //
 // Master files are text files that contain RRs in text form.  Since the
 // contents of a zone can be expressed in the form of a list of RRs a
 // master file is most often used to define a zone, though it can be used
 // to list a cache's contents.  Hence, this section first discusses the
 // format of RRs in a master file, and then the special considerations when
 // a master file is used to create a zone in some name server.
 //
 // 5.1. Format
 //
 // The format of these files is a sequence of entries.  Entries are
 // predominantly line-oriented, though parentheses can be used to continue
 // a list of items across a line boundary, and text literals can contain
 // CRLF within the text.  Any combination of tabs and spaces act as a
 // delimiter between the separate items that make up an entry.  The end of
 // any line in the master file can end with a comment.  The comment starts
 // with a ";" (semicolon).
 //
 // The following entries are defined:
 //
 //     <blank>[<comment>]
 //
 //     $ORIGIN <domain-name> [<comment>]
 //
 //     $INCLUDE <file-name> [<domain-name>] [<comment>]
 //
 //     <domain-name><rr> [<comment>]
 //
 //     <blank><rr> [<comment>]
 //
 // Blank lines, with or without comments, are allowed anywhere in the file.
 //
 // Two control entries are defined: $ORIGIN and $INCLUDE.  $ORIGIN is
 // followed by a domain name, and resets the current origin for relative
 // domain names to the stated name.  $INCLUDE inserts the named file into
 // the current file, and may optionally specify a domain name that sets the
 // relative domain name origin for the included file.  $INCLUDE may also
 // have a comment.  Note that a $INCLUDE entry never changes the relative
 // origin of the parent file, regardless of changes to the relative origin
 // made within the included file.
 //
 // The last two forms represent RRs.  If an entry for an RR begins with a
 // blank, then the RR is assumed to be owned by the last stated owner.  If
 // an RR entry begins with a <domain-name>, then the owner name is reset.
 //
 // <rr> contents take one of the following forms:
 //
 //     [<TTL>] [<class>] <type> <RDATA>
 //
 //     [<class>] [<TTL>] <type> <RDATA>
 //
 // The RR begins with optional TTL and class fields, followed by a type and
 // RDATA field appropriate to the type and class.  Class and type use the
 // standard mnemonics, TTL is a decimal integer.  Omitted class and TTL
 // values are default to the last explicitly stated values.  Since type and
 // class mnemonics are disjoint, the parse is unique.  (Note that this
 // order is different from the order used in examples and the order used in
 // the actual RRs; the given order allows easier parsing and defaulting.)
 //
 // <domain-name>s make up a large share of the data in the master file.
 // The labels in the domain name are expressed as character strings and
 // separated by dots.  Quoting conventions allow arbitrary characters to be
 // stored in domain names.  Domain names that end in a dot are called
 // absolute, and are taken as complete.  Domain names which do not end in a
 // dot are called relative; the actual domain name is the concatenation of
 // the relative part with an origin specified in a $ORIGIN, $INCLUDE, or as
 // an argument to the master file loading routine.  A relative name is an
 // error when no origin is available.
 //
 // <character-string> is expressed in one or two ways: as a contiguous set
 // of characters without interior spaces, or as a string beginning with a "
 // and ending with a ".  Inside a " delimited string any character can
 // occur, except for a " itself, which must be quoted using \ (back slash).
 //
 // Because these files are text files several special encodings are
 // necessary to allow arbitrary data to be loaded.  In particular:
 //
 //                 of the root.
 //
 // @               A free standing @ is used to denote the current origin.
 //
 // \X              where X is any character other than a digit (0-9), is
 //                 used to quote that character so that its special meaning
 //                 does not apply.  For example, "\." can be used to place
 //                 a dot character in a label.
 //
 // \DDD            where each D is a digit is the octet corresponding to
 //                 the decimal number described by DDD.  The resulting
 //                 octet is assumed to be text and is not checked for
 //                 special meaning.
 //
 // ( )             Parentheses are used to group data that crosses a line
 //                 boundary.  In effect, line terminations are not
 //                 recognized within parentheses.
 //
 // ;               Semicolon is used to start a comment; the remainder of
 //                 the line is ignored.
pub struct Parser {
  records: HashMap<RecordType, Record>,
  origin: Option<Name>,
}

impl Parser {
  pub fn new() -> Self {
    Parser { records: HashMap::new(), origin: None }
  }

  pub fn parse(&mut self, file: File) {
    let mut lexer = Lexer::with_chars(file.chars());
    let mut previous_name: Option<Name> = None;
    let mut rtype: Option<RecordType> = None;
    let mut ttl: Option<i32> = None;
    let mut class: Option<DNSClass> = None;
    let mut state = State::StartLine;
    let mut tokens: Vec<Token> = Vec::new();

    while let Some(t) = lexer.next_token() {
      state = match state {
        State::StartLine => {
          rtype = None;
          ttl = None;
          class = None;
          tokens.clear();

          match t {
            // if Dollar, then $INCLUDE or $ORIGIN
            Token::Dollar("INCLUDE") => unimplemented!(),
            Token::Dollar("ORIGIN") => unimplemented!(),

            // if CharData, then Name then ttl_class_type
            Token::CharData(ref data) => unimplemented!(),

            // if blank, then nothing or ttl_class_type... grr...
            Token::Blank => unimplemented!(),
            Token::EOL => State::StartLine, // probably a comment
            // _ => return Err(ParseError::UnrecognizedToken(t)),
          }
        },
        State::Ttl_Class_Type => {
          match t {
            // if number, TTL
            // Token::Number(ref num) => ttl = Some(*num),
            // One of Class or Type (these cannot be overlapping!)
            Token::CharData(ref data) => {
              // if it's a number it's a ttl
              let result = i32::from_str(data);
              if result.is_ok() {
                ttl = result.ok();
                return State::Ttl_Class_Type
              }

              // if can parse DNSClass, then class
              let result = DNSClass::from_str(data);
              if result.is_ok() {
                class = Some(result);
                return State::Ttl_Class_Type
              }

              // if can parse RecordType, then RecordType
              rtype = try!(RecordType::from_str(data));
              State::Record
            }
            // could be nothing if started with blank and is a comment, i.e. EOL
            Token::EOL => {
              State::StartLine // next line
            }
          }
        },
        State::Record => {
          // b/c of ownership rules, perhaps, just collect all the RData components as a list of
          //  tokens to pass into the processor
          match t {
            Token::EOL => State::EndRecord,
            _ => { tokens.push(t); State::Record },
          }
        },
        State::EndRecord => {
          // call out to parsers for difference record types
          let RData = try!(RData::parse(tokens));

          State::StartLine
        },
      }
    }

    // get the last one...
  }
}

enum State {
  StartLine,       // start of line, @, $<WORD>, Name, Blank
  Ttl_Class_Type,  // [<TTL>] [<class>] <type>,
  Record,
  EndRecord,
}
