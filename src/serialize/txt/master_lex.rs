use std::cell::{Cell,RefCell};
use std::iter::Peekable;
use std::str::Chars;
use std::char;
use std::fs::File;

use ::error::{LexerResult,LexerError};

pub struct Lexer<'a> {
  txt: Peekable<Chars<'a>>,
  is_first_line: bool,
  in_list: bool,
}

impl<'a> Lexer<'a> {
  pub fn new(txt: &str) -> Lexer {
    Lexer { txt: txt.chars().peekable(), is_first_line: true, in_list: false }
  }

  pub fn next_token(&mut self) -> LexerResult<Option<Token>> {
    let mut cur_token: Cell<Option<State>> = Cell::new(None);
    let mut cur_string: RefCell<Option<String>> = RefCell::new(None);

    //while let Some(ch) = self.txt.by_ref().peekable().peek() {
    'out: for i in 0..4096 { // max chars in a single lex, helps with issues in the lexer...
      assert!(i < 4095);     // keeps the bounds of the loop defined (nothing lasts forever)

      // This is to get around mutibility rules such that we can peek at the iter without moving next...
      let ch: char = if let Some(c) = self.peek() { c } else { break 'out };

      // collectors
      if let Some(t) = cur_token.get() {
        match t {
          State::Comment => {
            match ch {
              '\n' => cur_token.set(None), // out of the comment
              _ => { self.txt.next(); }, // advance the token by default
            }

            continue 'out;
          },
          State::Quote => {
            match ch {
              '"' => { cur_token.set(Some(State::Quoted)); self.txt.next() ; break 'out },
              '\\' => try!(self.escape_seq().and_then(|ch|Ok(self.push(State::Quote, &cur_token, &cur_string, ch)))),
              _ => self.push(State::Quote, &cur_token, &cur_string, ch),
            }

            continue 'out; // skipping rest of processing for quoted strings.
          }
          State::Dollar => {
            match ch {
              'A' ... 'Z' => { self.push(State::Dollar, &cur_token, &cur_string, ch); continue 'out },
              _ => { break 'out},
            }
          }
          _ => (),// do nothing
        }
      }

      // general case match for all other states...
      match ch {
        ' '|'\t' => {
          if self.is_first_line { self.set_token_if_not(State::Blank, &cur_token); break } // need the first blank on a line
          if cur_token.get().is_some() { break } else { self.txt.next(); continue }  // gobble all whitespace
        },
        'a' ... 'z' | 'A' ... 'Z' | '-' | '.' | '0' ... '9' => { self.push(State::CharData, &cur_token, &cur_string, ch); },
        '\r' => if cur_token.get().is_some() { break } else { self.txt.next(); continue },
        '\n' => {
          if self.in_list {
            // in a list act like a standard whitespace.
            if cur_token.get().is_some() {
              break
            } else {
              self.txt.next(); continue
            }
          } else {
            self.set_token_if_not(State::EOL, &cur_token);
            self.is_first_line = true;
            break
          }
        },
        '@'  => { self.set_token_if_not(State::At, &cur_token);  break },
        '$'  => if self.set_token_if_not(State::Dollar, &cur_token) { continue } else { break },
        '('  => {
          if self.set_token_if_not(State::StartList, &cur_token) {
            if self.in_list { return Err(LexerError::IllegalCharacter(ch)) }
            else { self.in_list = true; }
          }
          break
        },
        ')'  => {
          if self.set_token_if_not(State::EndList, &cur_token) {
            if !self.in_list { return Err(LexerError::IllegalCharacter(ch)) }
            else { self.in_list = false; }
          }
          break
        },
        '"'  => if self.set_token_if_not(State::Quote, &cur_token) { continue } else { break },
        ';'  => if self.set_token_if_not(State::Comment, &cur_token) { continue } else { break },
        '\\' => {
          try!(self.escape_seq().and_then(|c|Ok(self.push(State::CharData, &cur_token, &cur_string, c))));

          continue;
        },
        _ if !ch.is_control() && !ch.is_whitespace() => { self.push(State::CharData, &cur_token, &cur_string, ch); },
        _ => return Err(LexerError::UnrecognizedChar(ch)),
      }
    }

    // if the token is unset, then we are at end of stream, aka None
    match cur_token.get() {
      Some(State::Quote) => Err(LexerError::UnclosedQuotedString),
      None if self.in_list => Err(LexerError::UnclosedList),
      None => Ok(None),
      Some(s) => Token::from(s, cur_string.into_inner()),
    }
  }

  fn escape_seq(&mut self) -> LexerResult<char> {
    // escaped character, let's decode it.
    self.txt.next(); // consume the escape
    let ch = try!(self.peek().ok_or(LexerError::EOF));

    if (!ch.is_control()) {
      if (ch.is_numeric()) {
        // in this case it's an excaped octal: \DDD
        let d1 = try!(self.txt.next().ok_or(LexerError::EOF)); // gobble
        let d2 = try!(self.txt.next().ok_or(LexerError::EOF)); // gobble
        let d3 = try!(self.peek().ok_or(LexerError::EOF)); // peek b/c the push will advance

        // let ddd: [u8; 3] = [d1.unwrap() as u8, d2.unwrap() as u8, *d3.unwrap() as u8];
        // let ch: char = try!(u32::from_str_radix(&ddd.into(), 8)

        let ddd: String = try!(String::from_utf8(vec![d1 as u8, d2 as u8, d3 as u8]));
        let ch: char = try!(u32::from_str_radix(&ddd, 8)
        .or(Err(LexerError::BadEscapedData(ddd)))
        .and_then(|o|char::from_u32(o).ok_or(LexerError::UnrecognizedOctet(o))));
        //let ch: char = try!(char::from_digit(try!(u32::from_str_radix(&ddd as &str, 8)), 8).ok_or(Err(LexerError::BadEscapedData(ddd)))); // octal parsing

        return Ok(ch);
      } else {
        // this is an excaped char: \X
        return Ok(ch);
      }
    } else {
      return Err(LexerError::IllegalCharacter(ch));
    }

  }

  fn peek(&mut self) -> Option<char> {
    self.txt.peek().map(|c|*c)
  }

  /// set's the token if it's not set, if it is succesul it advances the txt iter
  fn set_token_if_not(&mut self, next_state: State, cur_token: &Cell<Option<State>>) -> bool {
    self.is_first_line = false;
    if cur_token.get().is_none() {
      cur_token.set(Some(next_state));
      self.txt.next(); // if we set a new state, it means we can consume the char
      true
    } else {
      false
    }
  }

  fn push(&mut self, next_state: State, cur_token: &Cell<Option<State>>, cell_string: &RefCell<Option<String>>, ch: char) {
    self.is_first_line = false;
    if cur_token.get().is_none() {
      cur_token.set(Some(next_state));
    }

    let mut cur_string = cell_string.borrow_mut();
    if cur_string.is_none() { *cur_string = Some(String::new()); }
    if let Some(s) = cur_string.as_mut() {
      s.push(ch);
    }

    self.txt.next();
  }
}

#[derive(Copy, Clone, PartialEq)]
pub enum State {
  Blank,             // only if the first part of the line
  StartList,         // (
  EndList,           // )
  CharData,          // [a-zA-Z, non-control utf8]+
  Comment,           // ;.*
  At,                // @
  Quote,             // ".*"
  Quoted,            // finish the quoted sequence
  Dollar,            // $
  EOL,               // \n or \r\n
}

#[derive(PartialEq, Debug, Clone)]
pub enum Token {
  Blank,             // only if the first part of the line
  StartList,         // (
  EndList,           // )
  CharData(String),  // [a-zA-Z, non-control utf8, ., -, 0-9]+
  At,                // @
  Quote(String),     // ".*"
  Include,           // $INCLUDE
  Origin,            // $ORIGIN
  EOL,               // \n or \r\n
}

impl Token {
  pub fn from(state: State, value: Option<String>) -> LexerResult<Option<Token>> {
    Ok(Some(match state {
      State::Blank => Token::Blank,
      State::StartList => Token::StartList,
      State::EndList => Token::EndList,
      State::CharData => Token::CharData(value.unwrap()),
      State::Comment => Token::EOL, // comments can't end a sequence, so must be EOF/EOL
      State::At => Token::At,
      State::Quote => return Err(LexerError::UnclosedQuotedString),
      State::Quoted => Token::Quote(value.unwrap_or_default()),
      State::Dollar => {
        let s = value.unwrap_or_default();
        if "INCLUDE".to_string() == s { Token::Include }
        else if "ORIGIN".to_string() == s { Token::Origin }
        else { return Err(LexerError::UnrecognizedDollar(s)) }
      },
      State::EOL => Token::EOL,
    }))
  }
}

#[cfg(test)]
mod lex_test {
  use ::error::*;
  use super::*;

  #[test]
  fn blank() {
    // first blank
    let mut lexer = Lexer::new("     dead beef");
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Blank);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("dead".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("beef".to_string()));

    // not the second blank
    let mut lexer = Lexer::new("dead beef");
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("dead".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("beef".to_string()));


    let mut lexer = Lexer::new("dead beef\r\n after");
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("dead".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("beef".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Blank);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("after".to_string()));

  }

  #[test]
  fn escape() {
    assert_eq!(Lexer::new("a\\A").next_token().unwrap().unwrap(), Token::CharData("aA".to_string()));
    assert_eq!(Lexer::new("a\\$").next_token().unwrap().unwrap(), Token::CharData("a$".to_string()));
    assert_eq!(Lexer::new("a\\077").next_token().unwrap().unwrap(), Token::CharData("a?".to_string()));
    assert!(Lexer::new("a\\").next_token().is_err());
    assert!(Lexer::new("a\\0").next_token().is_err());
    assert!(Lexer::new("a\\07").next_token().is_err());
  }

  #[test]
  fn quoted_txt() {
    assert_eq!(Lexer::new("\"Quoted\"").next_token().unwrap().unwrap(), Token::Quote("Quoted".to_string()));
    assert_eq!(Lexer::new("\";@$\"").next_token().unwrap().unwrap(), Token::Quote(";@$".to_string()));
    assert_eq!(Lexer::new("\"some \\A\"").next_token().unwrap().unwrap(), Token::Quote("some A".to_string()));

    let mut lexer = Lexer::new("\"multi\nline\ntext\"");

    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Quote("multi\nline\ntext".to_string()));
    assert_eq!(lexer.next_token().unwrap(), None);

    let mut lexer = Lexer::new("\"multi\r\nline\r\ntext\"\r\n");

    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Quote("multi\r\nline\r\ntext".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap(), None);

    assert!(Lexer::new("\"multi").next_token().is_err());
  }

  #[test]
  fn unicode() {
    assert_eq!(Lexer::new("♥").next_token().unwrap().unwrap(), Token::CharData("♥".to_string()));
  }

  // fun with tests!!! lots of options
  #[test]
  fn lex() {
    assert_eq!(Lexer::new(".").next_token().unwrap().unwrap(), Token::CharData(".".to_string()));
    assert_eq!(Lexer::new("            .").next_token().unwrap().unwrap(), Token::Blank);
    assert_eq!(Lexer::new("abc").next_token().unwrap().unwrap(), Token::CharData("abc".to_string()));
    assert_eq!(Lexer::new("abc.").next_token().unwrap().unwrap(), Token::CharData("abc.".to_string()));
    assert_eq!(Lexer::new(";abc").next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(Lexer::new(";;@$-\"").next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(Lexer::new("@").next_token().unwrap().unwrap(), Token::At);
    assert_eq!(Lexer::new("123").next_token().unwrap().unwrap(), Token::CharData("123".to_string()));
    assert_eq!(Lexer::new("$INCLUDE").next_token().unwrap().unwrap(), Token::Include);
    assert_eq!(Lexer::new("$ORIGIN").next_token().unwrap().unwrap(), Token::Origin);
    assert_eq!(Lexer::new("\n").next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(Lexer::new("\r\n").next_token().unwrap().unwrap(), Token::EOL);
  }

  #[test]
  fn list() {
    let mut lexer = Lexer::new("(");
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::StartList);
    assert!(lexer.next_token().is_err());

    assert!(Lexer::new(")").next_token().is_err());

    let mut lexer = Lexer::new("()");
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::StartList);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EndList);
    assert_eq!(lexer.next_token().unwrap(), None);

    let mut lexer = Lexer::new("(abc)");
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::StartList);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("abc".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EndList);
    assert_eq!(lexer.next_token().unwrap(), None);

    let mut lexer = Lexer::new("(\nabc\n)");
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::StartList);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("abc".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EndList);
    assert_eq!(lexer.next_token().unwrap(), None);

    let mut lexer = Lexer::new("(\nabc\nabc)");
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::StartList);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("abc".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("abc".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EndList);
    assert_eq!(lexer.next_token().unwrap(), None);


    let mut lexer = Lexer::new("(\n\"abc\"\n)");
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::StartList);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Quote("abc".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EndList);
    assert_eq!(lexer.next_token().unwrap(), None);
    let mut lexer = Lexer::new("(\n\"abc\";comment\n)");
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::StartList);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Quote("abc".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EndList);
    assert_eq!(lexer.next_token().unwrap(), None);
  }

  #[test]
  fn soa() {
    let mut lexer = Lexer::new("@   IN  SOA     VENERA      Action\\.domains (\n\
                                 20     ; SERIAL\n\
                                 7200   ; REFRESH\n\
                                 600    ; RETRY\n\
                                 3600000; EXPIRE\n\
                                 60)    ; MINIMUM\n\
\n\
        NS      A.ISI.EDU.\n\
        NS      VENERA\n\
        NS      VAXA\n\
        MX      10      VENERA\n\
        MX      20      VAXA\n\
\n\
A       A       26.3.0.103\n\
\n\
VENERA  A       10.1.0.52\n\
        A       128.9.0.32\n\
\n\
$INCLUDE <SUBSYS>ISI-MAILBOXES.TXT");

    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::At);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("IN".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("SOA".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("VENERA".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("Action.domains".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::StartList);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("20".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("7200".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("600".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("3600000".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("60".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EndList);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("NS".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("A.ISI.EDU.".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("NS".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("VENERA".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("NS".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("VAXA".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("MX".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("10".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("VENERA".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("MX".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("20".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("VAXA".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("A".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("A".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("26.3.0.103".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("VENERA".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("A".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("10.1.0.52".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("A".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("128.9.0.32".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Include);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("<SUBSYS>ISI-MAILBOXES.TXT".to_string()));
    assert!(lexer.next_token().unwrap().is_none());
  }
}
