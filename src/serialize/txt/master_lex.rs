use std::cell::{Cell,RefCell};
use std::iter::Peekable;
use std::str::Chars;
use std::char;

use ::error::{LexerResult,LexerError};

pub struct Lexer<'a> {
  txt: Peekable<Chars<'a>>,
  is_first_line: bool,
}

impl<'a> Lexer<'a> {
  pub fn new(txt: &str) -> Lexer {
    Self::with_chars(txt.chars())
  }

  pub fn with_chars(chars: Chars) -> Lexer {
    Lexer { txt: chars.peekable(), is_first_line: true }
  }

  pub fn next_token(&mut self) -> LexerResult<Option<Token>> {
    let mut cur_token: Cell<Option<State>> = Cell::new(None);
    let mut cur_string: RefCell<Option<String>> = RefCell::new(None);

    //while let Some(ch) = self.txt.by_ref().peekable().peek() {
    'out: for i in 0..4096 { // max chars in a single lex, helps with issues in the lexer...
      assert!(i < 4095);     // keeps the bounds of the loop defined (nothing lasts forever)

      // This is to get around mutibility rules such that we can peek at the iter without moving next...
      let ch: char = {
         //let mut peekable = self.txt.by_ref().peekable();
         let next_ch: Option<&char> = self.txt.peek();
         if next_ch.is_some() { *next_ch.unwrap() } else { break 'out }
      };

      if let Some(t) = cur_token.get() {
        if let State::Comment = t {
          let ch = self.txt.next();
          if ch.is_none() || ch.unwrap() == '\n' { return Ok(Some(Token::EOL)); } // special case for comments
          else { continue 'out } // gobbling rest of line for comment
        } else if let State::Quote = t {
          match ch {
            '"' => { cur_token.set(Some(State::Quoted)) ; break 'out },
            '/' => try!(self.escape_seq().and_then(|ch|Ok(self.push(State::Quote, &cur_token, &cur_string, ch)))),
            _ => self.push(State::Quote, &cur_token, &cur_string, ch),
          }

          continue 'out; // skipping rest of processing for quoted strings.
        }
      }
      match ch {
        ' '|'\t' => {
          if self.is_first_line { self.set_token_if_not(State::Blank, &cur_token); break } // need the first blank on a line
          if cur_token.get().is_some() { break } else { self.txt.next(); continue }  // gobble all whitespace
        },
        'a' ... 'z' | 'A' ... 'Z' | '-'                     => { self.push(State::CharData, &cur_token, &cur_string, ch); },
        '0' ... '9'                                         => { self.push(State::Number, &cur_token, &cur_string, ch); },
        '\u{E000}' ... '\u{10FFFF}' if ch.is_alphanumeric() => { self.push(State::CharData, &cur_token, &cur_string, ch); },
        '\r' => if cur_token.get().is_some() { break } else { self.txt.next(); continue },
        '\n' => { self.set_token_if_not(State::EOL, &cur_token); self.is_first_line = true; break },
        '@'  => { self.set_token_if_not(State::At, &cur_token);          break },
        '$'  => if self.set_token_if_not(State::Dollar, &cur_token) { continue } else { break },
        '('  => { self.set_token_if_not(State::LeftParen, &cur_token);   break },
        ')'  => { self.set_token_if_not(State::RightParen, &cur_token);  break },
        '"'  => if self.set_token_if_not(State::Quote, &cur_token) { continue } else { break },
        ';'  => if self.set_token_if_not(State::Comment, &cur_token) { continue } else { break },
        '.'  => { self.set_token_if_not(State::Dot, &cur_token) ; break },
        '\\' => {
          try!(self.escape_seq().and_then(|c|Ok(self.push(State::CharData, &cur_token, &cur_string, c))));

          continue;
        },
         _ => return Err(LexerError::UnrecognizedChar(ch)),
      }
    }

    // if the token is unset, then we are at end of stream, aka None
    if cur_token.get().is_none() { return Ok(None); }
    Token::from(cur_token.get().unwrap(), cur_string.into_inner())
  }

  fn escape_seq(&mut self) -> LexerResult<char> {
    // escaped character, let's decode it.
    self.txt.next(); // consume the escape
    let ch = {
      let ch_opt = self.txt.peek(); // the next character
      if ch_opt.is_none() { return Err(LexerError::EOF) }
      *ch_opt.unwrap()
    };

    if (!ch.is_control()) {
      if (ch.is_numeric()) {
        // in this case it's an excaped octal: \DDD
        let d1 = self.txt.next(); // gobble
        let d2 = self.txt.next(); // gobble
        let d3 = try!(self.peek()); // peek b/c the push will advance

        if d2.is_none() { return Err(LexerError::EOF) }

        // let ddd: [u8; 3] = [d1.unwrap() as u8, d2.unwrap() as u8, *d3.unwrap() as u8];
        // let ch: char = try!(u32::from_str_radix(&ddd.into(), 8)

        let ddd: String = try!(String::from_utf8(vec![d1.unwrap() as u8, d2.unwrap() as u8, d3 as u8]));
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

  fn peek(&mut self) -> LexerResult<char> {
    let ch_opt = self.txt.peek(); // the next character
    if ch_opt.is_none() { return Err(LexerError::EOF) }
    Ok(*ch_opt.unwrap())
  }

  /// set's the token if it's not set, if it is succesul it advances the txt iter
  fn set_token_if_not(&mut self, next_state: State, cur_token: &Cell<Option<State>>) -> bool {
    self.is_first_line = false;
    if cur_token.get().is_none() {
      cur_token.set(Some(next_state));
      self.txt.next();
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
  Dot,               // .
  LeftParen,         // (
  RightParen,        // )
  CharData,          // [a-zA-Z, non-control utf8]+
  Comment,           // ;.*
  At,                // @
  Number,            // [0-9]+
  Quote,             // ".*"
  Quoted,            // finish the quoted sequence
  Dollar,            // $
  EOL,               // \n or \r\n
}

#[derive(PartialEq, Debug)]
pub enum Token {
  Blank,             // only if the first part of the line
  Dot,               // .
  LeftParen,         // (
  RightParen,        // )
  CharData(String),  // [a-zA-Z, non-control utf8]+
  At,                // @
  Number(i32),       // [0-9]+
  Quote(String),     // ".*"
  Dollar(String),    // $
  EOL,               // \n or \r\n
}

impl Token {
  pub fn from(state: State, value: Option<String>) -> LexerResult<Option<Token>> {
    Ok(Some(match state {
      State::Blank => Token::Blank,
      State::Dot => Token::Dot,
      State::LeftParen => Token::LeftParen,
      State::RightParen => Token::RightParen,
      State::CharData => Token::CharData(value.unwrap()),
      State::Comment => Token::EOL, // comments can't end a sequence, so must be EOF/EOL
      State::At => Token::At,
      State::Number => Token::Number(value.unwrap().parse().unwrap()),
      State::Quote => return Err(LexerError::UnclosedQuotedString),
      State::Quoted => Token::Quote(value.unwrap_or_default()),
      State::Dollar => Token::Dollar(value.unwrap_or_default()),
      State::EOL => Token::EOL,
    }))
  }
}

#[cfg(test)]
mod lex_test {
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

  // fun with tests!!! lots of options
  #[test]
  fn lex() {
    assert_eq!(Lexer::new(".").next_token().unwrap().unwrap(), Token::Dot);
    assert_eq!(Lexer::new("            .").next_token().unwrap().unwrap(), Token::Blank);
    assert_eq!(Lexer::new("(").next_token().unwrap().unwrap(), Token::LeftParen);
    assert_eq!(Lexer::new(")").next_token().unwrap().unwrap(), Token::RightParen);
    assert_eq!(Lexer::new("abc").next_token().unwrap().unwrap(), Token::CharData("abc".to_string()));
    assert_eq!(Lexer::new("abc.").next_token().unwrap().unwrap(), Token::CharData("abc".to_string()));
    assert_eq!(Lexer::new("a\\A").next_token().unwrap().unwrap(), Token::CharData("aA".to_string()));
    assert_eq!(Lexer::new("a\\$").next_token().unwrap().unwrap(), Token::CharData("a$".to_string()));
    assert_eq!(Lexer::new("a\\077").next_token().unwrap().unwrap(), Token::CharData("a?".to_string()));
    assert_eq!(Lexer::new(";abc").next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(Lexer::new(";;@$-\"").next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(Lexer::new("@").next_token().unwrap().unwrap(), Token::At);
    assert_eq!(Lexer::new("123").next_token().unwrap().unwrap(), Token::Number(123));
    assert_eq!(Lexer::new("\"Quoted\"").next_token().unwrap().unwrap(), Token::Quote("Quoted".to_string()));
    assert_eq!(Lexer::new("\";@$\"").next_token().unwrap().unwrap(), Token::Quote(";@$".to_string()));
    assert_eq!(Lexer::new("$Bill").next_token().unwrap().unwrap(), Token::Dollar("Bill".to_string()));
    assert_eq!(Lexer::new("$$Bill").next_token().unwrap().unwrap(), Token::Dollar("".to_string()));
    assert_eq!(Lexer::new("\n").next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(Lexer::new("\r\n").next_token().unwrap().unwrap(), Token::EOL);
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
$INCLUDE \\<SUBSYS\\>ISI-MAILBOXES.TXT");

    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::At);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("IN".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("SOA".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("VENERA".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("Action.domains".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::LeftParen);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Number(20));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Number(7200));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Number(600));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Number(3600000));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Number(60));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::RightParen);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("NS".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("A".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Dot);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("ISI".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Dot);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("EDU".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Dot);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("NS".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("VENERA".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("NS".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("VAXA".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("MX".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Number(10));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("VENERA".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("MX".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Number(20));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("VAXA".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("A".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("A".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Number(26));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Dot);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Number(3));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Dot);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Number(0));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Dot);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Number(103));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("VENERA".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("A".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Number(10));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Dot);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Number(1));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Dot);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Number(0));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Dot);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Number(52));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("A".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Number(128));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Dot);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Number(9));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Dot);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Number(0));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Dot);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Number(32));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::EOL);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Dollar("INCLUDE".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("<SUBSYS>ISI-MAILBOXES".to_string()));
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::Dot);
    assert_eq!(lexer.next_token().unwrap().unwrap(), Token::CharData("TXT".to_string()));
    assert!(lexer.next_token().unwrap().is_none());
  }
}
