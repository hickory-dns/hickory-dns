use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum EncodeError {
  CharacterDataTooLong(usize),
  LabelBytesTooLong(usize),
  DomainNameTooLong(usize),
}

impl fmt::Display for EncodeError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      EncodeError::CharacterDataTooLong(length) => write!(f, "Char data exceeds 255: {}", length),
      EncodeError::LabelBytesTooLong(length) => write!(f, "Label bytes exceed 63: {}", length),
      EncodeError::DomainNameTooLong(length) => write!(f, "Name data exceed 255: {}", length),
    }
  }
}

impl Error for EncodeError {
  fn description(&self) -> &str {
    match *self {
      EncodeError::CharacterDataTooLong(..) => "Char data length exceeds 255",
      EncodeError::LabelBytesTooLong(..) => "Label bytes exceed 63",
      EncodeError::DomainNameTooLong(..) => "Name data exceed 255",
    }
  }

  fn cause(&self) -> Option<&Error> {
    match *self {
      _ => None,
    }
  }
}
