use std::error::Error;
use std::io;
use std::fmt;

#[derive(Debug)]
pub enum ClientError {
  DecodeError(super::DecodeError),
  EncodeError(super::EncodeError),
  IoError(io::Error),
  NotAllBytesSent{ sent: usize, expect: usize},
  IncorrectMessageId{ got: u16, expect: u16},
}

impl fmt::Display for ClientError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      ClientError::DecodeError(ref err) => err.fmt(f),
      ClientError::EncodeError(ref err) => err.fmt(f),
      ClientError::IoError(ref err) => err.fmt(f),
      ClientError::NotAllBytesSent{ sent, expect } => write!(f, "Not all bytes were sent: {}, expected: {}", sent, expect),
      ClientError::IncorrectMessageId { got, expect } => write!(f, "IncorrectMessageId got: {}, expected: {}", got, expect),
    }
  }
}

impl Error for ClientError {
  fn description(&self) -> &str {
    match *self {
      ClientError::DecodeError(ref err) => err.description(),
      ClientError::EncodeError(ref err) => err.description(),
      ClientError::IoError(ref err) => err.description(),
      ClientError::NotAllBytesSent{ .. } => "Not all bytes were sent to server",
      ClientError::IncorrectMessageId { .. } => "IncorrectMessageId recieved",
    }
  }

  fn cause(&self) -> Option<&Error> {
    match *self {
      ClientError::DecodeError(ref err) => Some(err),
      ClientError::EncodeError(ref err) => Some(err),
      ClientError::IoError(ref err) => Some(err),
      _ => None,
    }
  }
}

impl From<super::DecodeError> for ClientError {
    fn from(err: super::DecodeError) -> Self {
        ClientError::DecodeError(err)
    }
}

impl From<super::EncodeError> for ClientError {
    fn from(err: super::EncodeError) -> Self {
        ClientError::EncodeError(err)
    }
}

impl From<io::Error> for ClientError {
    fn from(err: io::Error) -> Self {
        ClientError::IoError(err)
    }
}
