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

//! All defined errors for Trust-DNS

mod decode_error;
mod encode_error;
mod client_error;
mod lexer_error;
mod parse_error;

pub use self::decode_error::Error as DecodeError;
pub use self::encode_error::Error as EncodeError;
pub use self::client_error::Error as ClientError;
pub use self::lexer_error::Error as LexerError;
pub use self::parse_error::Error as ParseError;

pub use self::decode_error::ErrorKind as DecodeErrorKind;
pub use self::encode_error::ErrorKind as EncodeErrorKind;
pub use self::client_error::ErrorKind as ClientErrorKind;
pub use self::lexer_error::ErrorKind as LexerErrorKind;
pub use self::parse_error::ErrorKind as ParseErrorKind;

pub use self::decode_error::ChainErr as DecodeChainErr;
pub use self::encode_error::ChainErr as EncodeChainErr;
pub use self::client_error::ChainErr as ClientChainErr;
pub use self::lexer_error::ChainErr as LexerChainErr;
pub use self::parse_error::ChainErr as ParseChainErr;

pub type DecodeResult<T> = Result<T, DecodeError>;
pub type EncodeResult = Result<(), EncodeError>;
pub type ClientResult<T> = Result<T, ClientError>;
pub type LexerResult<T> = Result<T, LexerError>;
pub type ParseResult<T> = Result<T, ParseError>;
