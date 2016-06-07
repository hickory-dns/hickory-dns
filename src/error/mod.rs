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

#[macro_use]
mod base_error;
mod decode_error;
mod encode_error;
mod client_error;
mod lexer_error;
mod parse_error;
mod persistence_error;
mod config_error;

pub use self::base_error::ErrorLoc;
pub use self::decode_error::DecodeError;
pub use self::encode_error::EncodeError;
pub use self::client_error::ClientError;
pub use self::lexer_error::LexerError;
pub use self::parse_error::ParseError;
pub use self::persistence_error::PersistenceError;
pub use self::config_error::ConfigError;

pub type DecodeResult<T> = Result<T, DecodeError>;
pub type EncodeResult = Result<(), EncodeError>;
pub type ClientResult<T> = Result<T, ClientError>;
pub type LexerResult<T> = Result<T, LexerError>;
pub type ParseResult<T> = Result<T, ParseError>;
pub type PersistenceResult<T> = Result<T, PersistenceError>;
pub type ConfigResult<T> = Result<T, ConfigError>;
