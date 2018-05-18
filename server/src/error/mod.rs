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

mod config_error;
mod persistence_error;

pub use self::config_error::Error as ConfigError;
pub use self::persistence_error::Error as PersistenceError;

pub use self::config_error::ErrorKind as ConfigErrorKind;
pub use self::persistence_error::ErrorKind as PersistenceErrorKind;

pub use self::config_error::Result as ConfigResult;
pub use self::persistence_error::Result as PersistenceResult;
