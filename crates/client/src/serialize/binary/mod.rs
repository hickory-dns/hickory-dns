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

//! Binary serialization types

use crate::proto::serialize::binary;

#[deprecated(note = "use [`trust_dns_client::serialize::binary::StreamHandle`] instead")]
pub use self::binary::BinDecodable as BinSerializable;
pub use self::binary::BinDecodable;
pub use self::binary::BinDecoder;
pub use self::binary::BinEncodable;
pub use self::binary::BinEncoder;
pub use self::binary::EncodeMode;
