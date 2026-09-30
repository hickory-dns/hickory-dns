// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Domain name associated types, such as Name and Label.

mod label;
pub use label::{IntoLabel, Label, LabelCmp};

mod name;
pub use name::{IntoName, LabelIter, Name};

#[cfg(feature = "std")]
pub mod usage;
