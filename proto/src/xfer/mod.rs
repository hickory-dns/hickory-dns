//! DNS high level tranisit implimentations.

use std::fmt::Debug;

pub mod dns_handle;
pub mod dns_future;
pub mod retry_dns_handle;
#[cfg(feature = "dnssec")]
pub mod secure_dns_handle;

/// Ignores the result of a send operation and logs and ignores errors
fn ignore_send<M, E: Debug>(result: Result<M, E>) {
    if let Err(error) = result {
        warn!("error notifying wait, possible future leak: {:?}", error);
    }
}
