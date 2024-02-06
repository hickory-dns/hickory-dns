use std::sync::atomic::{self, AtomicUsize};

pub use crate::client::Client;
pub use crate::domain::Domain;
pub use crate::name_server::NameServer;
pub use crate::recursive_resolver::RecursiveResolver;

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = core::result::Result<T, Error>;

const CHMOD_RW_EVERYONE: &str = "666";

mod client;
pub mod container;
mod domain;
mod name_server;
pub mod record;
mod recursive_resolver;

fn nameserver_count() -> usize {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    COUNT.fetch_add(1, atomic::Ordering::Relaxed)
}
