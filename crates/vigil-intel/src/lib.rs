//! Vigil threat intelligence (SPEC §13).
//!
//! - [`DnsCache`]: domain ↔ IP mapping built from observed DNS answers, so
//!   connections can be attributed to a domain and `dns_before` is known.
//! - [`Enricher`]: the pipeline's normalizer stage that maintains the cache
//!   and fills in `NetConnect::{domain, dns_before}`.

pub mod dns_cache;
pub mod enrich;

pub use dns_cache::DnsCache;
pub use enrich::Enricher;
