mod client;
pub mod model;
mod record_locks;
mod txt;

pub use client::{CloudflareClient, CloudflareError};

#[cfg(test)]
mod tests;
