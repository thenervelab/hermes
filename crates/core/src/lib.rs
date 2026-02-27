//! # hippius-hermes-core
//!
//! Bittensor cross-subnet Machine-to-Machine (M2M) communication protocol over
//! [Iroh](https://iroh.computer) QUIC transport and the Hippius Sync-Engine.
//!
//! This crate provides the core Rust implementation: Iroh P2P networking, connection
//! pooling, offline message buffering, and HTTP integration with the Hippius Sync-Engine
//! for large file transfers. For Python bindings see the companion `hippius-hermes-python`
//! crate.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use hippius_hermes_core::{Client, Config};
//!
//! # #[tokio::main]
//! # async fn main() -> hippius_hermes_core::Result<()> {
//! let config = Config::from_file("hermes_config.json")?;
//! let client = Client::new(config).await?;
//! client.spawn_retry_worker();
//! # Ok(())
//! # }
//! ```

pub mod acl;
pub mod client;
pub mod config;
pub mod crypto;
pub mod error;
pub mod identity;
pub mod network;
pub mod store;

pub use acl::{Acl, AclVerdict};
pub use client::Client;
pub use config::Config;
pub use error::{HermesError, Result};
