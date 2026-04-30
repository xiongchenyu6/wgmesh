//! wgmesh node agent. Reconciles `wg0` against the coordinator's view, with
//! a per-peer probe state machine that promotes peers to direct connections
//! when handshakes succeed and demotes them to relay when they don't.

pub mod config;
pub mod coord_client;
pub mod lan;
pub mod probe;
pub mod run;

pub use config::AgentConfig;
pub use run::run;
