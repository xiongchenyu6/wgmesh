//! Shared primitives between the wgmesh coordinator and agent.
//!
//! - [`api`]: wire types (RegisterRequest, PeersResponse, ...).
//! - [`sig`]: ed25519 request signing (canonical form + sign/verify).
//! - [`keyderive`]: turns an OpenSSH ed25519 host key into the X25519 keypair
//!   used by WireGuard.
//! - [`stun`]: minimal RFC 5389 STUN binding-request client.

pub mod api;
pub mod keyderive;
pub mod sig;
pub mod stun;
