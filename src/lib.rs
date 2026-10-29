//! Differential harness for SD-JWT (RFC 9901) verification.
//!
//! * [`jose`]: deterministic test keys, base64url and ES256 compact JWS.
//! * [`build`]: builder for Disclosures, Issuer-signed JWTs and KB-JWTs.
//! * [`reference`]: a verifier written from RFC 9901 sections 4, 7.1 and 7.3.
//! * [`cases`]: the hand-written corpus.
//! * [`adapters`]: the crates under test behind one interface.
//! * [`matrix`]: runs every case against every implementation.

pub mod adapters;
pub mod build;
pub mod cases;
pub mod jose;
pub mod matrix;
pub mod reference;
