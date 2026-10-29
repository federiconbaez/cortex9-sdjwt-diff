//! Differential harness for SD-JWT (RFC 9901) verification.
//!
//! * [`jose`]: deterministic test keys, base64url and ES256 compact JWS.
//! * [`build`]: builder for Disclosures, Issuer-signed JWTs and KB-JWTs.

pub mod build;
pub mod jose;
