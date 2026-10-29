//! Differential harness for SD-JWT (RFC 9901) verification.
//!
//! * [`jose`]: deterministic test keys, base64url and ES256 compact JWS.
//! * [`build`]: builder for Disclosures, Issuer-signed JWTs and KB-JWTs.
//! * [`reference`]: a verifier written from RFC 9901 sections 4, 7.1 and 7.3.
//! * [`cases`]: the hand-written corpus.

pub mod build;
pub mod cases;
pub mod jose;
pub mod reference;
