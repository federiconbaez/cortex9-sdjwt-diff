//! Builder for the corpus: Disclosures, Issuer-signed JWTs, SD-JWTs and KB-JWTs.

use crate::jose::{self, KeyId};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Fixed issuance time used across the corpus (seconds since the epoch).
pub const T0: u64 = 1_793_000_000;
/// Far-future expiry, so that wall-clock based libraries never see it expire.
pub const EXP: u64 = 4_102_444_800;
/// The "current time" handed to implementations that take it as a parameter.
pub const NOW: u64 = T0 + 30;
/// Key Binding freshness window of the verifier policy (seconds).
pub const KB_MAX_AGE: u64 = 300;
/// Allowed clock skew into the future for KB-JWT `iat` (seconds).
pub const KB_SKEW: u64 = 60;

pub const ISS: &str = "https://issuer.example";
pub const VCT: &str = "https://credentials.example/identity";
pub const AUD: &str = "https://verifier.example";
pub const NONCE: &str = "n-0S6_WzA2Mj";

/// A Disclosure as transmitted plus its SHA-256 digest (RFC 9901 4.2.3).
#[derive(Clone, Debug)]
pub struct Disc {
    pub enc: String,
    pub digest: String,
}

/// base64url SHA-256 over the US-ASCII bytes of `s`.
pub fn sha256_b64(s: &str) -> String {
    jose::b64(&Sha256::digest(s.as_bytes()))
}

/// Disclosure from the exact JSON text given, without re-serializing it.
pub fn disc_raw(json_text: &str) -> Disc {
    disc_enc(jose::b64(json_text.as_bytes()))
}

/// Disclosure from an already base64url-encoded string.
pub fn disc_enc(enc: String) -> Disc {
    let digest = sha256_b64(&enc);
    Disc { enc, digest }
}

/// Object-property Disclosure `[salt, name, value]` (RFC 9901 4.2.1).
pub fn disc_obj(salt: &str, name: &str, value: Value) -> Disc {
    disc_raw(&json!([salt, name, value]).to_string())
}

/// Array-element Disclosure `[salt, value]` (RFC 9901 4.2.2).
pub fn disc_arr(salt: &str, value: Value) -> Disc {
    disc_raw(&json!([salt, value]).to_string())
}

/// A digest that matches no Disclosure, usable as a decoy (RFC 9901 4.2.5).
pub fn decoy(tag: &str) -> String {
    sha256_b64(&format!("decoy-{tag}"))
}

/// Default Issuer-signed JWT header.
pub fn header() -> Value {
    json!({"alg": "ES256", "typ": "dc+sd-jwt"})
}

/// `<jwt>~<d1>~...~<dn>~` (RFC 9901 4).
pub fn sd_jwt(jwt: &str, discs: &[&Disc]) -> String {
    let mut s = format!("{jwt}~");
    for d in discs {
        s.push_str(&d.enc);
        s.push('~');
    }
    s
}

/// KB-JWT inputs; every field can be altered by a case.
#[derive(Clone, Debug)]
pub struct Kb {
    pub header: Value,
    pub payload: Value,
    pub key: KeyId,
    pub unsigned: bool,
}

impl Kb {
    /// A correct KB-JWT over `sd_jwt_str` (RFC 9901 4.3, 4.3.1).
    pub fn for_sd_jwt(sd_jwt_str: &str) -> Kb {
        Kb {
            header: json!({"alg": "ES256", "typ": "kb+jwt"}),
            payload: json!({
                "iat": T0,
                "aud": AUD,
                "nonce": NONCE,
                "sd_hash": sha256_b64(sd_jwt_str),
            }),
            key: KeyId::Holder,
            unsigned: false,
        }
    }

    pub fn sign(&self) -> String {
        if self.unsigned {
            jose::sign_none(&self.header, &self.payload)
        } else {
            jose::sign_es256(&self.header, &self.payload, self.key)
        }
    }
}

/// The three ordinary object-property Disclosures and one array Disclosure
/// that most cases start from.
pub struct World {
    pub given: Disc,
    pub family: Disc,
    pub street: Disc,
    pub nat_us: Disc,
}

impl Default for World {
    fn default() -> Self {
        World {
            given: disc_obj("c2FsdC1naXZlbi0wMDAx", "given_name", json!("Ana")),
            family: disc_obj("c2FsdC1mYW1pbHktMDAy", "family_name", json!("Pérez")),
            street: disc_obj(
                "c2FsdC1zdHJlZXQtMDAz",
                "street_address",
                json!("Calle Falsa 123"),
            ),
            nat_us: disc_arr("c2FsdC1uYXQtdXMtMDA0", json!("US")),
        }
    }
}

impl World {
    /// The base payload of the corpus. `cnf` adds the Holder key.
    pub fn payload(&self, cnf: bool) -> Value {
        let mut p = json!({
            "iss": ISS,
            "iat": T0,
            "exp": EXP,
            "vct": VCT,
            "_sd_alg": "sha-256",
            "_sd": [self.given.digest, self.family.digest],
            "address": {"_sd": [self.street.digest], "country": "AR"},
            "nationalities": [{"...": self.nat_us.digest}, "DE"],
        });
        if cnf {
            p["cnf"] = json!({"jwk": jose::public_jwk(KeyId::Holder)});
        }
        p
    }

    pub fn all(&self) -> Vec<&Disc> {
        vec![&self.given, &self.family, &self.street, &self.nat_us]
    }

    /// Processed payload expected when every Disclosure of the base is sent.
    pub fn processed_all(&self, cnf: bool) -> Value {
        let mut p = json!({
            "iss": ISS,
            "iat": T0,
            "exp": EXP,
            "vct": VCT,
            "given_name": "Ana",
            "family_name": "Pérez",
            "address": {"street_address": "Calle Falsa 123", "country": "AR"},
            "nationalities": ["US", "DE"],
        });
        if cnf {
            p["cnf"] = json!({"jwk": jose::public_jwk(KeyId::Holder)});
        }
        p
    }
}

pub fn issue(payload: &Value) -> String {
    jose::sign_es256(&header(), payload, KeyId::Issuer)
}
