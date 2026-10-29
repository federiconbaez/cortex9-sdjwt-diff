//! The crates under test behind one interface.
//!
//! Every adapter receives the same serialized presentation and policy. Where
//! a crate hands a step to its caller by design (JWS verification, the
//! choice of Holder key), the adapter supplies that step with the harness's
//! ES256 code and the affected cells are reported as `delegated`, not scored.

use crate::build::{AUD, KB_MAX_AGE, KB_SKEW, NONCE, NOW};
use crate::cases::Area;
use crate::jose::{self, KeyId};
use crate::reference::{self, Policy};
use serde_json::Value;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::str::FromStr;

/// Outcome of one implementation on one case.
#[derive(Clone, Debug, PartialEq)]
pub enum Verdict {
    /// Accepted; carries the processed payload when the crate exposes it.
    Accept(Option<Value>),
    Reject(String),
    /// The crate does not offer this part of the verification by design.
    Delegated(String),
    /// The crate cannot run this case at all (unsupported key type etc.).
    Unsupported(String),
    Panic(String),
}

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Accept(_) => "accept",
            Verdict::Reject(_) => "reject",
            Verdict::Delegated(_) => "delegated",
            Verdict::Unsupported(_) => "unsupported",
            Verdict::Panic(_) => "panic",
        }
    }
    pub fn detail(&self) -> String {
        match self {
            Verdict::Accept(_) => String::new(),
            Verdict::Reject(s)
            | Verdict::Delegated(s)
            | Verdict::Unsupported(s)
            | Verdict::Panic(s) => s.clone(),
        }
    }
}

pub trait Implementation {
    fn name(&self) -> &'static str;
    /// Whether `area` is handed to the caller by this crate.
    fn delegated(&self, area: Area, policy: Policy) -> Option<&'static str> {
        let _ = (area, policy);
        None
    }
    fn verify(&self, input: &str, policy: Policy) -> Verdict;
}

/// Run an adapter, turning panics into a verdict.
pub fn run(imp: &dyn Implementation, input: &str, policy: Policy, area: Area) -> Verdict {
    if let Some(why) = imp.delegated(area, policy) {
        return Verdict::Delegated(why.into());
    }
    match catch_unwind(AssertUnwindSafe(|| imp.verify(input, policy))) {
        Ok(v) => v,
        Err(e) => {
            let msg = e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "panic".into());
            Verdict::Panic(msg)
        }
    }
}

fn short(e: impl std::fmt::Display) -> String {
    let s = e.to_string().replace(['\n', '\r', ','], " ");
    s.chars().take(120).collect()
}

fn jwt_part(input: &str) -> &str {
    input.split('~').next().unwrap_or("")
}

fn unverified_payload(input: &str) -> Option<Value> {
    jose::decode_unverified(jwt_part(input))
        .ok()
        .map(|d| d.payload)
}

pub fn all() -> Vec<Box<dyn Implementation>> {
    vec![
        Box::new(Reference),
        Box::new(SdJwtPayload),
        Box::new(Affinidi),
        Box::new(BhSdJwt),
        Box::new(Sdjwt),
        Box::new(SdJwtRs),
    ]
}

// ------------------------------------------------------------- reference

pub struct Reference;

impl Implementation for Reference {
    fn name(&self) -> &'static str {
        "reference"
    }
    fn verify(&self, input: &str, policy: Policy) -> Verdict {
        match reference::verify(input, policy) {
            Ok(p) => Verdict::Accept(Some(p)),
            Err(e) => Verdict::Reject(short(e)),
        }
    }
}

// ------------------------------------------------- sd-jwt-payload 0.5.1

/// sd-jwt-payload parses and decodes; it does not verify JWS signatures nor
/// Key Binding JWTs. The adapter checks the Issuer signature with the
/// harness ES256 verifier before handing the token to the crate.
pub struct SdJwtPayload;

impl Implementation for SdJwtPayload {
    fn name(&self) -> &'static str {
        "sd-jwt-payload"
    }
    fn delegated(&self, area: Area, policy: Policy) -> Option<&'static str> {
        if policy == Policy::Kb {
            return Some("crate does not verify KB-JWTs");
        }
        (area == Area::IssuerSig).then_some("crate does not verify JWS")
    }
    fn verify(&self, input: &str, _policy: Policy) -> Verdict {
        use sd_jwt_payload::{SdJwt, Sha256Hasher};
        if let Err(e) = jose::verify_es256(jwt_part(input), &jose::verifying_key(KeyId::Issuer)) {
            return Verdict::Reject(format!("adapter JWS: {e}"));
        }
        let sd = match SdJwt::parse(input) {
            Ok(s) => s,
            Err(e) => return Verdict::Reject(short(e)),
        };
        match sd.into_disclosed_object(&Sha256Hasher::new()) {
            Ok(obj) => Verdict::Accept(Some(Value::Object(obj))),
            Err(e) => Verdict::Reject(short(e)),
        }
    }
}

// ------------------------------------------------ affinidi-sd-jwt 0.1.8

struct Es256Jwt(p256::ecdsa::VerifyingKey);

impl affinidi_sd_jwt::JwtVerifier for Es256Jwt {
    fn verify_jwt(&self, jws: &str) -> Result<Value, affinidi_sd_jwt::SdJwtError> {
        jose::verify_es256(jws, &self.0)
            .map(|d| d.payload)
            .map_err(affinidi_sd_jwt::SdJwtError::Verification)
    }
}

/// affinidi-sd-jwt takes the JWS verifiers from the caller (`JwtVerifier`),
/// including the Holder verifier, which its docs say must be built from
/// `cnf.jwk`. The adapter does exactly that with the harness ES256 code.
pub struct Affinidi;

impl Implementation for Affinidi {
    fn name(&self) -> &'static str {
        "affinidi-sd-jwt"
    }
    fn delegated(&self, area: Area, _policy: Policy) -> Option<&'static str> {
        match area {
            Area::IssuerSig | Area::KbSig => Some("JWS verification supplied by the caller"),
            _ => None,
        }
    }
    fn verify(&self, input: &str, policy: Policy) -> Verdict {
        use affinidi_sd_jwt::verifier::{verify, verify_with_kb_freshness, KbFreshness};
        use affinidi_sd_jwt::{SdJwt, Sha256Hasher, VerificationOptions};
        let hasher = Sha256Hasher;
        let sd = match SdJwt::parse(input, &hasher) {
            Ok(s) => s,
            Err(e) => return Verdict::Reject(short(e)),
        };
        let issuer = Es256Jwt(jose::verifying_key(KeyId::Issuer));
        let res = match policy {
            Policy::NoKb => {
                let opts = VerificationOptions {
                    verify_kb: false,
                    expected_audience: None,
                    expected_nonce: None,
                };
                verify(&sd, &issuer, &hasher, &opts, None)
            }
            Policy::Kb => {
                let holder = unverified_payload(input)
                    .and_then(|p| p.get("cnf").and_then(|c| c.get("jwk")).cloned())
                    .and_then(|j| jose::verifying_key_from_jwk(&j).ok())
                    .map(Es256Jwt);
                let opts = VerificationOptions {
                    verify_kb: true,
                    expected_audience: Some(AUD),
                    expected_nonce: Some(NONCE),
                };
                let fresh = KbFreshness {
                    now: NOW as i64,
                    max_age_secs: KB_MAX_AGE as i64,
                    max_future_skew_secs: KB_SKEW as i64,
                };
                verify_with_kb_freshness(
                    &sd,
                    &issuer,
                    &hasher,
                    &opts,
                    holder
                        .as_ref()
                        .map(|h| h as &dyn affinidi_sd_jwt::JwtVerifier),
                    &fresh,
                )
            }
        };
        match res {
            Ok(r) => Verdict::Accept(Some(r.claims)),
            Err(e) => Verdict::Reject(short(e)),
        }
    }
}

// ------------------------------------------------------ bh-sd-jwt 0.7.1

struct FixedIssuerKey;

#[derive(Debug)]
struct NeverFails;
impl std::fmt::Display for NeverFails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("never")
    }
}
impl bherror::BhError for NeverFails {}

impl bh_sd_jwt::IssuerPublicKeyLookup for FixedIssuerKey {
    type Err = NeverFails;
    async fn lookup(
        &self,
        _alleged_iss: Option<&str>,
        _header: &bh_sd_jwt::IssuerJwtHeader,
    ) -> Result<bh_jws_utils::JwkPublic, bherror::Error<Self::Err>> {
        Ok(jose::public_jwk(KeyId::Issuer)
            .as_object()
            .cloned()
            .unwrap_or_default())
    }
}

/// bh-sd-jwt verifies SD-JWT VC (typ dc+sd-jwt, vct). It takes the current
/// time as a parameter, so it is called with the corpus NOW.
pub struct BhSdJwt;

impl Implementation for BhSdJwt {
    fn name(&self) -> &'static str {
        "bh-sd-jwt"
    }
    fn verify(&self, input: &str, policy: Policy) -> Verdict {
        use bh_jws_utils::{Es256Verifier, SignatureVerifier, SigningAlgorithm};
        use bh_sd_jwt::verifier::{NoHolderBindingVerifier, Verifier};
        use bh_sd_jwt::{Hasher, HashingAlgorithm, KeyBindingChallenge, Sha256};
        let es = Es256Verifier;
        let get_hasher = |alg: HashingAlgorithm| -> Option<Box<dyn Hasher>> {
            (alg == HashingAlgorithm::Sha256).then(|| Box::new(Sha256) as Box<dyn Hasher>)
        };
        let get_sig = |alg: SigningAlgorithm| -> Option<&dyn SignatureVerifier> {
            (alg == SigningAlgorithm::Es256).then_some(&es as &dyn SignatureVerifier)
        };
        let res = match policy {
            Policy::NoKb => {
                let sd = match bh_sd_jwt::SdJwt::from_str(input) {
                    Ok(s) => s,
                    Err(e) => return Verdict::Reject(short(e)),
                };
                futures::executor::block_on(NoHolderBindingVerifier.verify(
                    sd,
                    &FixedIssuerKey,
                    NOW,
                    get_hasher,
                    get_sig,
                ))
                .map_err(short)
            }
            Policy::Kb => {
                let sd = match bh_sd_jwt::SdJwtKB::from_str(input) {
                    Ok(s) => s,
                    Err(e) => return Verdict::Reject(short(e)),
                };
                let v = Verifier::from_challenge(KeyBindingChallenge {
                    aud: AUD.into(),
                    nonce: NONCE.into(),
                });
                futures::executor::block_on(v.verify(sd, &FixedIssuerKey, NOW, get_hasher, get_sig))
                    .map_err(short)
            }
        };
        match res {
            Ok((claims, _, _)) => Verdict::Accept(serde_json::to_value(claims).ok()),
            Err(e) => Verdict::Reject(e),
        }
    }
}

// ---------------------------------------------------------- sdjwt 0.8.1

/// sdjwt verifies the Issuer JWS itself (ES256 via PEM). Its Key Binding
/// path only accepts RSA `cnf` keys, so KB-policy cases with the corpus'
/// P-256 Holder key are reported as unsupported.
pub struct Sdjwt;

impl Implementation for Sdjwt {
    fn name(&self) -> &'static str {
        "sdjwt"
    }
    fn verify(&self, input: &str, policy: Policy) -> Verdict {
        use sdjwt::{Algorithm, KeyForDecoding, Validation, Verifier};
        if policy == Policy::Kb {
            return Verdict::Unsupported("KB path only accepts RSA cnf keys".into());
        }
        let key = match KeyForDecoding::from_ec_pem(jose::public_pem(KeyId::Issuer).as_bytes()) {
            Ok(k) => k,
            Err(e) => return Verdict::Reject(format!("key: {}", short(e))),
        };
        let validation = Validation::new(Algorithm::ES256);
        match Verifier::verify(input, &key, &validation, &None) {
            Ok((_, claims)) => Verdict::Accept(Some(claims)),
            Err(e) => Verdict::Reject(short(e)),
        }
    }
}

// ------------------------------------------------------- sd-jwt-rs 0.7.1

/// sd-jwt-rs (OpenWallet Foundation) verifies the Issuer JWS through
/// jsonwebtoken with a key callback, and Key Binding when both `aud` and
/// `nonce` are given.
pub struct SdJwtRs;

impl Implementation for SdJwtRs {
    fn name(&self) -> &'static str {
        "sd-jwt-rs"
    }
    fn verify(&self, input: &str, policy: Policy) -> Verdict {
        use jsonwebtoken9::DecodingKey;
        use sd_jwt_rs::{SDJWTSerializationFormat, SDJWTVerifier};
        let pem = jose::public_pem(KeyId::Issuer);
        let cb = Box::new(move |_iss: &str, _h: &jsonwebtoken9::Header| {
            DecodingKey::from_ec_pem(pem.as_bytes()).expect("issuer pem")
        });
        let (aud, nonce) = match policy {
            Policy::NoKb => (None, None),
            Policy::Kb => (Some(AUD.to_string()), Some(NONCE.to_string())),
        };
        match SDJWTVerifier::new(
            input.to_string(),
            cb,
            aud,
            nonce,
            SDJWTSerializationFormat::Compact,
        ) {
            Ok(v) => Verdict::Accept(Some(v.verified_claims)),
            Err(e) => Verdict::Reject(short(e)),
        }
    }
}
