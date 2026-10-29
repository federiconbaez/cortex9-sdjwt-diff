//! Deterministic keys, base64url and ES256 compact JWS.
//!
//! The private scalars below are fixed test values chosen for this harness.
//! They protect nothing and exist only so that every run produces the same
//! corpus.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::EncodePublicKey;
use serde_json::Value;
use sha2::Sha256;

/// Which deterministic key to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyId {
    Issuer,
    Holder,
    Attacker,
}

fn scalar(id: KeyId) -> [u8; 32] {
    let b = match id {
        KeyId::Issuer => 0x11,
        KeyId::Holder => 0x22,
        KeyId::Attacker => 0x33,
    };
    [b; 32]
}

pub fn signing_key(id: KeyId) -> SigningKey {
    SigningKey::from_bytes(&scalar(id).into()).expect("fixed scalar is a valid P-256 key")
}

pub fn verifying_key(id: KeyId) -> VerifyingKey {
    *signing_key(id).verifying_key()
}

/// Public JWK (`kty`, `crv`, `x`, `y`) as a JSON value.
pub fn public_jwk(id: KeyId) -> Value {
    let pk = p256::PublicKey::from(verifying_key(id));
    serde_json::from_str(&pk.to_jwk_string()).expect("jwk json")
}

/// SPKI PEM of the public key ("BEGIN PUBLIC KEY").
pub fn public_pem(id: KeyId) -> String {
    let pk = p256::PublicKey::from(verifying_key(id));
    pk.to_public_key_pem(Default::default()).expect("pem")
}

pub fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

/// Compact JWS over `header` and `payload` serialized with serde_json.
pub fn sign_es256(header: &Value, payload: &Value, key: KeyId) -> String {
    sign_es256_raw(
        &b64(header.to_string().as_bytes()),
        &b64(payload.to_string().as_bytes()),
        key,
    )
}

/// Compact JWS over already-encoded header and payload segments.
pub fn sign_es256_raw(h: &str, p: &str, key: KeyId) -> String {
    let input = format!("{h}.{p}");
    let sig: Signature = signing_key(key).sign(input.as_bytes());
    format!("{input}.{}", b64(&sig.to_bytes()))
}

/// JWS with `alg: HS256`, keyed with the given secret bytes.
pub fn sign_hs256(header: &Value, payload: &Value, secret: &[u8]) -> String {
    let input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(payload.to_string().as_bytes())
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(input.as_bytes());
    format!("{input}.{}", b64(&mac.finalize().into_bytes()))
}

/// Unsecured JWS (`alg: none`, empty signature).
pub fn sign_none(header: &Value, payload: &Value) -> String {
    format!(
        "{}.{}.",
        b64(header.to_string().as_bytes()),
        b64(payload.to_string().as_bytes())
    )
}

/// Decoded parts of a compact JWS, without verification.
pub struct Decoded {
    pub header: Value,
    pub payload: Value,
}

pub fn decode_unverified(jws: &str) -> Result<Decoded, String> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err("JWS must have three segments".into());
    }
    let header = b64_decode(parts[0]).ok_or("header is not base64url")?;
    let payload = b64_decode(parts[1]).ok_or("payload is not base64url")?;
    let header: Value = serde_json::from_slice(&header).map_err(|e| e.to_string())?;
    let payload: Value = serde_json::from_slice(&payload).map_err(|e| e.to_string())?;
    if !header.is_object() || !payload.is_object() {
        return Err("header and payload must be JSON objects".into());
    }
    Ok(Decoded { header, payload })
}

/// Verify an ES256 compact JWS against `key`. Only `alg: ES256` is accepted.
pub fn verify_es256(jws: &str, key: &VerifyingKey) -> Result<Decoded, String> {
    let d = decode_unverified(jws)?;
    if d.header.get("alg").and_then(Value::as_str) != Some("ES256") {
        return Err("alg is not ES256".into());
    }
    let (input, sig) = jws.rsplit_once('.').ok_or("no signature")?;
    let sig = b64_decode(sig).ok_or("signature is not base64url")?;
    let sig = Signature::from_slice(&sig).map_err(|_| "bad signature length")?;
    key.verify(input.as_bytes(), &sig)
        .map_err(|_| "signature does not verify".to_string())?;
    Ok(d)
}

/// Parse a public P-256 JWK value.
pub fn verifying_key_from_jwk(jwk: &Value) -> Result<VerifyingKey, String> {
    let pk = p256::PublicKey::from_jwk_str(&jwk.to_string()).map_err(|e| e.to_string())?;
    Ok(VerifyingKey::from(pk))
}
