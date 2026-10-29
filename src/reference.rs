//! Reference verifier written from RFC 9901 sections 4, 4.3, 7.1 and 7.3.
//!
//! Policy choices that the RFC leaves to the application are fixed here and
//! listed in PREREGISTRO.md: ES256 only for both the Issuer and the KB-JWT,
//! `sha-256` as the only accepted `_sd_alg`, the Issuer key is known out of
//! band, and the KB-JWT `iat` must lie in `[NOW - 300, NOW + 60]`.

use crate::build::{self, AUD, KB_MAX_AGE, KB_SKEW, NONCE, NOW};
use crate::jose::{self, KeyId};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};

/// Verifier policy for one case (RFC 9901 7.3 step 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Policy {
    /// The Verifier expects an SD-JWT without Key Binding.
    NoKb,
    /// The Verifier requires an SD-JWT+KB with `aud` = AUD and `nonce` = NONCE.
    Kb,
}

impl Policy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Policy::NoKb => "sd-jwt",
            Policy::Kb => "sd-jwt+kb",
        }
    }
}

struct Ctx {
    by_digest: HashMap<String, (usize, Vec<Value>)>,
    seen: HashSet<String>,
    used: HashSet<usize>,
}

/// Verify `input` under `policy`. Returns the Processed SD-JWT Payload.
pub fn verify(input: &str, policy: Policy) -> Result<Value, String> {
    // RFC 9901 4: <JWT>~<D.1>~...~<D.N>~[<KB-JWT>]
    let parts: Vec<&str> = input.split('~').collect();
    if parts.len() < 2 {
        return Err("no tilde separator".into());
    }
    let jwt = parts[0];
    let last = parts[parts.len() - 1];
    let discs = &parts[1..parts.len() - 1];
    match policy {
        Policy::NoKb if !last.is_empty() => {
            return Err("expected SD-JWT but final component is not empty".into())
        }
        Policy::Kb if last.is_empty() => return Err("Key Binding required but absent".into()),
        _ => {}
    }

    // 7.1 step 2: Issuer-signed JWT.
    let issuer = jose::verify_es256(jwt, &jose::verifying_key(KeyId::Issuer))?;
    let mut payload = issuer.payload;
    match payload.get("_sd_alg") {
        None => {}
        Some(Value::String(s)) if s == "sha-256" => {}
        Some(other) => return Err(format!("_sd_alg not accepted: {other}")),
    }

    // 7.1 step 3a: digests over the Disclosures as transmitted.
    let mut ctx = Ctx {
        by_digest: HashMap::new(),
        seen: HashSet::new(),
        used: HashSet::new(),
    };
    for (i, d) in discs.iter().enumerate() {
        if d.is_empty() {
            return Err("empty Disclosure".into());
        }
        let raw = jose::b64_decode(d).ok_or("Disclosure is not base64url")?;
        let v: Value = serde_json::from_slice(&raw).map_err(|_| "Disclosure is not JSON")?;
        let arr = match v {
            Value::Array(a) => a,
            _ => return Err("Disclosure is not a JSON array".into()),
        };
        if ctx
            .by_digest
            .insert(build::sha256_b64(d), (i, arr))
            .is_some()
        {
            return Err("same Disclosure sent more than once".into());
        }
    }

    // 7.1 steps 3b-3e and 4.
    let obj = payload.as_object_mut().ok_or("payload is not an object")?;
    let sd_alg = obj.remove("_sd_alg"); // step 3f
    let processed = process_object(std::mem::take(obj), &mut ctx)?;
    let _ = sd_alg;
    let processed = Value::Object(processed);

    // 7.1 step 5.
    if ctx.used.len() != discs.len() {
        return Err("Disclosure not referenced by any digest".into());
    }

    // 7.1 step 6: validity claims of the processed payload.
    if let Some(exp) = processed.get("exp") {
        let exp = exp.as_u64().ok_or("exp is not a number")?;
        if NOW >= exp {
            return Err("expired".into());
        }
    }
    if let Some(nbf) = processed.get("nbf") {
        let nbf = nbf.as_u64().ok_or("nbf is not a number")?;
        if NOW < nbf {
            return Err("not yet valid".into());
        }
    }

    if policy == Policy::Kb {
        verify_kb(input, last, &processed)?;
    }
    Ok(processed)
}

fn verify_kb(input: &str, kb: &str, processed: &Value) -> Result<(), String> {
    // 7.3 step 5.
    let jwk = processed
        .get("cnf")
        .and_then(|c| c.get("jwk"))
        .ok_or("no cnf.jwk for Key Binding")?;
    let holder = jose::verifying_key_from_jwk(jwk)?;
    let d = jose::verify_es256(kb, &holder)?; // b, c
    if d.header.get("typ").and_then(Value::as_str) != Some("kb+jwt") {
        return Err("KB-JWT typ is not kb+jwt".into()); // d
    }
    let p = &d.payload;
    let iat = p
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or("KB-JWT iat missing")?; // e
    if iat + KB_MAX_AGE < NOW || iat > NOW + KB_SKEW {
        return Err("KB-JWT iat outside the acceptance window".into());
    }
    if p.get("aud").and_then(Value::as_str) != Some(AUD) {
        return Err("KB-JWT aud mismatch".into()); // f
    }
    if p.get("nonce").and_then(Value::as_str) != Some(NONCE) {
        return Err("KB-JWT nonce mismatch".into());
    }
    let presented = &input[..input.len() - kb.len()]; // up to and including the last '~'
    if p.get("sd_hash").and_then(Value::as_str) != Some(&build::sha256_b64(presented)) {
        return Err("KB-JWT sd_hash mismatch".into()); // g
    }
    Ok(())
}

fn see(ctx: &mut Ctx, digest: &str) -> Result<(), String> {
    if !ctx.seen.insert(digest.to_string()) {
        return Err(format!("digest {digest} encountered more than once"));
    }
    Ok(())
}

fn process_value(v: Value, ctx: &mut Ctx) -> Result<Value, String> {
    match v {
        Value::Object(o) => Ok(Value::Object(process_object(o, ctx)?)),
        Value::Array(a) => process_array(a, ctx),
        other => Ok(other),
    }
}

fn process_object(mut o: Map<String, Value>, ctx: &mut Ctx) -> Result<Map<String, Value>, String> {
    let sd = o.remove("_sd");
    let mut out = Map::new();
    for (k, v) in o {
        out.insert(k, process_value(v, ctx)?);
    }
    let Some(sd) = sd else { return Ok(out) };
    let list = sd.as_array().ok_or("_sd is not an array")?;
    for d in list {
        let d = d.as_str().ok_or("_sd element is not a string")?;
        see(ctx, d)?;
        let Some((idx, arr)) = ctx.by_digest.get(d).cloned() else {
            continue; // decoy or undisclosed
        };
        if arr.len() != 3 {
            return Err("object Disclosure is not [salt, name, value]".into());
        }
        if !arr[0].is_string() {
            return Err("salt is not a string".into());
        }
        let name = arr[1].as_str().ok_or("claim name is not a string")?;
        if name == "_sd" || name == "..." {
            return Err(format!("forbidden claim name {name}"));
        }
        if out.contains_key(name) {
            return Err(format!("claim {name} already exists at this level"));
        }
        ctx.used.insert(idx);
        let value = process_value(arr[2].clone(), ctx)?;
        out.insert(name.to_string(), value);
    }
    Ok(out)
}

fn process_array(a: Vec<Value>, ctx: &mut Ctx) -> Result<Value, String> {
    let mut out = Vec::new();
    for e in a {
        let digest = match &e {
            Value::Object(m) if m.len() == 1 => m.get("...").and_then(Value::as_str),
            _ => None,
        };
        let Some(digest) = digest.map(str::to_string) else {
            out.push(process_value(e, ctx)?);
            continue;
        };
        see(ctx, &digest)?;
        let Some((idx, arr)) = ctx.by_digest.get(&digest).cloned() else {
            continue; // step 3d: removed
        };
        if arr.len() != 2 {
            return Err("array Disclosure is not [salt, value]".into());
        }
        if !arr[0].is_string() {
            return Err("salt is not a string".into());
        }
        ctx.used.insert(idx);
        out.push(process_value(arr[1].clone(), ctx)?);
    }
    Ok(Value::Array(out))
}
