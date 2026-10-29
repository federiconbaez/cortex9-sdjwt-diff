//! The reference verifier against the RFC 9901 text, independent of any
//! crate under test.

use sdjwt_diff::build::{self, sd_jwt, World};
use sdjwt_diff::cases::{self, Expect};
use sdjwt_diff::reference::{verify, Policy};
use serde_json::json;

#[test]
fn rfc9901_4_2_1_disclosure_and_4_2_3_digest_vectors() {
    // Section 4.2.1: the array and its Disclosure.
    let d = build::disc_raw(r#"["_26bc4LT-ac6q2KI6cBW5es", "family_name", "Möbius"]"#);
    assert_eq!(
        d.enc,
        "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"
    );
    // Section 4.2.3: its SHA-256 digest.
    assert_eq!(d.digest, "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0");
}

#[test]
fn processed_payload_of_the_base_case() {
    let w = World::default();
    let jwt = build::issue(&w.payload(false));
    let out = verify(&sd_jwt(&jwt, &w.all()), Policy::NoKb).expect("accept");
    assert_eq!(out, w.processed_all(false));
}

#[test]
fn undisclosed_claims_are_absent() {
    let w = World::default();
    let jwt = build::issue(&w.payload(false));
    let out = verify(&sd_jwt(&jwt, &[&w.given]), Policy::NoKb).expect("accept");
    assert_eq!(out["given_name"], json!("Ana"));
    assert!(out.get("family_name").is_none());
    assert_eq!(out["address"], json!({"country": "AR"}));
    assert_eq!(out["nationalities"], json!(["DE"]));
}

#[test]
fn reference_matches_every_scored_expectation() {
    let mut wrong = Vec::new();
    for c in cases::all() {
        let got = verify(&c.input, c.policy).is_ok();
        match c.expect {
            Expect::Accept if !got => wrong.push(format!("{} rejected", c.id)),
            Expect::Reject if got => wrong.push(format!("{} accepted", c.id)),
            _ => {}
        }
    }
    assert!(wrong.is_empty(), "{wrong:?}");
}

#[test]
fn key_binding_is_checked_only_under_the_kb_policy() {
    let w = World::default();
    let jwt = build::issue(&w.payload(true));
    let sd = sd_jwt(&jwt, &w.all());
    assert!(verify(&sd, Policy::NoKb).is_ok());
    assert!(verify(&sd, Policy::Kb).is_err());
    let kb = build::Kb::for_sd_jwt(&sd).sign();
    let sdkb = format!("{sd}{kb}");
    assert!(verify(&sdkb, Policy::Kb).is_ok());
    // An SD-JWT Verifier must see an empty final component (section 4).
    assert!(verify(&sdkb, Policy::NoKb).is_err());
}
