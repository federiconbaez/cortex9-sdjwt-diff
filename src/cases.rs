//! Hand-written corpus. Every case cites the RFC 9901 section it exercises.
//!
//! Classes: `V` valid (RFC: accept), `T` tampered or malformed (RFC: reject),
//! `K` Key Binding (RFC: reject unless stated), `P` points where the RFC text
//! does not fix the Verifier's answer (reported, never scored).

use crate::build::{self, decoy, disc_arr, disc_obj, disc_raw, issue, sd_jwt, Kb, World};
use crate::jose::{self, KeyId};
use crate::reference::Policy;
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    Accept,
    Reject,
    /// RFC text does not decide; not scored.
    Open,
}

impl Expect {
    pub fn as_str(&self) -> &'static str {
        match self {
            Expect::Accept => "accept",
            Expect::Reject => "reject",
            Expect::Open => "open",
        }
    }
}

/// What part of the stack a case exercises. Used to mark cells as
/// "delegated" when a crate hands that part to the caller by design.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Area {
    Format,
    IssuerSig,
    Disclosure,
    Validity,
    KeyBinding,
    KbSig,
}

impl Area {
    pub fn as_str(&self) -> &'static str {
        match self {
            Area::Format => "format",
            Area::IssuerSig => "issuer-sig",
            Area::Disclosure => "disclosure",
            Area::Validity => "validity",
            Area::KeyBinding => "key-binding",
            Area::KbSig => "kb-sig",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Case {
    pub id: &'static str,
    pub section: &'static str,
    pub area: Area,
    pub policy: Policy,
    pub expect: Expect,
    /// Positive or negative control: every implementation must agree.
    pub control: bool,
    pub title: &'static str,
    pub input: String,
}

fn case(
    id: &'static str,
    section: &'static str,
    area: Area,
    policy: Policy,
    expect: Expect,
    title: &'static str,
    input: String,
) -> Case {
    Case {
        id,
        section,
        area,
        policy,
        expect,
        control: false,
        title,
        input,
    }
}

fn control(mut c: Case) -> Case {
    c.control = true;
    c
}

fn with_kb(sd: String) -> String {
    let kb = Kb::for_sd_jwt(&sd).sign();
    format!("{sd}{kb}")
}

fn with_kb_edit(sd: String, edit: impl FnOnce(&mut Kb)) -> String {
    let mut kb = Kb::for_sd_jwt(&sd);
    edit(&mut kb);
    format!("{sd}{}", kb.sign())
}

/// The full corpus, in a fixed order.
#[allow(clippy::vec_init_then_push)]
pub fn all() -> Vec<Case> {
    use Area::*;
    use Expect::*;
    use Policy::*;
    let w = World::default();
    let base = w.payload(false);
    let jwt = issue(&base);
    let all = w.all();
    let basek = w.payload(true);
    let jwtk = issue(&basek);
    let mut v = Vec::new();

    // ---------------------------------------------------------------- valid
    v.push(control(case(
        "V01",
        "7.1",
        Disclosure,
        NoKb,
        Accept,
        "base SD-JWT with every Disclosure",
        sd_jwt(&jwt, &all),
    )));
    v.push(case(
        "V02",
        "4",
        Format,
        NoKb,
        Accept,
        "zero Disclosures (<JWT>~)",
        sd_jwt(&jwt, &[]),
    ));
    v.push(case(
        "V03",
        "7.2",
        Disclosure,
        NoKb,
        Accept,
        "subset of Disclosures",
        sd_jwt(&jwt, &[&w.given]),
    ));
    v.push(case(
        "V04",
        "4",
        Disclosure,
        NoKb,
        Accept,
        "Disclosures in reverse order",
        sd_jwt(&jwt, &[&w.nat_us, &w.street, &w.family, &w.given]),
    ));
    {
        let mut p = base.clone();
        p["_sd"].as_array_mut().unwrap().push(json!(decoy("a")));
        p["address"]["_sd"]
            .as_array_mut()
            .unwrap()
            .insert(0, json!(decoy("b")));
        v.push(case(
            "V05",
            "4.2.5",
            Disclosure,
            NoKb,
            Accept,
            "decoy digests in _sd arrays",
            sd_jwt(&issue(&p), &all),
        ));
    }
    {
        let mut p = base.clone();
        p.as_object_mut().unwrap().remove("_sd_alg");
        v.push(case(
            "V06",
            "4.1.1",
            Disclosure,
            NoKb,
            Accept,
            "_sd_alg absent, default sha-256",
            sd_jwt(&issue(&p), &all),
        ));
    }
    let addr = disc_obj(
        "c2FsdC1hZGRyLTAwNQ",
        "address",
        json!({"_sd": [w.street.digest], "country": "AR"}),
    );
    let mut rec = base.clone();
    rec.as_object_mut().unwrap().remove("address");
    rec["_sd"].as_array_mut().unwrap().push(json!(addr.digest));
    let jwt_rec = issue(&rec);
    v.push(case(
        "V07",
        "7.1 3c.ii.5",
        Disclosure,
        NoKb,
        Accept,
        "recursive Disclosure: address disclosed, street inside",
        sd_jwt(
            &jwt_rec,
            &[&w.given, &w.family, &addr, &w.street, &w.nat_us],
        ),
    ));
    v.push(case(
        "V08",
        "7.1 3c.ii.5",
        Disclosure,
        NoKb,
        Accept,
        "recursive Disclosure: parent sent, nested child withheld",
        sd_jwt(&jwt_rec, &[&addr]),
    ));
    {
        let mut p = base.clone();
        p["nationalities"] = json!([{"...": w.nat_us.digest}, {"...": decoy("c")}, "DE"]);
        v.push(case(
            "V09",
            "7.1 3d",
            Disclosure,
            NoKb,
            Accept,
            "array decoy element is removed",
            sd_jwt(&issue(&p), &all),
        ));
    }
    {
        let dn = disc_obj("c2FsdC1udWxsLTAwNg", "middle_name", Value::Null);
        let do_ = disc_obj(
            "c2FsdC1vYmotMDA3",
            "extra",
            json!({"a": [1, 2], "b": {"c": true}}),
        );
        let dnum = disc_obj("c2FsdC1udW0tMDA4", "age", json!(42));
        let db = disc_obj("c2FsdC1ib29sLTAwOQ", "over_18", json!(true));
        let mut p = base.clone();
        for d in [&dn, &do_, &dnum, &db] {
            p["_sd"].as_array_mut().unwrap().push(json!(d.digest));
        }
        v.push(case(
            "V10",
            "4.2.1",
            Disclosure,
            NoKb,
            Accept,
            "claim values null, object, number and boolean",
            sd_jwt(&issue(&p), &[&dn, &do_, &dnum, &db]),
        ));
    }
    {
        let spaced = disc_raw(r#"["c2FsdC1zcGFjZS0wMTA", "family_name", "Möbius"]"#);
        let escaped = disc_raw(r#"["c2FsdC1lc2MtMDEx","given_name","M\u00f6bius"]"#);
        let mut p = base.clone();
        p["_sd"] = json!([spaced.digest, escaped.digest]);
        v.push(case(
            "V11",
            "4.2.1",
            Disclosure,
            NoKb,
            Accept,
            "Disclosure JSON with spaces and \\u escape, hashed as sent",
            sd_jwt(&issue(&p), &[&spaced, &escaped]),
        ));
    }
    v.push(control(case(
        "V12",
        "7.3",
        KeyBinding,
        Kb,
        Accept,
        "SD-JWT+KB with every Disclosure",
        with_kb(sd_jwt(&jwtk, &all)),
    )));
    v.push(case(
        "V13",
        "7.3",
        KeyBinding,
        Kb,
        Accept,
        "SD-JWT+KB with zero Disclosures",
        with_kb(sd_jwt(&jwtk, &[])),
    ));
    v.push(case(
        "V14",
        "7.3 step 1",
        KeyBinding,
        NoKb,
        Accept,
        "cnf present, Verifier does not require KB, no KB-JWT",
        sd_jwt(&jwtk, &all),
    ));
    {
        let city = disc_obj("c2FsdC1jaXR5LTAxMg", "city", json!("CABA"));
        let elem = disc_arr(
            "c2FsdC1lbGVtLTAxMw",
            json!({"_sd": [city.digest], "zip": "1000"}),
        );
        let mut p = base.clone();
        p["addresses"] = json!([{"...": elem.digest}]);
        v.push(case(
            "V15",
            "7.1 3c.iii.3",
            Disclosure,
            NoKb,
            Accept,
            "array element Disclosure whose value holds an _sd object",
            sd_jwt(&issue(&p), &[&elem, &city]),
        ));
    }
    {
        let d = disc_obj("a", "nickname", json!("Ani"));
        let mut p = base.clone();
        p["_sd"].as_array_mut().unwrap().push(json!(d.digest));
        v.push(case(
            "V16",
            "9.3",
            Disclosure,
            NoKb,
            Accept,
            "one-character salt (entropy is an Issuer duty)",
            sd_jwt(&issue(&p), &[&d]),
        ));
    }
    {
        let d1 = disc_obj("c2FsdC11bmktMDE0", "名前", json!("アナ"));
        let d2 = disc_obj("c2FsdC1zcGMtMDE1", "claim with space", json!("x"));
        let mut p = base.clone();
        p["_sd"] = json!([d1.digest, d2.digest]);
        v.push(case(
            "V17",
            "4.2.1",
            Disclosure,
            NoKb,
            Accept,
            "non-ASCII claim name and name with a space",
            sd_jwt(&issue(&p), &[&d1, &d2]),
        ));
    }
    {
        let inner = disc_arr("c2FsdC1pbm5lci0wMTY", json!("X"));
        let outer = disc_arr("c2FsdC1vdXRlci0wMTc", json!([{"...": inner.digest}, "Y"]));
        let mut p = base.clone();
        p["codes"] = json!([{"...": outer.digest}]);
        v.push(case(
            "V18",
            "7.1 3c.iii.3",
            Disclosure,
            NoKb,
            Accept,
            "array Disclosure nested inside an array Disclosure",
            sd_jwt(&issue(&p), &[&outer, &inner]),
        ));
    }
    {
        let d = disc_obj("c2FsdC1jdHJ5LTAxOA", "country", json!("UY"));
        let mut p = base.clone();
        p["_sd"].as_array_mut().unwrap().push(json!(d.digest));
        v.push(case(
            "V19",
            "7.1 3c.ii.3",
            Disclosure,
            NoKb,
            Accept,
            "same claim name at a different level (address.country)",
            sd_jwt(&issue(&p), &[&d, &w.street]),
        ));
    }
    v.push(case(
        "V20",
        "4.3.1",
        KeyBinding,
        Kb,
        Accept,
        "SD-JWT+KB with a subset, sd_hash over that subset",
        with_kb(sd_jwt(&jwtk, &[&w.family, &w.nat_us])),
    ));
    {
        let mut p = base.clone();
        p["meta"] = json!({"_sd": [decoy("d")]});
        v.push(case(
            "V21",
            "7.1 3e",
            Disclosure,
            NoKb,
            Accept,
            "object left with no properties becomes {}",
            sd_jwt(&issue(&p), &[]),
        ));
    }

    // ------------------------------------------------------------- tampered
    v.push(case(
        "T01",
        "4",
        Format,
        NoKb,
        Reject,
        "SD-JWT without the final tilde",
        sd_jwt(&jwt, &all).trim_end_matches('~').to_string(),
    ));
    v.push(case(
        "T02",
        "4",
        Format,
        NoKb,
        Reject,
        "Verifier expects SD-JWT, receives SD-JWT+KB (final part not empty)",
        with_kb(sd_jwt(&jwtk, &all)),
    ));
    v.push(case(
        "T03",
        "4",
        Format,
        NoKb,
        Reject,
        "empty Disclosure between two tildes",
        format!("{jwt}~~{}~", w.given.enc),
    ));
    v.push(case(
        "T04",
        "4.2.1",
        Format,
        NoKb,
        Reject,
        "Disclosure with a non-base64url character",
        format!("{jwt}~{}!~", w.given.enc),
    ));
    {
        let d = disc_raw(r#"{"salt":"x","given_name":"Ana"}"#);
        let mut p = base.clone();
        p["_sd"].as_array_mut().unwrap().push(json!(d.digest));
        v.push(case(
            "T05",
            "7.1 3c.ii.1",
            Format,
            NoKb,
            Reject,
            "Disclosure is a JSON object, not an array",
            sd_jwt(&issue(&p), &[&d]),
        ));
    }
    {
        let d = build::disc_enc(jose::b64(b"not json at all"));
        let mut p = base.clone();
        p["_sd"].as_array_mut().unwrap().push(json!(d.digest));
        v.push(case(
            "T06",
            "4.2.1",
            Format,
            NoKb,
            Reject,
            "Disclosure is not JSON",
            sd_jwt(&issue(&p), &[&d]),
        ));
    }
    {
        let h = json!({"alg": "none", "typ": "dc+sd-jwt"});
        v.push(control(case(
            "T07",
            "7.1 2a",
            IssuerSig,
            NoKb,
            Reject,
            "Issuer JWT with alg none",
            sd_jwt(&jose::sign_none(&h, &base), &all),
        )));
    }
    v.push(control(case(
        "T08",
        "7.1 2b",
        IssuerSig,
        NoKb,
        Reject,
        "Issuer JWT signed by a different key",
        sd_jwt(
            &jose::sign_es256(&build::header(), &base, KeyId::Attacker),
            &all,
        ),
    )));
    {
        let mut p = base.clone();
        p["iss"] = json!("https://attacker.example");
        let (h, _, s) = split3(&jwt);
        let forged = format!("{h}.{}.{s}", jose::b64(p.to_string().as_bytes()));
        v.push(control(case(
            "T09",
            "9.1",
            IssuerSig,
            NoKb,
            Reject,
            "Issuer payload changed after signing",
            sd_jwt(&forged, &all),
        )));
    }
    {
        let h = json!({"alg": "HS256", "typ": "dc+sd-jwt"});
        let secret = jose::public_pem(KeyId::Issuer);
        v.push(case(
            "T10",
            "7.1 2a",
            IssuerSig,
            NoKb,
            Reject,
            "alg confusion: HS256 keyed with the Issuer public key PEM",
            sd_jwt(&jose::sign_hs256(&h, &base, secret.as_bytes()), &all),
        ));
    }
    {
        let (h, p, _) = split3(&jwt);
        v.push(case(
            "T11",
            "7.1 2b",
            IssuerSig,
            NoKb,
            Reject,
            "ES256 header with the signature stripped",
            sd_jwt(&format!("{h}.{p}."), &all),
        ));
    }
    {
        let forged = disc_obj("c2FsdC1naXZlbi0wMDAx", "given_name", json!("Eva"));
        v.push(control(case(
            "T12",
            "9.2",
            Disclosure,
            NoKb,
            Reject,
            "Disclosure value changed by the Holder",
            sd_jwt(&jwt, &[&forged, &w.family]),
        )));
    }
    {
        let stray = disc_obj("c2FsdC1zdHJheS0wMTk", "role", json!("admin"));
        v.push(case(
            "T13",
            "7.1 step 5",
            Disclosure,
            NoKb,
            Reject,
            "extra Disclosure not referenced by any digest",
            sd_jwt(&jwt, &[&w.given, &stray]),
        ));
    }
    {
        let mut p = base.clone();
        p["_sd"].as_array_mut().unwrap().push(json!(w.given.digest));
        v.push(case(
            "T14",
            "7.1 step 4",
            Disclosure,
            NoKb,
            Reject,
            "same digest twice in one _sd array",
            sd_jwt(&issue(&p), &[&w.given]),
        ));
    }
    {
        let mut p = base.clone();
        p["address"]["_sd"]
            .as_array_mut()
            .unwrap()
            .push(json!(w.given.digest));
        v.push(case(
            "T15",
            "7.1 step 4",
            Disclosure,
            NoKb,
            Reject,
            "same digest in two different objects",
            sd_jwt(&issue(&p), &[&w.given]),
        ));
    }
    {
        let addr2 = disc_obj(
            "c2FsdC1hZGRyMi0wMjA",
            "address",
            json!({"_sd": [w.street.digest, w.given.digest], "country": "AR"}),
        );
        let mut p = rec.clone();
        p["_sd"] = json!([w.given.digest, w.family.digest, addr2.digest]);
        v.push(case(
            "T16",
            "7.1 step 4",
            Disclosure,
            NoKb,
            Reject,
            "digest in the payload and again inside a Disclosure",
            sd_jwt(&issue(&p), &[&w.given, &addr2, &w.street]),
        ));
    }
    {
        let mut p = base.clone();
        p["nationalities"] = json!([{"...": w.given.digest}]);
        p["_sd"] = json!([w.family.digest]);
        v.push(case(
            "T17",
            "7.1 3c.iii.1",
            Disclosure,
            NoKb,
            Reject,
            "three-element Disclosure referenced from an array",
            sd_jwt(&issue(&p), &[&w.given]),
        ));
    }
    {
        let mut p = base.clone();
        p["_sd"]
            .as_array_mut()
            .unwrap()
            .push(json!(w.nat_us.digest));
        p["nationalities"] = json!(["DE"]);
        v.push(case(
            "T18",
            "7.1 3c.ii.1",
            Disclosure,
            NoKb,
            Reject,
            "two-element Disclosure referenced from _sd",
            sd_jwt(&issue(&p), &[&w.nat_us]),
        ));
    }
    for (id, name, title) in [
        ("T19", "_sd", "Disclosure with claim name _sd"),
        ("T20", "...", "Disclosure with claim name ..."),
    ] {
        let d = disc_obj("c2FsdC1yZXNlcnZlZA", name, json!(["x"]));
        let mut p = base.clone();
        p["_sd"].as_array_mut().unwrap().push(json!(d.digest));
        v.push(case(
            id,
            "7.1 3c.ii.2",
            Disclosure,
            NoKb,
            Reject,
            title,
            sd_jwt(&issue(&p), &[&d]),
        ));
    }
    {
        let d = disc_obj("c2FsdC1pc3MtMDIx", "iss", json!("https://attacker.example"));
        let mut p = base.clone();
        p["_sd"].as_array_mut().unwrap().push(json!(d.digest));
        v.push(case(
            "T21",
            "7.1 3c.ii.3",
            Disclosure,
            NoKb,
            Reject,
            "Disclosure overrides a plaintext claim (iss)",
            sd_jwt(&issue(&p), &[&d]),
        ));
    }
    {
        let d2 = disc_obj("c2FsdC1naXZlbjItMDIy", "given_name", json!("Eva"));
        let mut p = base.clone();
        p["_sd"].as_array_mut().unwrap().push(json!(d2.digest));
        v.push(case(
            "T22",
            "7.1 3c.ii.3",
            Disclosure,
            NoKb,
            Reject,
            "two Disclosures with the same claim name at one level",
            sd_jwt(&issue(&p), &[&w.given, &d2]),
        ));
    }
    {
        let mut p = base.clone();
        p["_sd_alg"] = json!("sha-0-unknown");
        v.push(case(
            "T23",
            "7.1 2d",
            Disclosure,
            NoKb,
            Reject,
            "_sd_alg not understood",
            sd_jwt(&issue(&p), &all),
        ));
    }
    {
        let d = disc_raw(r#"["c2FsdC1mb3VyLTAyMw","given_name","Ana","extra"]"#);
        let mut p = base.clone();
        p["_sd"] = json!([d.digest]);
        v.push(case(
            "T24",
            "7.1 3c.ii.1",
            Disclosure,
            NoKb,
            Reject,
            "four-element Disclosure",
            sd_jwt(&issue(&p), &[&d]),
        ));
    }
    {
        let d = disc_raw(r#"["c2FsdC1udW1uYW1lLTI0",7,"x"]"#);
        let mut p = base.clone();
        p["_sd"] = json!([d.digest]);
        v.push(case(
            "T25",
            "4.2.1",
            Disclosure,
            NoKb,
            Reject,
            "claim name is a number",
            sd_jwt(&issue(&p), &[&d]),
        ));
    }
    {
        // Same JSON content as w.given, serialized with spaces: different digest.
        let respaced = disc_raw(r#"["c2FsdC1naXZlbi0wMDAx", "given_name", "Ana"]"#);
        v.push(case(
            "T26",
            "4.2.3",
            Disclosure,
            NoKb,
            Reject,
            "Disclosure re-serialized by the Holder (digest no longer matches)",
            sd_jwt(&jwt, &[&respaced]),
        ));
    }
    {
        let mut p = base.clone();
        p["exp"] = json!(build::T0 - 1000);
        v.push(case(
            "T27",
            "7.1 step 6",
            Validity,
            NoKb,
            Reject,
            "exp in the past",
            sd_jwt(&issue(&p), &all),
        ));
        let mut p = base.clone();
        p["nbf"] = json!(build::EXP - 1);
        v.push(case(
            "T28",
            "7.1 step 6",
            Validity,
            NoKb,
            Reject,
            "nbf in the future",
            sd_jwt(&issue(&p), &all),
        ));
        let dexp = disc_obj("c2FsdC1leHAtMDI1", "exp", json!(build::T0 - 1000));
        let mut p = base.clone();
        p.as_object_mut().unwrap().remove("exp");
        p["_sd"].as_array_mut().unwrap().push(json!(dexp.digest));
        v.push(case(
            "T29",
            "9.7",
            Validity,
            NoKb,
            Reject,
            "exp in the past, delivered as a Disclosure",
            sd_jwt(&issue(&p), &[&dexp]),
        ));
    }

    // ---------------------------------------------------------- key binding
    let sdk = sd_jwt(&jwtk, &all);
    v.push(case(
        "K01",
        "7.3 step 2",
        KeyBinding,
        Kb,
        Reject,
        "KB required, SD-JWT without KB-JWT",
        sdk.clone(),
    ));
    v.push(case(
        "K02",
        "4.3",
        KeyBinding,
        Kb,
        Reject,
        "KB-JWT typ is jwt",
        with_kb_edit(sdk.clone(), |k| k.header["typ"] = json!("jwt")),
    ));
    v.push(case(
        "K03",
        "4.3",
        KeyBinding,
        Kb,
        Reject,
        "KB-JWT without typ",
        with_kb_edit(sdk.clone(), |k| {
            k.header.as_object_mut().unwrap().remove("typ");
        }),
    ));
    v.push(case(
        "K04",
        "4.3.2",
        KbSig,
        Kb,
        Reject,
        "KB-JWT signed by a key other than cnf",
        with_kb_edit(sdk.clone(), |k| k.key = KeyId::Attacker),
    ));
    v.push(case(
        "K05",
        "7.3 5b",
        KbSig,
        Kb,
        Reject,
        "KB-JWT with alg none",
        with_kb_edit(sdk.clone(), |k| {
            k.header["alg"] = json!("none");
            k.unsigned = true;
        }),
    ));
    v.push(case(
        "K06",
        "7.3 5f",
        KeyBinding,
        Kb,
        Reject,
        "KB-JWT aud for another Verifier",
        with_kb_edit(sdk.clone(), |k| {
            k.payload["aud"] = json!("https://other.example")
        }),
    ));
    v.push(case(
        "K07",
        "7.3 5f",
        KeyBinding,
        Kb,
        Reject,
        "KB-JWT nonce mismatch",
        with_kb_edit(sdk.clone(), |k| {
            k.payload["nonce"] = json!("replayed-nonce")
        }),
    ));
    {
        let kb = build::Kb::for_sd_jwt(&sdk).sign();
        let fewer = sd_jwt(&jwtk, &[&w.given]);
        v.push(case(
            "K08",
            "7.3 5g",
            KeyBinding,
            Kb,
            Reject,
            "Disclosure removed after the KB-JWT was signed",
            format!("{fewer}{kb}"),
        ));
    }
    v.push(case(
        "K09",
        "4.3",
        KeyBinding,
        Kb,
        Reject,
        "KB-JWT without sd_hash",
        with_kb_edit(sdk.clone(), |k| {
            k.payload.as_object_mut().unwrap().remove("sd_hash");
        }),
    ));
    v.push(case(
        "K10",
        "7.3 5e",
        KeyBinding,
        Kb,
        Reject,
        "KB-JWT iat one day old",
        with_kb_edit(sdk.clone(), |k| {
            k.payload["iat"] = json!(build::T0 - 86_400)
        }),
    ));
    v.push(case(
        "K11",
        "4.3",
        KeyBinding,
        Kb,
        Reject,
        "KB-JWT without iat",
        with_kb_edit(sdk.clone(), |k| {
            k.payload.as_object_mut().unwrap().remove("iat");
        }),
    ));
    v.push(case(
        "K12",
        "4.3",
        KeyBinding,
        Kb,
        Reject,
        "KB-JWT without nonce",
        with_kb_edit(sdk.clone(), |k| {
            k.payload.as_object_mut().unwrap().remove("nonce");
        }),
    ));
    v.push(case(
        "K13",
        "7.3 5a",
        KeyBinding,
        Kb,
        Reject,
        "credential without cnf, KB-JWT present",
        with_kb(sd_jwt(&jwt, &all)),
    ));
    v.push(case(
        "K14",
        "4.3.1",
        KeyBinding,
        Kb,
        Reject,
        "sd_hash computed without the trailing tilde",
        with_kb_edit(sdk.clone(), |k| {
            k.payload["sd_hash"] = json!(build::sha256_b64(sdk.trim_end_matches('~')));
        }),
    ));
    v.push(case(
        "K15",
        "7.3 5e",
        KeyBinding,
        Kb,
        Reject,
        "KB-JWT iat one hour in the future",
        with_kb_edit(sdk.clone(), |k| k.payload["iat"] = json!(build::T0 + 3_600)),
    ));
    {
        let good = with_kb(sdk.clone());
        let (pre, kb) = good.rsplit_once('~').unwrap();
        let (h, _, s) = split3(kb);
        let mut p = build::Kb::for_sd_jwt(&sdk).payload;
        p["aud"] = json!("https://other.example");
        let forged = format!("{pre}~{h}.{}.{s}", jose::b64(p.to_string().as_bytes()));
        v.push(case(
            "K16",
            "7.3 5c",
            KbSig,
            Kb,
            Reject,
            "KB-JWT payload changed after signing",
            forged,
        ));
    }

    // ----------------------------------------------------------------- open
    v.push(case(
        "P01",
        "4",
        Disclosure,
        NoKb,
        Open,
        "same Disclosure sent twice (a Holder MUST NOT; Verifier rule unstated)",
        sd_jwt(&jwt, &[&w.given, &w.given]),
    ));
    {
        let d = disc_raw(r#"[12345,"nickname","Ani"]"#);
        let mut p = base.clone();
        p["_sd"] = json!([d.digest]);
        v.push(case(
            "P02",
            "4.2.1",
            Disclosure,
            NoKb,
            Open,
            "salt is a number (Issuer MUST use a string)",
            sd_jwt(&issue(&p), &[&d]),
        ));
    }
    {
        let mut p = base.clone();
        p["address"]["_sd_alg"] = json!("sha-256");
        v.push(case(
            "P03",
            "4.1.1",
            Disclosure,
            NoKb,
            Open,
            "_sd_alg inside a nested object",
            sd_jwt(&issue(&p), &all),
        ));
    }
    v.push(case(
        "P04",
        "4.3",
        KeyBinding,
        Kb,
        Open,
        "KB-JWT aud is an array holding the expected value",
        with_kb_edit(sdk.clone(), |k| k.payload["aud"] = json!([build::AUD])),
    ));
    {
        let mut p = base.clone();
        p["address"]["_sd"] = json!(w.street.digest);
        v.push(case(
            "P05",
            "7.1 3b.i",
            Disclosure,
            NoKb,
            Open,
            "_sd is a string instead of an array",
            sd_jwt(&issue(&p), &[&w.street]),
        ));
    }
    {
        let mut p = base.clone();
        p["nationalities"] = json!([{"...": w.nat_us.digest, "x": 1}, "DE"]);
        v.push(case(
            "P06",
            "7.1 3b.ii",
            Disclosure,
            NoKb,
            Open,
            "array element with ... and a second key",
            sd_jwt(&issue(&p), &[&w.nat_us]),
        ));
    }
    v
}

fn split3(jws: &str) -> (&str, &str, &str) {
    let mut it = jws.splitn(3, '.');
    (it.next().unwrap(), it.next().unwrap(), it.next().unwrap())
}
