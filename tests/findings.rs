//! The committed results are what the harness produces today, and the
//! headline findings hold.

use sdjwt_diff::adapters::{self, Verdict};
use sdjwt_diff::cases;
use sdjwt_diff::matrix;
use serde_json::Value;

fn quiet_run() -> matrix::Matrix {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let m = matrix::run();
    std::panic::set_hook(hook);
    m
}

#[test]
fn committed_results_match_a_fresh_run() {
    let m = quiet_run();
    let summary = serde_json::to_string_pretty(&m.summary()).unwrap() + "\n";
    assert_eq!(summary, include_str!("../results/summary.json"));
    assert_eq!(m.csv(), include_str!("../results/matrix.csv"));
    assert_eq!(m.details_csv(), include_str!("../results/details.csv"));
}

fn payload_of(imp: &str, id: &str) -> Option<Value> {
    let c = cases::all().into_iter().find(|c| c.id == id).unwrap();
    let a = adapters::all()
        .into_iter()
        .find(|a| a.name() == imp)
        .unwrap();
    match adapters::run(a.as_ref(), &c.input, c.policy, c.area) {
        Verdict::Accept(p) => p,
        _ => None,
    }
}

#[test]
fn sdjwt_lets_a_disclosure_override_a_plaintext_claim() {
    // T21: RFC 9901 7.1 3c.ii.3 requires rejection.
    let p = payload_of("sdjwt", "T21").expect("sdjwt accepts T21");
    assert_eq!(p["iss"], "https://attacker.example");
}

#[test]
fn sdjwt_reorders_array_elements() {
    let p = payload_of("sdjwt", "V01").expect("accept");
    assert_eq!(p["nationalities"], serde_json::json!(["DE", "US"]));
}

#[test]
fn sd_jwt_rs_puts_the_claim_name_in_an_array_slot() {
    // T17: a three-element Disclosure referenced from an array.
    let p = payload_of("sd-jwt-rs", "T17").expect("sd-jwt-rs accepts T17");
    assert_eq!(p["nationalities"], serde_json::json!(["given_name"]));
}

#[test]
fn bh_sd_jwt_agrees_with_every_scored_case() {
    let m = quiet_run();
    let i = m.impls.iter().position(|n| *n == "bh-sd-jwt").unwrap();
    let s = m.score(i);
    assert_eq!((s.agree, s.scored), (66, 66));
}
