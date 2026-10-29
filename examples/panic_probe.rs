//! Exploratory, post-hoc: is the sd-jwt-rs index panic reachable with
//! Disclosures the Holder can add (digest not in the Issuer-signed JWT)?
use sdjwt_diff::adapters::{self, SdJwtRs};
use sdjwt_diff::build::{self, disc_raw, sd_jwt, World};
use sdjwt_diff::cases::Area;
use sdjwt_diff::reference::Policy;
fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let w = World::default();
    let jwt = build::issue(&w.payload(false));
    for (name, text) in [
        ("two-element, unreferenced", r#"["c2FsdC1wcm9iZQ","x"]"#),
        ("one-element, unreferenced", r#"["c2FsdC1wcm9iZQ"]"#),
        ("empty array, unreferenced", r#"[]"#),
    ] {
        let d = disc_raw(text);
        let input = sd_jwt(&jwt, &[&w.given, &d]);
        let v = adapters::run(&SdJwtRs, &input, Policy::NoKb, Area::Disclosure);
        println!("{name}: {} {}", v.label(), v.detail());
    }
}
