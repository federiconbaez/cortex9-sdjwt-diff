use sdjwt_diff::adapters::{self, Verdict};
use sdjwt_diff::cases;
fn main() {
    let ids: Vec<String> = std::env::args().skip(1).collect();
    for c in cases::all() {
        if !ids.iter().any(|i| i == c.id) {
            continue;
        }
        for imp in adapters::all() {
            let v = adapters::run(imp.as_ref(), &c.input, c.policy, c.area);
            match v {
                Verdict::Accept(Some(p)) => println!("{} {}: {}", c.id, imp.name(), p),
                other => println!("{} {}: {:?}", c.id, imp.name(), other),
            }
        }
    }
}
