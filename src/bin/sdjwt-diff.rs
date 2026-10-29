//! Run the corpus and print or write the matrix.
//!
//! `sdjwt-diff [--csv PATH] [--details PATH] [--json PATH] [--only ID,ID]`

use sdjwt_diff::matrix;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let get = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1).cloned())
    };
    // Panics inside adapters are caught and recorded as verdicts.
    std::panic::set_hook(Box::new(|_| {}));
    let m = matrix::run();
    if let Some(p) = get("--csv") {
        std::fs::write(p, m.csv()).expect("write csv");
    }
    if let Some(p) = get("--details") {
        std::fs::write(p, m.details_csv()).expect("write details");
    }
    let summary = serde_json::to_string_pretty(&m.summary()).expect("json") + "\n";
    if let Some(p) = get("--json") {
        std::fs::write(p, &summary).expect("write json");
    }
    let only: Option<Vec<String>> = get("--only").map(|s| s.split(',').map(String::from).collect());
    print!("{:<5}", "case");
    for i in &m.impls {
        print!(" {:>16}", i);
    }
    println!();
    for r in &m.rows {
        if let Some(o) = &only {
            if !o.iter().any(|x| x == r.case.id) {
                continue;
            }
        }
        print!("{:<5}", r.case.id);
        for c in &r.cells {
            print!(" {:>16}", c.verdict.label());
        }
        println!("  {}", if r.divergent() { "*" } else { "" });
    }
    if only.is_none() {
        print!("{summary}");
    }
}
