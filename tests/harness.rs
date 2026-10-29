//! Properties of the corpus and of the harness itself.

use sdjwt_diff::adapters::{self, Verdict};
use sdjwt_diff::cases::{self, Expect};
use std::collections::HashSet;

#[test]
fn corpus_size_and_unique_ids() {
    let all = cases::all();
    let ids: HashSet<_> = all.iter().map(|c| c.id).collect();
    assert_eq!(ids.len(), all.len());
    let scored = all.iter().filter(|c| c.expect != Expect::Open).count();
    assert!(scored >= 40, "only {scored} scored cases");
    assert!(all.iter().any(|c| c.control && c.expect == Expect::Accept));
    assert!(
        all.iter()
            .filter(|c| c.control && c.expect == Expect::Reject)
            .count()
            >= 4
    );
}

#[test]
fn corpus_is_deterministic() {
    let a: Vec<String> = cases::all().into_iter().map(|c| c.input).collect();
    let b: Vec<String> = cases::all().into_iter().map(|c| c.input).collect();
    assert_eq!(a, b);
}

#[test]
fn no_case_input_reuses_another() {
    let all = cases::all();
    let mut seen = HashSet::new();
    for c in &all {
        // Same bytes under the same policy would be a duplicated case.
        assert!(
            seen.insert((c.input.clone(), c.policy)),
            "{} duplicates",
            c.id
        );
    }
}

#[test]
fn every_implementation_runs_the_positive_controls() {
    let controls: Vec<_> = cases::all()
        .into_iter()
        .filter(|c| c.control && c.expect == Expect::Accept)
        .collect();
    for imp in adapters::all() {
        for c in &controls {
            let v = adapters::run(imp.as_ref(), &c.input, c.policy, c.area);
            assert!(
                matches!(
                    v,
                    Verdict::Accept(_) | Verdict::Delegated(_) | Verdict::Unsupported(_)
                ),
                "{} on {}: {:?}",
                imp.name(),
                c.id,
                v
            );
        }
    }
}

#[test]
fn a_verifier_that_skips_checks_is_caught_by_the_negative_controls() {
    // Harness sanity: an "accept everything" implementation must fail every
    // negative control, otherwise the controls would measure nothing.
    struct AcceptAll;
    impl adapters::Implementation for AcceptAll {
        fn name(&self) -> &'static str {
            "accept-all"
        }
        fn verify(&self, _: &str, _: sdjwt_diff::reference::Policy) -> Verdict {
            Verdict::Accept(None)
        }
    }
    let neg: Vec<_> = cases::all()
        .into_iter()
        .filter(|c| c.control && c.expect == Expect::Reject)
        .collect();
    for c in &neg {
        let v = adapters::run(&AcceptAll, &c.input, c.policy, c.area);
        assert_eq!(v.label(), "accept", "{}", c.id);
        assert!(
            sdjwt_diff::reference::verify(&c.input, c.policy).is_err(),
            "{}",
            c.id
        );
    }
}
