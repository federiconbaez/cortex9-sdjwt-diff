//! Runs the corpus against every implementation and scores the verdicts.

use crate::adapters::{self, Verdict};
use crate::cases::{self, Case, Expect};
use serde_json::{json, Value};

pub struct Cell {
    pub verdict: Verdict,
    /// For accepted cases: whether the processed payload equals the
    /// reference's (ignoring a top-level `_sd_alg`). `None` if not comparable.
    pub claims_match: Option<bool>,
}

pub struct Row {
    pub case: Case,
    pub cells: Vec<Cell>,
}

pub struct Matrix {
    pub impls: Vec<&'static str>,
    pub rows: Vec<Row>,
}

fn strip(mut v: Value) -> Value {
    if let Some(o) = v.as_object_mut() {
        o.remove("_sd_alg");
    }
    v
}

pub fn run() -> Matrix {
    let imps = adapters::all();
    let impls = imps.iter().map(|i| i.name()).collect();
    let rows = cases::all()
        .into_iter()
        .map(|case| {
            let mut cells: Vec<Cell> = Vec::new();
            let mut reference_payload: Option<Value> = None;
            for imp in &imps {
                let verdict = adapters::run(imp.as_ref(), &case.input, case.policy, case.area);
                if imp.name() == "reference" {
                    if let Verdict::Accept(Some(p)) = &verdict {
                        reference_payload = Some(strip(p.clone()));
                    }
                }
                let claims_match = match (&verdict, &reference_payload) {
                    (Verdict::Accept(Some(p)), Some(r)) => Some(&strip(p.clone()) == r),
                    _ => None,
                };
                cells.push(Cell {
                    verdict,
                    claims_match,
                });
            }
            Row { case, cells }
        })
        .collect();
    Matrix { impls, rows }
}

fn scored(v: &Verdict) -> Option<bool> {
    // Some(true) = accepted, Some(false) = rejected (a panic rejects).
    match v {
        Verdict::Accept(_) => Some(true),
        Verdict::Reject(_) | Verdict::Panic(_) => Some(false),
        Verdict::Delegated(_) | Verdict::Unsupported(_) => None,
    }
}

impl Row {
    /// Implementations that ran the case disagree with each other.
    pub fn divergent(&self) -> bool {
        let mut seen: Option<bool> = None;
        for c in &self.cells {
            if let Some(a) = scored(&c.verdict) {
                match seen {
                    None => seen = Some(a),
                    Some(s) if s != a => return true,
                    _ => {}
                }
            }
        }
        false
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Score {
    pub scored: usize,
    pub agree: usize,
    pub spurious_reject: usize,
    pub undue_accept: usize,
    pub claims_mismatch: usize,
    pub panics: usize,
    pub delegated: usize,
    pub unsupported: usize,
    pub controls_ok: usize,
    pub controls_run: usize,
    pub open_accept: usize,
    pub open_reject: usize,
    pub undue_ids: Vec<String>,
    pub spurious_ids: Vec<String>,
    pub mismatch_ids: Vec<String>,
}

impl Matrix {
    pub fn score(&self, idx: usize) -> Score {
        let mut s = Score::default();
        for r in &self.rows {
            let cell = &r.cells[idx];
            if matches!(cell.verdict, Verdict::Panic(_)) {
                s.panics += 1;
            }
            let Some(acc) = scored(&cell.verdict) else {
                match cell.verdict {
                    Verdict::Delegated(_) => s.delegated += 1,
                    _ => s.unsupported += 1,
                }
                continue;
            };
            if r.case.expect == Expect::Open {
                if acc {
                    s.open_accept += 1
                } else {
                    s.open_reject += 1
                }
                continue;
            }
            s.scored += 1;
            let want = r.case.expect == Expect::Accept;
            let ok = acc == want;
            if ok {
                s.agree += 1;
            } else if want {
                s.spurious_reject += 1;
                s.spurious_ids.push(r.case.id.into());
            } else {
                s.undue_accept += 1;
                s.undue_ids.push(r.case.id.into());
            }
            if cell.claims_match == Some(false) && want {
                s.claims_mismatch += 1;
                s.mismatch_ids.push(r.case.id.into());
            }
            if r.case.control {
                s.controls_run += 1;
                if ok {
                    s.controls_ok += 1;
                }
            }
        }
        s
    }

    pub fn divergent_count(&self) -> usize {
        self.rows.iter().filter(|r| r.divergent()).count()
    }

    /// One row per case; verdict per implementation; the input is the repro.
    pub fn csv(&self) -> String {
        let mut out = String::from("id,section,area,policy,expect,control,title");
        for i in &self.impls {
            out.push(',');
            out.push_str(i);
        }
        out.push_str(",divergent,repro\n");
        for r in &self.rows {
            let c = &r.case;
            out.push_str(&format!(
                "{},{},{},{},{},{},\"{}\"",
                c.id,
                c.section,
                c.area.as_str(),
                c.policy.as_str(),
                c.expect.as_str(),
                c.control,
                c.title.replace('"', "'")
            ));
            for cell in &r.cells {
                let mut l = cell.verdict.label().to_string();
                if cell.claims_match == Some(false) {
                    l.push_str("+claims-differ");
                }
                out.push(',');
                out.push_str(&l);
            }
            out.push_str(&format!(",{},{}\n", r.divergent(), c.input));
        }
        out
    }

    /// Error text per non-accept cell, for triage.
    pub fn details_csv(&self) -> String {
        let mut out = String::from("id,implementation,verdict,detail\n");
        for r in &self.rows {
            for (i, cell) in r.cells.iter().enumerate() {
                out.push_str(&format!(
                    "{},{},{},\"{}\"\n",
                    r.case.id,
                    self.impls[i],
                    cell.verdict.label(),
                    cell.verdict.detail().replace('"', "'")
                ));
            }
        }
        out
    }

    pub fn summary(&self) -> Value {
        let mut per = serde_json::Map::new();
        for (i, name) in self.impls.iter().enumerate() {
            let s = self.score(i);
            per.insert(
                name.to_string(),
                json!({
                    "scored": s.scored,
                    "agree_with_rfc": s.agree,
                    "spurious_rejections": s.spurious_reject,
                    "spurious_ids": s.spurious_ids,
                    "undue_acceptances": s.undue_accept,
                    "undue_ids": s.undue_ids,
                    "claims_mismatch": s.claims_mismatch,
                    "claims_mismatch_ids": s.mismatch_ids,
                    "panics": s.panics,
                    "delegated": s.delegated,
                    "unsupported": s.unsupported,
                    "controls_ok": s.controls_ok,
                    "controls_run": s.controls_run,
                    "open_accept": s.open_accept,
                    "open_reject": s.open_reject,
                }),
            );
        }
        let count = |e: Expect| self.rows.iter().filter(|r| r.case.expect == e).count();
        json!({
            "cases": self.rows.len(),
            "expect_accept": count(Expect::Accept),
            "expect_reject": count(Expect::Reject),
            "open": count(Expect::Open),
            "divergent_cases": self.divergent_count(),
            "implementations": per,
        })
    }
}
