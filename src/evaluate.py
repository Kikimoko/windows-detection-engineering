"""Evaluate Sigma-style detections against real Windows attack telemetry (OTRF Security-Datasets).
Unit of evaluation = one attack run (dataset) with ATT&CK ground truth from its metadata.
Split by attack TOOL, not randomly: rules are written/tuned using runs made with Empire and cmd ("dev"); every other tool (Covenant, PowerShell scripts, Metasploit, etc.) is held out ("test")
and scored once after the rules are frozen.
Metrics per rule: run-level recall on the technique(s) it targets, runs it fires on outside its target technique (off-target; chained attacks make this a noise *proxy*, not a true FPR),
alerts per 10k events, and overall run-level coverage of ground-truth techniques. Output: evaluation_results.json, reports/*.md"""
import json, sys, os, argparse, warnings; warnings.filterwarnings("ignore")
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(__file__)); import sigma_engine as S
ROOT = os.path.join(os.path.dirname(__file__), "..")
ap = argparse.ArgumentParser(); ap.add_argument("--split", choices=["dev", "test", "all"], default="dev"); ap.add_argument("--out", default=None); a = ap.parse_args()
ev = pd.read_pickle(os.path.join(ROOT, "data/events.pkl.gz")); runs = pd.read_pickle(os.path.join(ROOT, "data/runs.pkl.gz"))
runs = runs[runs.techniques.str.len() > 0].copy(); runs["bases"] = runs.techniques.apply(lambda l: sorted({t.split(".")[0] for t in l}))
runs["split"] = np.where(runs.tool.isin(["empire", "cmd"]), "dev", "test")
sel = runs if a.split == "all" else runs[runs.split == a.split]; ev = ev[ev.run.isin(sel.run)].reset_index(drop=True)
rules = S.load_rules(os.path.join(ROOT, "rules")); hits = {}
for r in rules: hits[r["id"]] = S.evaluate(r, ev)
H = pd.DataFrame(hits); H["run"] = ev.run.values
per_run = H.groupby("run").sum()            # alerts per run per rule
ev_per_run = ev.groupby("run").size()
rows = []; all_targets = set()
for r in rules:
    targets = {t.split(".")[0] for t in S.techniques(r)}; all_targets |= targets
    on = sel[sel.bases.apply(lambda b: bool(targets & set(b)))]; off = sel[~sel.bases.apply(lambda b: bool(targets & set(b)))]
    fired = per_run[r["id"]] > 0
    rows.append({"rule": r["id"], "level": r["level"], "targets": sorted(targets), "runs_with_target_technique": len(on), "detected": int(fired.reindex(on.run).sum()),
                 "recall_on_target_runs": round(float(fired.reindex(on.run).mean()), 3) if len(on) else None,
                 "fires_on_off_target_runs": int(fired.reindex(off.run).sum()), "off_target_runs": len(off), "off_target_rate": round(float(fired.reindex(off.run).mean()), 3),
                 "alerts_total": int(per_run[r["id"]].sum()), "alerts_per_10k_events": round(10000 * per_run[r["id"]].sum() / len(ev), 2)})
T = pd.DataFrame(rows)
# technique-level coverage: a run is "detected" for its ground truth if any rule whose targets include a ground-truth base technique fires
cov = []
for _, run in sel.iterrows():
    cand = [r["id"] for r in rules if {t.split(".")[0] for t in S.techniques(r)} & set(run.bases)]
    cov.append({"run": run.run, "tool": run.tool, "bases": run.bases, "has_rule_for_technique": bool(cand), "detected_by_targeted_rule": bool(cand) and bool((per_run.loc[run.run, cand] > 0).any()),
                "any_rule_fired": bool((per_run.loc[run.run] > 0).any())})
C = pd.DataFrame(cov)
R = {"split": a.split, "runs": len(sel), "events": len(ev), "rules": len(rules),
     "run_level": {"runs_whose_technique_has_a_rule": int(C.has_rule_for_technique.sum()), "detected_by_targeted_rule": int(C.detected_by_targeted_rule.sum()),
                   "recall_where_rule_exists": round(float(C[C.has_rule_for_technique].detected_by_targeted_rule.mean()), 3) if C.has_rule_for_technique.any() else None,
                   "overall_recall_all_runs": round(float(C.detected_by_targeted_rule.mean()), 3), "runs_with_any_alert": int(C.any_rule_fired.sum())},
     "per_rule": rows, "uncovered_techniques_in_runs": dict(pd.Series([b for l in C[~C.has_rule_for_technique].bases for b in l]).value_counts()),
     "missed_runs": C[C.has_rule_for_technique & ~C.detected_by_targeted_rule][["run", "tool", "bases"]].to_dict("records")}
print(f"split={a.split} runs={len(sel)} events={len(ev):,} rules={len(rules)}")
print(T[["rule", "runs_with_target_technique", "detected", "recall_on_target_runs", "fires_on_off_target_runs", "off_target_rate", "alerts_per_10k_events"]].to_string(index=False))
print(R["run_level"]); print("missed:", [(m["run"].split("__")[1][:45], m["bases"]) for m in R["missed_runs"]][:40]); print("no rule for:", R["uncovered_techniques_in_runs"])
if a.out: json.dump(R, open(os.path.join(ROOT, a.out), "w"), indent=1, default=str)
