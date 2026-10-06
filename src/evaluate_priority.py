"""Measure whether the exposure step actually helps, once analysts have given verdicts. THIS CANNOT BE RUN HONESTLY WITHOUT REAL VERDICTS: the Mordor data has no
analyst verdicts and no per-incident severity, so no effectiveness number is claimed in this project. The harness is ready for when you have them.
Inputs: a respond run made with --inventory (tickets/ carry `alert_priority_before_exposure` and the final `priority`) and a verdicts CSV with columns
  incident,severe      (1 = the incident turned out to be real and serious, 0 = not)
Reports, for P1 before exposure and P1 after exposure: precision (share of P1 incidents that were severe), recall (share of severe incidents that were P1), how many incidents exposure
lifted and how many of those were severe (precision of the lift itself). A useful exposure step raises recall without dropping precision much, and the lifted incidents should be severe more
often than the incidents left alone.
Usage: python src/evaluate_priority.py respond_run_exposure verdicts.csv"""
import json, sys
from pathlib import Path
import pandas as pd
def evaluate(run_dir, verdicts):
    v = pd.read_csv(verdicts) if not isinstance(verdicts, pd.DataFrame) else verdicts
    rows = []
    for f in Path(run_dir, "tickets").glob("*.json"):
        t = json.load(open(f)); rows.append({"incident": t["incident"], "after": t["priority"], "before": t.get("alert_priority_before_exposure", t["priority"])})
    d = pd.DataFrame(rows).merge(v, on="incident", how="inner")
    if d.empty: raise ValueError("no incident ids in common between the run and the verdicts")
    def pr(col):
        sel = d[d[col] == "P1"]; return {"p1_count": int(len(sel)), "precision": round(float(sel.severe.mean()), 3) if len(sel) else None, "recall": round(float(sel.severe.sum() / max(1, d.severe.sum())), 3)}
    lifted = d[d.before != d.after]; others = d[d.before == d.after]
    return {"incidents_with_verdicts": int(len(d)), "severe_incidents": int(d.severe.sum()), "p1_before_exposure": pr("before"), "p1_after_exposure": pr("after"), "incidents_lifted": int(len(lifted)),
            "severe_share_among_lifted": round(float(lifted.severe.mean()), 3) if len(lifted) else None, "severe_share_among_not_lifted": round(float(others.severe.mean()), 3) if len(others) else None}
if __name__ == "__main__": print(json.dumps(evaluate(sys.argv[1], sys.argv[2]), indent=1))
