"""Measure false positives on BENIGN Windows telemetry (goodware baseline logs) - the missing piece of the attack-only evaluation.
Bring your own data: the recommended source is Nextron's evtx-baseline (clean Windows 10/11/Server logs with software installs and normal use;
the large files are GitHub release downloads, which were NOT reachable from the build environment, so this has not been run on real benign data).
Convert .evtx to JSON lines with the open-source `evtx_dump` (pip install evtx / cargo install evtx):  evtx_dump -o jsonl file.evtx > file.jsonl
Usage: python src/benign_baseline.py baseline/*.jsonl [--out benign_results.json]
Limits: evtx JSON has no rendered 'Message' text, so rules that match on Message (admin-share, DCSync GUIDs, machine-account filters) will under-fire here; the
report lists them. Alerts on benign hosts are false positives by definition (assuming the baseline really was clean)."""
import argparse, json, os, sys, warnings; warnings.filterwarnings("ignore")
import pandas as pd
sys.path.insert(0, os.path.dirname(__file__)); import sigma_engine as S
ROOT = os.path.join(os.path.dirname(__file__), "..")

def _scalar(v): return v.get("#text") if isinstance(v, dict) else v
def flatten(rec):
    e = rec.get("Event", rec); s = e.get("System", {}); d = e.get("EventData") or {}
    row = {"EventID": _scalar(s.get("EventID")), "Channel": str(s.get("Channel", "")).lower(), "Hostname": s.get("Computer"),
           "TimeCreated": (s.get("TimeCreated", {}).get("#attributes", {}) or {}).get("SystemTime")}
    if isinstance(d, dict): row.update({k: _scalar(v) for k, v in d.items() if not k.startswith("#")})
    if "NewProcessName" in row and "Image" not in row: pass           # rules check both Image and NewProcessName where relevant
    try: row["EventID"] = int(row["EventID"])
    except (TypeError, ValueError): pass
    return row

def load_jsonl(paths):
    rows = []
    for i, p in enumerate(paths):
        for line in open(p, errors="ignore"):
            line = line.strip()
            if not line: continue
            try: r = flatten(json.loads(line))
            except Exception: continue
            r["run"] = f"benign_{i}"; rows.append(r)
    return pd.DataFrame(rows)

def report(df, rules):
    rows = []; n = len(df)
    for r in rules:
        h = S.evaluate(r, df); uses_msg = "Message" in json.dumps(r["detection"])
        rows.append({"rule": r["id"], "alerts": int(h.sum()), "alerts_per_10k_events": round(10000 * h.sum() / max(1, n), 2), "uses_Message_field": uses_msg,
                     "example": df.loc[h].get("CommandLine", pd.Series(dtype=object)).dropna().astype(str).str[:120].head(2).tolist() if h.any() else []})
    return {"events": n, "total_alerts": sum(x["alerts"] for x in rows), "per_rule": rows}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("files", nargs="+"); ap.add_argument("--out", default="benign_results.json"); a = ap.parse_args()
    df = load_jsonl(a.files); R = report(df, S.load_rules(os.path.join(ROOT, "rules"))); json.dump(R, open(os.path.join(ROOT, a.out), "w"), indent=1)
    print(f"{R['events']:,} benign events, {R['total_alerts']} alerts"); [print(f"{x['rule']:40s} {x['alerts']:6d} {x['alerts_per_10k_events']:8.2f}/10k {'(Message-based: under-fires)' if x['uses_Message_field'] else ''}") for x in R["per_rule"]]
