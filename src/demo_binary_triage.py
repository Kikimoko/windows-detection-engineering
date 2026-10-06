"""Demo harness for the binary-triage step. SYNTHETIC by construction: the Mordor runs contain no binaries, so this script PLACES real PE files from folders you give it onto the
hosts of the baseline incidents and remembers which incidents got a malware file. It then checks what the step did against that known placement.

What this measures: how the step behaves when the classifier meets files of known label on incident hosts (flag rate on malware, false-flag rate on benign, how often a flag
changes a priority). What it does NOT measure: whether binary triage improves real triage. The placement is artificial, and if the sample files were in the classifier's training
data the scores are optimistic - use files the model never saw if you can.

  make:   python src/demo_binary_triage.py make   --tickets respond_run/tickets --benign DIR --malware DIR --out demo [--seed 7] [--malware-share 0.5]
          -> demo/manifest.csv (run it with respond.py --binaries), demo/benign_calibration.csv (if >=100 spare benign files), demo/truth.csv
  report: python src/demo_binary_triage.py report --baseline respond_run/tickets --run respond_run_binaries/tickets --truth demo/truth.csv
Files are only read, never executed. Keep the samples outside cloud-synced folders and never open them."""
import argparse, json, random, sys
from pathlib import Path
import pandas as pd
RANK = ["P3", "P2", "P1"]; LOOKBACK_H, SLACK_MIN = 24, 10          # same window as binary_triage.assess (the defaults)

def tickets(d):
    rows = [json.load(open(f)) for f in sorted(Path(d).glob("INC-*.json"))]
    return pd.DataFrame([{"incident": t["incident"], "host": t["host"], "first_seen": pd.Timestamp(t["first_seen"]), "last_seen": pd.Timestamp(t["last_seen"]),
                          "priority": t["priority"], "tier": t.get("binary_triage", {}).get("tier", "NONE")} for t in rows])

def files(d): return sorted(p for p in Path(d).rglob("*") if p.is_file() and not p.name.startswith("."))

def make(a):
    T = tickets(a.tickets); rnd = random.Random(a.seed); ben, mal = files(a.benign), files(a.malware); rnd.shuffle(ben); rnd.shuffle(mal)
    reserve = ben[:150] if len(ben) >= 150 + 20 else []                      # spare benign files for calibrating the cutoff; never placed on a host
    ben = ben[len(reserve):]; idx = list(T.index); rnd.shuffle(idx)
    n_mal = min(len(mal), round(len(idx) * a.malware_share)); n_ben = min(len(ben), len(idx) - n_mal)
    placed = [(i, mal[k], 1) for k, i in enumerate(idx[:n_mal])] + [(i, ben[k], 0) for k, i in enumerate(idx[n_mal:n_mal + n_ben])]
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    man = pd.DataFrame([{"host": T.host[i], "path": str(p.resolve()), "first_seen": (T.first_seen[i] - pd.Timedelta(minutes=2)).isoformat(sep=" "), "label": lab, "incident": T.incident[i]}
                        for i, p, lab in placed])
    man[["host", "path", "first_seen"]].to_csv(out / "manifest.csv", index=False)
    man.to_csv(out / "placement.csv", index=False)
    if reserve: pd.DataFrame({"host": "calibration", "path": [str(p.resolve()) for p in reserve]}).to_csv(out / "benign_calibration.csv", index=False)
    # ground truth per incident = does ANY placed malware file fall inside the incident's window on its host (files placed for a neighbouring incident can)
    m = man[man.label == 1].copy(); m["first_seen"] = pd.to_datetime(m.first_seen); truth = []
    for r in T.itertuples():
        lo, hi = r.first_seen - pd.Timedelta(hours=LOOKBACK_H), r.last_seen + pd.Timedelta(minutes=SLACK_MIN)
        hit = m[(m.host.str.split(".").str[0].str.lower() == str(r.host).split(".")[0].lower()) & (m.first_seen >= lo) & (m.first_seen <= hi)]
        anyfile = man[(man.host == r.host) & (pd.to_datetime(man.first_seen) >= lo) & (pd.to_datetime(man.first_seen) <= hi)]
        truth.append({"incident": r.incident, "malware_in_window": int(len(hit) > 0), "any_file_in_window": int(len(anyfile) > 0)})
    pd.DataFrame(truth).to_csv(out / "truth.csv", index=False)
    print(f"incidents {len(T)}: placed {n_mal} malware + {n_ben} benign files; calibration set {len(reserve)} files; wrote {out}/manifest.csv, truth.csv, placement.csv"
          + ("" if reserve else "\n(note: fewer than 170 benign files, so no benign_calibration.csv; the cutoff stays the model's own and CRITICAL needs a YARA hit)"))

def report(a):
    B, R, Z = tickets(a.baseline), tickets(a.run), pd.read_csv(a.truth)
    D = B.merge(R[["incident", "priority", "tier"]], on="incident", suffixes=("_base", "_new")).merge(Z, on="incident")
    D["raised"] = [RANK.index(n) > RANK.index(b) for b, n in zip(D.priority_base, D.priority_new)]; D["raisable"] = D.priority_base != "P1"; D["flagged"] = D.tier_new != "NONE"
    D["lowered"] = [RANK.index(n) < RANK.index(b) for b, n in zip(D.priority_base, D.priority_new)]
    out = {"incidents": len(D), "priority_lowered_anywhere": int(D.lowered.sum())}
    for name, sub in (("malware_file_in_window", D[D.malware_in_window == 1]), ("no_malware_file_in_window", D[D.malware_in_window == 0])):
        r = sub[sub.raisable]
        out[name] = {"incidents": len(sub), "flagged": int(sub.flagged.sum()), "flag_rate": round(sub.flagged.mean(), 3) if len(sub) else None, "tiers": sub.tier_new.value_counts().to_dict(),
                     "raisable_incidents (not already P1)": len(r), "raised": int(r.raised.sum()), "raise_rate_of_raisable": round(r.raised.mean(), 3) if len(r) else None}
    print(json.dumps(out, indent=1)); Path(a.truth).with_name("report.json").write_text(json.dumps(out, indent=1))
    if out["priority_lowered_anywhere"]: sys.exit("BUG: a priority was lowered")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("make"); m.add_argument("--tickets", required=True); m.add_argument("--benign", required=True); m.add_argument("--malware", required=True)
    m.add_argument("--out", default="demo"); m.add_argument("--seed", type=int, default=7); m.add_argument("--malware-share", type=float, default=0.5)
    r = sub.add_parser("report"); r.add_argument("--baseline", required=True); r.add_argument("--run", required=True); r.add_argument("--truth", required=True)
    a = ap.parse_args(); make(a) if a.cmd == "make" else report(a)
