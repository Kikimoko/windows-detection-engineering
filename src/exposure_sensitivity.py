"""How does the exposure step behave when the estate is worse than the lab? Simulation of the POLICY (not proof that it improves outcomes).
For each scenario, hosts from the real alert table are given known-exploited CVEs with probability p (the rest get non-KEV CVEs); the pipeline is run with the raise
budget off (max_raise_share=1) and on (0.25), and the share of incidents lifted and the P1 share are recorded. KEV CVEs used are published before the incidents happened.
Usage: python src/exposure_sensitivity.py  ->  exposure_sensitivity.json  (first run builds data/alerts_cache.pkl, ~90 s)"""
import os, sys, json, tempfile, warnings; warnings.filterwarnings("ignore")
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(__file__)); import respond as R, exposure as X, sigma_engine as S
ROOT = R.ROOT
def alerts():
    p = ROOT / "data/alerts_cache.pkl"
    if p.exists(): return pd.read_pickle(p)
    A = R.alert_table(pd.read_pickle(ROOT / "data/events.pkl.gz"), S.load_rules(ROOT / "rules")); A.to_pickle(p); return A
def main(draws=20, seed=0):
    A = alerts(); hosts = sorted(A.host.unique()); rng = np.random.RandomState(seed); scores = X.load_scores(); kev = X.load_kev()
    old = scores[(scores.published < "2019-01-01")]; kev_pool = old.index[old.index.isin(kev.index)].tolist(); non_kev = old.index[~old.index.isin(kev.index)].tolist()
    res = []
    for p in (0.05, 0.10, 0.25, 0.50, 1.00):
        for cap in (1.0, 0.25):
            shares, p1s = [], []
            for d in range(draws):
                rng2 = np.random.RandomState(seed * 1000 + d); rows = []
                for h in hosts:
                    crit = rng2.choice(["low", "medium", "high", "critical"], p=[.3, .4, .2, .1]); net = rng2.rand() < 0.1
                    rows.append((h, rng2.choice(kev_pool) if rng2.rand() < p else rng2.choice(non_kev), crit, "yes" if net else "no"))
                inv = pd.DataFrame(rows, columns=["host", "cve_id", "criticality", "internet_facing"])
                m = R.run(out_dir=tempfile.mkdtemp(), alerts=A, inventory=inv, scores=scores, kev=kev, max_raise_share=cap)
                shares.append(m["raise_share"]); p1s.append(m["priority_counts"].get("P1", 0) / m["incidents"])
            res.append({"share_of_hosts_with_a_known_exploited_cve": p, "raise_budget": cap, "incidents_raised_mean": round(float(np.mean(shares)), 3), "incidents_raised_max": round(float(np.max(shares)), 3), "p1_share_mean": round(float(np.mean(p1s)), 3)})
            print(res[-1])
    base = R.run(out_dir=tempfile.mkdtemp(), alerts=A); res_base = base["priority_counts"].get("P1", 0) / base["incidents"]
    json.dump({"draws_per_cell": draws, "hosts": len(hosts), "incidents": base["incidents"], "p1_share_without_exposure": round(res_base, 3), "scenarios": res}, open(ROOT / "exposure_sensitivity.json", "w"), indent=1)
if __name__ == "__main__": main()
