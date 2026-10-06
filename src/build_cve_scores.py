"""Build data/cve_scores.csv.gz: exploit-likelihood score per CVE, used to add asset-exposure context to incidents (see exposure.py).
Model = gradient boosting on CVSS vector components + description keyword flags (no vendor/product priors), trained on CVEs published up to --train-until (default 2022-12-31)
against CISA KEV labels; every CVE with a CVSS v3 score is scored. CVEs published after the cutoff are genuinely out-of-sample; older CVEs are in-sample, so for those
the KEV flag (ground truth) matters more than the score. Input: the CVE table built by the vuln-prioritization project (cves.csv.gz: cve, published, vendor, product, cvss, desc, v3_*, exploited).
Usage: python src/build_cve_scores.py path/to/cves.csv.gz"""
import sys, os, json, datetime, warnings; warnings.filterwarnings("ignore")
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
sys.path.insert(0, os.path.dirname(__file__)); import vuln_features as F, exposure as EX
ROOT = os.path.join(os.path.dirname(__file__), "..")
def main(path, cutoff="2022-12-31"):
    d = pd.read_csv(path, low_memory=False); d = d[d.cvss.notna()].reset_index(drop=True); tr = d[d.published <= cutoff]
    cols = [c for c in F.prep(tr.head(5)).columns if c != "year"]
    m = HistGradientBoostingClassifier(random_state=42, learning_rate=.05, max_iter=200, max_leaf_nodes=15, l2_regularization=5, categorical_features="from_dtype")
    m.fit(F.prep(tr)[cols], tr.exploited); d["risk_score"] = m.predict_proba(F.prep(d)[cols])[:, 1]; d["risk_pct"] = d.risk_score.rank(pct=True)
    d["vuln_class"] = d.desc.map(lambda x: ",".join(EX.vuln_classes(x)))
    out = d.rename(columns={"exploited": "kev"})[["cve", "published", "vendor", "product", "cvss", "kev", "risk_score", "risk_pct", "vuln_class"]]
    out.to_csv(os.path.join(ROOT, "data/cve_scores.csv.gz"), index=False, float_format="%.5f"); meta_p = os.path.join(ROOT, "data/cve_data_meta.json"); meta = json.load(open(meta_p)) if os.path.exists(meta_p) else {}
    meta.update({"scores_built": datetime.date.today().isoformat(), "scored_cves": len(out), "cve_published_range": [out.published.min(), out.published.max()], "model_train_until": cutoff}); json.dump(meta, open(meta_p, "w"), indent=1)
    print(len(out), "CVEs scored;", int(out.kev.sum()), "KEV; trained on", len(tr), "CVEs published <=", cutoff)
if __name__ == "__main__": main(sys.argv[1])
