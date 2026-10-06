"""Load the Windows events into a LOCAL Elasticsearch and verify each exported DSL query returns exactly as many hits as the Sigma engine.
Start Elasticsearch first:  docker compose -f siem/docker-compose.yml up -d     Then:  python siem/load_and_verify.py [--runs 40]
Standard library + pandas only. NOT RUN in the build environment (no Docker there): the local DSL-evaluator check in src/siem_export.py --verify is what was run.
The hit counts of aggregation rules compare the SELECTION stage only. Regex rules need script.painless.regex.enabled=true (set in the compose file)."""
import argparse, json, sys, urllib.request
from pathlib import Path
import pandas as pd
ROOT = Path(__file__).resolve().parent.parent; sys.path.insert(0, str(ROOT / "src"))
import sigma_engine as S, siem_export as X
ES = "http://127.0.0.1:9200"
def call(method, path, body=None, raw=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    return json.loads(urllib.request.urlopen(urllib.request.Request(ES + path, data, {"Content-Type": "application/x-ndjson" if raw is not None else "application/json"}, method=method), timeout=300).read())
if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--runs", type=int, default=40); a = ap.parse_args()
    ev = pd.read_pickle(ROOT / "data/events.pkl.gz"); keep = ev.run.drop_duplicates().head(a.runs); ev = ev[ev.run.isin(keep)].reset_index(drop=True)
    try: call("DELETE", "/winevents")
    except Exception: pass
    call("PUT", "/winevents", {"mappings": {"dynamic_templates": [{"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword", "ignore_above": 32000}}}], "properties": {"EventID": {"type": "long"}}}})
    lines = []
    for _, r in ev.iterrows():
        doc = {k: (v.item() if hasattr(v, "item") else v) for k, v in r.items() if pd.notna(v)}; lines += [json.dumps({"index": {"_index": "winevents"}}), json.dumps(doc, default=str)]
    for i in range(0, len(lines), 10000): call("POST", "/winevents/_bulk?refresh=false", raw=("\n".join(lines[i:i + 10000]) + "\n").encode())
    call("POST", "/winevents/_refresh"); res = []; ok = True
    for rule in S.load_rules(ROOT / "rules"):
        local = int(S.evaluate(X.selection_only(rule), ev).sum()); es = call("POST", "/winevents/_count", {"query": X.to_dsl(rule)})["count"]
        res.append({"rule": rule["id"], "local_hits": local, "elastic_hits": es, "match": local == es}); ok &= local == es; print(res[-1])
    Path(__file__).with_name("verification.json").write_text(json.dumps({"events_loaded": len(ev), "all_rules_match": ok, "rules": res}, indent=1)); print("ALL MATCH" if ok else "MISMATCH - investigate")
