"""Compile the Sigma rules to SIEM queries: Splunk SPL, Microsoft Sentinel/Defender KQL, and Elasticsearch query DSL, and check the DSL locally.

Field names are the dataset's (Sysmon/Security field names: Image, CommandLine, EventID, ...). Real deployments must map them to the SIEM schema
(Splunk: EventID->EventCode; Elastic ECS: Image->process.executable, ...). Text matching is case-insensitive, as in Sigma.
Verification status (be precise when describing this project):
  * VERIFIED locally: the Elasticsearch DSL produced for every rule is evaluated by an independent mini-evaluator (dsl_mask, which only reads the DSL) and must return
    exactly the same events as the Sigma engine on all events. Regex atoms are exported as painless regex scripts and the local evaluator runs them with Python `re`, so
    Java-vs-Python regex differences are NOT covered by that check.
  * NOT run anywhere: the SPL and KQL text, and the DSL against a real Elasticsearch (see siem/load_and_verify.py, which you run yourself).
  * Aggregation rules export their selection exactly; the window stage is SPL streamstats (trailing window) / KQL tumbling bins / an Elastic threshold rule, which are
    approximations of the engine's sliding window (they alert on the same bursts but may flag a different subset of events).
Usage: python src/siem_export.py -> exported/{rules.kql, splunk_searches.spl, elastic_dsl.ndjson}; python src/siem_export.py --verify"""
import argparse, json, os, re, sys
from pathlib import Path
import pandas as pd
sys.path.insert(0, os.path.dirname(__file__)); import sigma_engine as S
ROOT = Path(__file__).resolve().parent.parent
NUM_OPS = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
AGG = S.AGG

# ---------- Sigma -> AST ----------
def atoms(key, val):
    field, *mods = key.split("|"); vals = val if isinstance(val, list) else [val]; op = next((m for m in mods if m in ("contains", "startswith", "endswith", "re", *NUM_OPS)), "eq")
    leaves = [("atom", field, op, v) for v in vals]
    return ("and" if "all" in mods else "or", leaves) if len(leaves) > 1 else leaves[0]
def selection_ast(sel):
    if isinstance(sel, list): return ("or", [selection_ast(m) for m in sel])
    parts = [atoms(k, v) for k, v in sel.items()]; return parts[0] if len(parts) == 1 else ("and", parts)
def condition_ast(cond, sels):
    toks = S.TOK.findall(cond); pos = [0]; peek = lambda: toks[pos[0]] if pos[0] < len(toks) else None
    def take(): t = toks[pos[0]]; pos[0] += 1; return t
    def atom():
        t = take()
        if t == "(": v = expr(); take(); return v
        if t == "not": return ("not", atom())
        if t in ("1", "all") and peek() == "of":
            take(); pat = take(); keys = list(sels) if pat == "them" else [k for k in sels if re.fullmatch(pat.replace("*", ".*"), k)]
            return ("or" if t == "1" else "and", [sels[k] for k in keys])
        return sels[t]
    def conj():
        v = [atom()]
        while peek() == "and": take(); v.append(atom())
        return v[0] if len(v) == 1 else ("and", v)
    def expr():
        v = [conj()]
        while peek() == "or": take(); v.append(conj())
        return v[0] if len(v) == 1 else ("or", v)
    return expr()
def rule_ast(rule):
    det = rule["detection"]; sels = {k: selection_ast(v) for k, v in det.items() if k not in ("condition", "timeframe")}; cond = det["condition"]; m = AGG.match(cond)
    agg = None
    if m: cond = m.group(1).strip(); agg = {"field": m.group(2), "by": m.group(3), "op": m.group(4), "n": int(m.group(5)), "timeframe": det["timeframe"]}
    return condition_ast(cond, sels), agg

# ---------- SPL (single `where` expression; match() is PCRE) ----------
def spl_str(s): return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'
def spl(n):
    if n[0] == "and": return "(" + " AND ".join(spl(x) for x in n[1]) + ")"
    if n[0] == "or": return "(" + " OR ".join(spl(x) for x in n[1]) + ")"
    if n[0] == "not": return "NOT " + spl(n[1])
    _, f, op, v = n
    if op in NUM_OPS: return f"tonumber({f}){NUM_OPS[op]}{v}"
    if op == "eq": return f"isnull({f})" if v is None else (f"{f}={v}" if isinstance(v, int) else f"lower({f})={spl_str(str(v).lower())}")
    pat = {"contains": re.escape(str(v)), "startswith": "^" + re.escape(str(v)), "endswith": re.escape(str(v)) + "$", "re": str(v)}[op]
    return f"match({f}, {spl_str('(?i)' + pat)})"
def to_spl(rule):
    ast, agg = rule_ast(rule); q = f"index=windows | where {spl(ast)}"
    if agg:
        fn = f"dc({agg['field']})" if agg["field"] else "count"
        q += f" | sort 0 _time | streamstats time_window={agg['timeframe']} {fn} as n {'by ' + agg['by'] if agg['by'] else ''} | where n{agg['op']}{agg['n']}"
    return q

# ---------- KQL ----------
def kql_str(s): return '@"' + str(s).replace('"', '""') + '"'
def kql(n):
    if n[0] == "and": return "(" + " and ".join(kql(x) for x in n[1]) + ")"
    if n[0] == "or": return "(" + " or ".join(kql(x) for x in n[1]) + ")"
    if n[0] == "not": return "not(" + kql(n[1]) + ")"
    _, f, op, v = n
    if op in NUM_OPS: return f"toreal({f}) {NUM_OPS[op]} {v}"
    if op == "eq": return f"isempty({f})" if v is None else (f"{f} == {v}" if isinstance(v, int) else f"{f} =~ {kql_str(v)}")
    if op == "re": return f"{f} matches regex {kql_str('(?i)' + str(v))}"
    return f"{f} {op} {kql_str(v)}"            # contains / startswith / endswith are case-insensitive in KQL
def to_kql(rule):
    ast, agg = rule_ast(rule); q = f"SecurityEvent\n| where {kql(ast)}"
    if agg:
        fn = f"dcount({agg['field']})" if agg["field"] else "count()"
        q += f"\n| summarize n = {fn} by {agg['by'] + ', ' if agg['by'] else ''}bin(TimeGenerated, {agg['timeframe']})\n| where n {agg['op']} {agg['n']}    // tumbling-window approximation"
    return q

# ---------- Elasticsearch DSL ----------
def wc(s): return re.sub(r"([*?\\])", r"\\\1", str(s))
def dsl(n):
    if n[0] == "and": return {"bool": {"filter": [dsl(x) for x in n[1]]}}
    if n[0] == "or": return {"bool": {"should": [dsl(x) for x in n[1]], "minimum_should_match": 1}}
    if n[0] == "not": return {"bool": {"must_not": [dsl(n[1])]}}
    _, f, op, v = n
    if op in NUM_OPS: return {"range": {f: {op: v}}}
    if op == "eq":
        if v is None: return {"bool": {"must_not": [{"exists": {"field": f}}]}}
        return {"term": {f: v}} if isinstance(v, int) else {"term": {f: {"value": str(v), "case_insensitive": True}}}
    if op == "re":
        return {"script": {"script": {"lang": "painless", "source": "def v = doc[params.f]; if (v.size() == 0) return false; return Pattern.compile(params.p).matcher(v.value).find();", "params": {"f": f, "p": "(?i)" + str(v)}}}}
    val = {"contains": f"*{wc(v)}*", "startswith": f"{wc(v)}*", "endswith": f"*{wc(v)}"}[op]
    return {"wildcard": {f: {"value": val, "case_insensitive": True}}}
def to_dsl(rule): return dsl(rule_ast(rule)[0])

# ---------- independent local evaluator of the DSL (reads only the DSL, never the Sigma rule) ----------
_COLS = {}
def dsl_mask(q, df):
    k, v = next(iter(q.items())); idx = df.index; cache = _COLS.setdefault(id(df), {})
    def col(f):
        if f not in cache: cache[f] = df[f].astype("string") if f in df.columns else pd.Series([pd.NA] * len(df), index=idx, dtype="string")
        return cache[f]
    if k == "bool":
        m = pd.Series(True, index=idx)
        for c in v.get("filter", []) + v.get("must", []): m &= dsl_mask(c, df)
        if "should" in v:
            s = pd.Series(False, index=idx)
            for c in v["should"]: s |= dsl_mask(c, df)
            m &= s
        for c in v.get("must_not", []): m &= ~dsl_mask(c, df)
        return m
    if k == "term":
        f, spec = next(iter(v.items())); val = spec["value"] if isinstance(spec, dict) else spec; s = col(f)
        if isinstance(val, int): return pd.to_numeric(s, errors="coerce").eq(val).fillna(False)
        return s.str.lower().eq(str(val).lower()).fillna(False)
    if k == "wildcard":
        f, spec = next(iter(v.items())); pat = re.sub(r"\\(.)", lambda m: "\x00" + m.group(1), spec["value"]); parts = pat.split("*")
        rx = "^" + ".*".join(re.escape(p.replace("\x00", "")) for p in parts) + "$"; return col(f).str.contains(rx, flags=re.I | re.S, regex=True, na=False)
    if k == "exists": return col(v["field"]).notna()
    if k == "range":
        f, spec = next(iter(v.items())); op, val = next(iter(spec.items())); x = pd.to_numeric(col(f), errors="coerce")
        return {"gt": x > val, "gte": x >= val, "lt": x < val, "lte": x <= val}[op].fillna(False)
    if k == "script":
        p = v["script"]["params"]; return col(p["f"]).str.contains(p["p"], regex=True, na=False)           # (?i) is inside the pattern, exactly as sent to Elasticsearch
    raise ValueError(f"unsupported DSL clause {k}")

def export(rules, out):
    out.mkdir(exist_ok=True); kq, sp, ds = [], [], []
    for r in rules:
        hdr = f"{r['id']} | {r['title']} | {','.join(S.techniques(r))} | level={r['level']}"
        kq.append(f"// {hdr}\n{to_kql(r)}\n"); sp.append(f"`# {hdr}`\n{to_spl(r)}\n"); ds.append(json.dumps({"rule": r["id"], "level": r["level"], "attack": S.techniques(r), "query": to_dsl(r)}))
    (out / "rules.kql").write_text("\n".join(kq)); (out / "splunk_searches.spl").write_text("\n".join(sp)); (out / "elastic_dsl.ndjson").write_text("\n".join(ds) + "\n")

def selection_only(rule):
    """for aggregation rules the window stage is not in the DSL, so compare against the engine's pre-aggregation mask"""
    det = dict(rule["detection"]); m = AGG.match(det["condition"])
    if m: det["condition"] = m.group(1).strip()
    return {**rule, "detection": det}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--verify", action="store_true"); a = ap.parse_args(); rules = S.load_rules(ROOT / "rules"); export(rules, ROOT / "exported")
    print(f"exported {len(rules)} rules -> exported/")
    if a.verify:
        ev = pd.read_pickle(ROOT / "data/events.pkl.gz"); res = []
        for r in rules:
            eng = S.evaluate(selection_only(r), ev); loc = dsl_mask(to_dsl(r), ev); res.append({"rule": r["id"], "engine_hits": int(eng.sum()), "dsl_hits": int(loc.sum()), "identical": bool((eng == loc).all()), "aggregation_rule": bool(AGG.match(r["detection"]["condition"]))})
            print(res[-1])
        (ROOT / "exported" / "local_equivalence.json").write_text(json.dumps({"events": len(ev), "all_identical": all(x["identical"] for x in res), "rules": res}, indent=1))
        print("ALL IDENTICAL" if all(x["identical"] for x in res) else "MISMATCH")
