"""Small Sigma-subset rule engine over a pandas DataFrame of Windows events.
Supported: named selections (map or list of maps = OR), field modifiers contains / startswith / endswith / re / all / gt / gte / lt / lte,
null checks, case-insensitive text matching, list values (OR), conditions with and / or / not / parentheses and '1 of sel*', 'all of sel*', '1 of them', 'all of them'.
Aggregation (Sigma v1 style): condition "selection | count([Field]) [by Group[,Group2]] >= N" with detection.timeframe (e.g. 60s, 5m). count(Field) counts DISTINCT values;
count() counts events. Every event inside a window that reaches the threshold is flagged. Not supported: near, temporal sequences."""
import re, warnings; warnings.filterwarnings("ignore", message="This pattern is interpreted as a regular expression")
from pathlib import Path
import pandas as pd, yaml

def _series(df, field):
    return df[field] if field in df.columns else pd.Series([None] * len(df), index=df.index, dtype=object)

def _match_one(s, mods, val):
    text = s.astype("string")
    if val is None: return s.isna()
    if "re" in mods: return text.str.contains(val, flags=re.I, regex=True, na=False)
    if any(m in mods for m in ("gt", "gte", "lt", "lte")):
        x = pd.to_numeric(s, errors="coerce"); op = [m for m in mods if m in ("gt", "gte", "lt", "lte")][0]
        return {"gt": x > val, "gte": x >= val, "lt": x < val, "lte": x <= val}[op].fillna(False)
    v = str(val)
    if "contains" in mods: return text.str.contains(re.escape(v), case=False, regex=True, na=False)
    if "startswith" in mods: return text.str.lower().str.startswith(v.lower(), na=False)
    if "endswith" in mods: return text.str.lower().str.endswith(v.lower(), na=False)
    if v.endswith("*") or v.startswith("*"):           # Sigma wildcard in plain equality
        pat = "^" + ".*".join(re.escape(p) for p in v.split("*")) + "$"; return text.str.contains(pat, flags=re.I, regex=True, na=False)
    return text.str.lower() == v.lower()

def eval_map(df, m):
    mask = pd.Series(True, index=df.index)
    for key, val in m.items():
        field, *mods = key.split("|"); s = _series(df, field)
        vals = val if isinstance(val, list) else [val]
        parts = [_match_one(s, mods, v) for v in vals]
        if "all" in mods: hit = parts[0]; [hit := hit & p for p in parts[1:]]
        else: hit = parts[0]; [hit := hit | p for p in parts[1:]]
        mask &= hit.fillna(False).astype(bool)
    return mask

def eval_selection(df, sel):
    if isinstance(sel, list):
        out = pd.Series(False, index=df.index)
        for m in sel: out |= eval_map(df, m)
        return out
    return eval_map(df, sel)

TOK = re.compile(r"\(|\)|[A-Za-z0-9_*]+")
def eval_condition(cond, sels):
    toks = TOK.findall(cond); pos = [0]
    peek = lambda: toks[pos[0]] if pos[0] < len(toks) else None
    def take(): t = toks[pos[0]]; pos[0] += 1; return t
    def pick(pattern): 
        keys = [k for k in sels if k not in ("condition",)] if pattern == "them" else [k for k in sels if re.fullmatch(pattern.replace("*", ".*"), k)]
        if not keys: raise ValueError(f"no selections match {pattern!r}")
        return [sels[k] for k in keys]
    def atom():
        t = take()
        if t == "(": v = expr(); take(); return v
        if t == "not": return ~atom()
        if t in ("1", "all") and peek() == "of":
            take(); pat = take(); ms = pick(pat)
            out = ms[0]
            for m in ms[1:]: out = (out | m) if t == "1" else (out & m)
            return out
        if t not in sels: raise ValueError(f"unknown selection {t!r}")
        return sels[t]
    def conj():
        v = atom()
        while peek() == "and": take(); v = v & atom()
        return v
    def expr():
        v = conj()
        while peek() == "or": take(); v = v | conj()
        return v
    out = expr()
    if pos[0] != len(toks): raise ValueError(f"trailing tokens in condition {cond!r}")
    return out

def timestamps(df):
    """Single UTC timeline: UtcTime, else EventTime shifted by the per-run offset observed on rows that have both, else TimeCreated."""
    utc = pd.to_datetime(_series(df, "UtcTime"), errors="coerce"); loc = pd.to_datetime(_series(df, "EventTime"), errors="coerce")
    tc = pd.to_datetime(_series(df, "TimeCreated"), errors="coerce", utc=True).dt.tz_localize(None)
    grp = df["run"] if "run" in df.columns else pd.Series(0, index=df.index)
    both = (utc.notna() & loc.notna()); off = (utc - loc)[both].dt.total_seconds().groupby(grp[both]).median()
    shifted = loc + pd.to_timedelta(grp.map(off.to_dict()).astype(float).fillna(0.0), unit="s")
    return utc.fillna(shifted).fillna(tc)

def _dur(s):
    m = re.fullmatch(r"(\d+)\s*([smhd])", str(s).strip().lower()); return pd.Timedelta(int(m.group(1)), {"s": "s", "m": "min", "h": "h", "d": "D"}[m.group(2)])

AGG = re.compile(r"^(.*?)\|\s*count\(\s*([A-Za-z0-9_]*)\s*\)\s*(?:by\s+([A-Za-z0-9_, ]+?)\s*)?(>=|>|<=|<|==)\s*(\d+)\s*$")
def aggregate(base, df, field, by, op, n, window):
    """Flag events in `base` that lie inside a sliding window (length `window`) whose count/distinct-count meets the threshold, per group key."""
    out = pd.Series(False, index=df.index)
    ts = timestamps(df); idx = base[base & ts.notna()].index
    if len(idx) == 0: return out
    sub = pd.DataFrame({"ts": ts[idx]}); keys = [k.strip() for k in by.split(",")] if by else []
    for k in keys: sub[k] = _series(df, k)[idx].astype("string").fillna("")
    if field: sub["_v"] = _series(df, field)[idx].astype("string").fillna("")
    cmp = {">=": lambda x: x >= n, ">": lambda x: x > n, "<=": lambda x: x <= n, "<": lambda x: x < n, "==": lambda x: x == n}[op]
    for _, g in (sub.groupby(keys, sort=False) if keys else [(None, sub)]):
        g = g.sort_values("ts"); tv = g.ts.values; vals = g["_v"].values if field else None; ids = g.index.values; lo = 0; cnt = {}
        for hi in range(len(g)):
            k = vals[hi] if field else hi; cnt[k] = cnt.get(k, 0) + 1
            while tv[hi] - tv[lo] > window.to_timedelta64():
                k0 = vals[lo] if field else lo; cnt[k0] -= 1
                if not cnt[k0]: del cnt[k0]
                lo += 1
            if cmp(len(cnt)): out.loc[ids[lo:hi + 1]] = True
    return out

def evaluate(rule, df):
    det = rule["detection"]; sels = {k: eval_selection(df, v) for k, v in det.items() if k not in ("condition", "timeframe")}
    cond = det["condition"]; m = AGG.match(cond)
    if m:
        base = eval_condition(m.group(1).strip(), sels).fillna(False).astype(bool)
        if "timeframe" not in det: raise ValueError("aggregation rule needs detection.timeframe")
        return aggregate(base, df, m.group(2), m.group(3), m.group(4), int(m.group(5)), _dur(det["timeframe"]))
    return eval_condition(cond, sels).fillna(False).astype(bool)

def load_rules(folder):
    rules = []
    for f in sorted(Path(folder).glob("*.yml")):
        r = yaml.safe_load(f.read_text()); r["_file"] = f.name; rules.append(r)
    return rules

def techniques(rule):
    return sorted({t.split(".", 1)[1].upper() for t in rule.get("tags", []) if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)})
