"""Asset-exposure context for incidents: which known-exploited / likely-to-be-exploited CVEs are open on the affected host, and whether they matter for THIS incident.

Inputs
  inventory  : a scanner export. Columns are auto-detected (host: host/hostname/devicename/dns name/asset/fqdn; cve: cve/cve_id/cveid/cves, several CVEs per cell allowed,
               so Nessus/Qualys/Defender-style CSVs load as they are). Optional columns: criticality (low|medium|high|critical), internet_facing (yes/no),
               first_seen, patched_date, owner. Missing optional columns default to criticality=medium, internet_facing=no.
  scores     : data/cve_scores.csv.gz (build_cve_scores.py): CVSS, exploit-likelihood score and percentile, vulnerability class, optional EPSS (data/epss.csv.gz, see README).
  kev        : data/kev_catalog.csv.gz (build_kev_catalog.py): CISA KEV with the real due date and known-ransomware-use flag.
Per incident (assess):
  * a CVE counts only if it was published before the incident, was first seen on the host before it (when first_seen is given) and was not patched before it;
  * relevance: the CVE's vulnerability class (from its description) is mapped to the ATT&CK tactics an attacker exploiting it would show (CLASS_TACTICS, an analyst
    judgement, coarse); RELEVANT = overlap with the incident's tactics;
  * tier: CRITICAL = KEV-listed CVE that is relevant to the incident, or on a critical/high asset, or internet-facing, or used in ransomware; HIGH = any other KEV CVE, or a
    relevant CVE in the top 5% of exploit likelihood (model or EPSS); NONE otherwise.
Priority: CRITICAL lifts an incident one level, HIGH lifts P3->P2; never lowers. Because most hosts in a real estate carry SOME known-exploited CVE, raises are BUDGETED:
only the strongest candidates (budget_raises) are lifted, up to max_share of all incidents; the rest keep their priority but still get the patch recommendation."""
import re, datetime
import numpy as np, pandas as pd
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
RANK = ["P3", "P2", "P1"]; HIGH_PCT = 0.95; CRIT_W = {"low": 0, "medium": 1, "high": 2, "critical": 3}
CLASS_TACTICS = {   # vulnerability class -> tactics an attacker exploiting it would show on the host (analyst judgement)
    "rce": {"execution", "lateral_movement", "persistence"}, "cmdi": {"execution", "persistence"}, "deser": {"execution", "persistence"}, "upload": {"execution", "persistence"},
    "uaf": {"execution", "persistence", "privilege_escalation"}, "privesc": {"privilege_escalation", "credential_access", "defense_evasion", "persistence"},
    "authbypass": {"credential_access", "lateral_movement"}, "unauth": {"lateral_movement", "discovery"}, "ssrf": {"lateral_movement", "credential_access"},
    "traversal": {"credential_access", "discovery"}, "sqli": {"credential_access", "discovery"}, "xss": set()}
KW = {"rce": r"remote code execution|arbitrary code|execute arbitrary|code execution", "unauth": r"unauthenticated|without authentication",
      "authbypass": r"authentication bypass|bypass authentication|improper authentication", "deser": r"deserializ", "sqli": r"sql injection", "cmdi": r"command injection|os command",
      "traversal": r"path traversal|directory traversal", "uaf": r"use[- ]after[- ]free|memory corruption|buffer overflow|out-of-bounds", "privesc": r"privilege|elevation",
      "xss": r"cross-site scripting|\bxss\b", "ssrf": r"server-side request forgery|\bssrf\b", "upload": r"file upload|arbitrary file"}
def vuln_classes(desc):
    d = str(desc or "").lower(); return sorted(k for k, p in KW.items() if re.search(p, d))
def tactics_of(classes):
    out = set()
    for c in (classes.split(",") if isinstance(classes, str) else classes):
        out |= CLASS_TACTICS.get(c.strip(), set())
    return out

# ---------------- loading ----------------
def load_scores(path=None):
    s = pd.read_csv(path or ROOT / "data/cve_scores.csv.gz").drop_duplicates("cve").set_index("cve")
    epss = ROOT / "data/epss.csv.gz"                                   # optional: not downloadable from the build environment, see README
    if path is None and epss.exists():
        e = pd.read_csv(epss, comment="#").rename(columns=str.lower); e = e.drop_duplicates("cve").set_index("cve")[["epss", "percentile"]].rename(columns={"percentile": "epss_pct"}); s = s.join(e)
    return s
def load_kev(path=None):
    p = Path(path) if path else ROOT / "data/kev_catalog.csv.gz"
    return pd.read_csv(p).drop_duplicates("cve").set_index("cve") if p.exists() else pd.DataFrame(columns=["vendor", "product", "name", "date_added", "due_date", "ransomware"])
def data_freshness(asof=None):
    import json
    p = ROOT / "data/cve_data_meta.json"; asof = pd.Timestamp(asof or datetime.date.today())
    if not p.exists(): return {"known": False}
    m = json.load(open(p)); age = {k: (asof - pd.Timestamp(m[k])).days for k in ("kev_built", "scores_built") if k in m}
    return {"known": True, **m, "age_days": age, "stale": any(v > 14 for v in age.values())}
ALIASES = {"host": ["host", "hostname", "host name", "devicename", "device name", "dns name", "fqdn", "computername", "asset", "asset name", "netbios name"],
           "cve_id": ["cve_id", "cve", "cveid", "cve id", "cves"], "criticality": ["criticality", "asset_criticality", "asset criticality", "tier"],
           "internet_facing": ["internet_facing", "internet facing", "external", "exposed"], "first_seen": ["first_seen", "first seen", "first discovered", "first_detected"],
           "patched_date": ["patched_date", "patched", "remediated_date", "fixed_date"], "owner": ["owner", "asset owner", "team"]}
def load_inventory(src):
    """src = CSV path, DataFrame, or legacy dict host -> [cve ids]. Returns a normalised DataFrame."""
    if isinstance(src, dict): d = pd.DataFrame([(h, c) for h, cs in src.items() for c in cs], columns=["host", "cve_id"])
    else: d = src.copy() if isinstance(src, pd.DataFrame) else pd.read_csv(src)
    norm = lambda x: re.sub(r"[^a-z0-9]", "", str(x).lower()); low = {norm(c): c for c in d.columns}; ren = {}          # 'Internet Facing', 'internet_facing', 'InternetFacing' all match
    for k, names in ALIASES.items():
        for n in names:
            if norm(n) in low: ren[low[norm(n)]] = k; break
    d = d.rename(columns=ren)
    if "host" not in d or "cve_id" not in d: raise ValueError(f"inventory needs a host column and a CVE column; found {list(d.columns)}")
    h = d.host.astype(str).str.lower().str.strip(); d["host"] = h.where(h.str.fullmatch(r"\d{1,3}(\.\d{1,3}){3}"), h.str.split(".").str[0])      # FQDN -> short name; IPs stay whole (incident hosts are names, so an IP-keyed inventory needs a hostname column to join)
    d["cve_id"] = d.cve_id.astype(str).str.upper().str.findall(r"CVE-\d{4}-\d{4,7}"); d = d.explode("cve_id").dropna(subset=["cve_id"])
    crit = d["criticality"].astype(str).str.lower() if "criticality" in d else pd.Series("medium", index=d.index)
    d["criticality"] = crit.where(crit.isin(CRIT_W), "medium")
    d["internet_facing"] = d["internet_facing"].astype(str).str.lower().isin(["yes", "true", "1", "y"]) if "internet_facing" in d else False
    for c in ("first_seen", "patched_date"): d[c] = pd.to_datetime(d[c], errors="coerce") if c in d else pd.NaT
    if "owner" not in d: d["owner"] = ""
    d["owner"] = d.owner.fillna("")
    return d.drop_duplicates(["host", "cve_id"]).reset_index(drop=True)[["host", "cve_id", "criticality", "internet_facing", "first_seen", "patched_date", "owner"]]

# ---------------- assessment ----------------
def _cve_row(cve, r, scores, kev):
    s = scores.loc[cve] if cve in scores.index else None; k = kev.loc[cve] if cve in kev.index else None
    is_kev = k is not None or (s is not None and int(s.get("kev", 0) or 0) == 1)
    pub = pd.Timestamp(s["published"]) if s is not None and "published" in s and pd.notna(s["published"]) else pd.NaT
    classes = str(s["vuln_class"]) if s is not None and "vuln_class" in s and pd.notna(s["vuln_class"]) else ""
    pct = max(float(s["risk_pct"]) if s is not None and "risk_pct" in s and pd.notna(s["risk_pct"]) else 0.0, float(s["epss_pct"]) if s is not None and "epss_pct" in s and pd.notna(s["epss_pct"]) else 0.0)
    return {"cve": cve, "kev": bool(is_kev), "ransomware": bool(k is not None and int(k.get("ransomware", 0))), "due_date": (pd.Timestamp(k["due_date"]) if k is not None and pd.notna(k.get("due_date")) else pd.NaT),
            "cvss": float(s["cvss"]) if s is not None and pd.notna(s.get("cvss")) else None, "risk_score": float(s["risk_score"]) if s is not None and pd.notna(s.get("risk_score")) else None, "likelihood_pct": pct,
            "classes": classes, "published": pub, "criticality": r.criticality, "internet_facing": bool(r.internet_facing), "owner": r.owner}
def assess(host, inv, scores, kev=None, ts=None, tactics=()):
    """inv: normalised inventory DataFrame. ts: incident time (Timestamp). tactics: raw tactic keys of the incident (credential_access, ...)."""
    kev = kev if kev is not None else load_kev(); ts = pd.Timestamp(ts) if ts is not None else None; tactics = set(tactics)
    rows = inv[inv.host == str(host).lower()]; items, skipped = [], {"not_yet_published": 0, "patched_before": 0, "not_yet_seen": 0}
    for r in rows.itertuples():
        if ts is not None and pd.notna(r.patched_date) and r.patched_date <= ts: skipped["patched_before"] += 1; continue
        if ts is not None and pd.notna(r.first_seen) and r.first_seen > ts: skipped["not_yet_seen"] += 1; continue
        it = _cve_row(r.cve_id, r, scores, kev)
        if ts is not None and pd.notna(it["published"]) and it["published"] > ts: skipped["not_yet_published"] += 1; continue
        it["relevant"] = bool(tactics & tactics_of(it["classes"])); items.append(it)
    if not items: return {"tier": "NONE", "open_cves": 0, "kev_cves": [], "top": [], "relevant": False, "skipped": skipped, "strength": (0,) * 6, "cves_without_score": []}
    def strength(it): return (int(it["kev"] and it["relevant"]), int(it["kev"]), int(it["ransomware"]), CRIT_W.get(it["criticality"], 1), int(it["internet_facing"]), it["likelihood_pct"])
    items.sort(key=strength, reverse=True); best = items[0]; kev_items = [i for i in items if i["kev"]]
    crit = any(i["kev"] and (i["relevant"] or i["ransomware"] or CRIT_W.get(i["criticality"], 1) >= 2 or i["internet_facing"]) for i in items)
    high = bool(kev_items) or any(i["relevant"] and i["likelihood_pct"] >= HIGH_PCT for i in items)
    tier = "CRITICAL" if crit else ("HIGH" if high else "NONE")
    def dd(i): return None if pd.isna(i["due_date"]) else i["due_date"].date().isoformat()
    top = [{"cve": i["cve"], "kev": i["kev"], "cvss": i["cvss"], "risk_score": None if i["risk_score"] is None else round(i["risk_score"], 3), "relevant": i["relevant"], "ransomware": i["ransomware"],
            "criticality": i["criticality"], "internet_facing": i["internet_facing"], "patch_due": dd(i),
            "overdue_at_incident": bool(ts is not None and pd.notna(i["due_date"]) and ts > i["due_date"])} for i in items[:3]]
    return {"tier": tier, "open_cves": len(items), "kev_cves": [i["cve"] for i in kev_items], "top": top, "relevant": any(i["relevant"] for i in items), "skipped": skipped,
            "strength": strength(best), "cves_without_score": [i["cve"] for i in items if i["risk_score"] is None and not i["kev"]]}

def adjust(priority, tier):
    if tier == "CRITICAL": return RANK[min(RANK.index(priority) + 1, 2)]
    if tier == "HIGH" and priority == "P3": return "P2"
    return priority
def budget_raises(expos, max_share=0.25):
    """expos: list of assessments (one per incident). Returns the set of indexes whose raise is granted: strongest candidates first, at most max_share of all incidents."""
    cand = [i for i, e in enumerate(expos) if e and e["tier"] in ("CRITICAL", "HIGH") and e.get("would_raise", True)]
    cand.sort(key=lambda i: (expos[i]["tier"] == "CRITICAL", expos[i]["strength"]), reverse=True)
    return set(cand[: int(np.ceil(max_share * len(expos)))]) if max_share is not None and max_share < 1 else set(cand)

def remediation_queue(inv, scores, kev, hosts, incident_ids=None, asof=None):
    """Per host x CVE remediation list for hosts that had incidents: KEV first, then ransomware, asset criticality, internet exposure, likelihood; with CISA due date and overdue days as of `asof`."""
    asof = pd.Timestamp(asof or datetime.date.today()); rows = []
    for r in inv[inv.host.isin([h.lower() for h in hosts])].itertuples():
        if pd.notna(r.patched_date) and r.patched_date <= asof: continue
        it = _cve_row(r.cve_id, r, scores, kev); od = int((asof - it["due_date"]).days) if pd.notna(it["due_date"]) and asof > it["due_date"] else 0
        rows.append({"host": r.host, "cve": it["cve"], "kev": it["kev"], "ransomware_used": it["ransomware"], "cvss": it["cvss"], "likelihood_pct": round(it["likelihood_pct"], 3), "criticality": it["criticality"],
                     "internet_facing": it["internet_facing"], "owner": it["owner"], "cisa_due_date": None if pd.isna(it["due_date"]) else it["due_date"].date().isoformat(), "days_overdue": od,
                     "linked_incidents": ";".join((incident_ids or {}).get(r.host, []))})
    q = pd.DataFrame(rows)
    if q.empty: return q
    q["_k"] = list(zip(q.kev, q.ransomware_used, q.criticality.map(CRIT_W), q.internet_facing, q.likelihood_pct)); q = q.sort_values("_k", ascending=False).drop(columns="_k").reset_index(drop=True)
    q.insert(0, "rank", q.index + 1); return q
