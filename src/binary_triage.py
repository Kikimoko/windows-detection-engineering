"""Binary triage for incidents: a static PE malware score (and optional YARA hits) for the executables tied to an incident's host.

Where it sits in the pipeline (see respond.py): after alerts are grouped into incidents, each incident's host is joined to a manifest of executables
(files collected from that host), every file is scored by the static classifier from the malware-classifier project, and the result can
(a) lift the incident's priority by at most one level, (b) add a sandbox-analysis step to the ticket. It never lowers a priority and never confirms or closes anything.

Why it is a bounded, soft signal and not a verdict (measured in the malware-classifier project, see its README):
  * on a source the model never saw, the training-source threshold gave 3-43 % benign false alarms, so a score above the model's own threshold is only a lead;
  * forging a handful of header/section fields hides most malware from the model (recall 7.5-17 % after forging all 8 tested fields), so a LOW score proves nothing -
    which is why a low score never lowers anything;
  * the cutoff must be calibrated on benign files from the deployment environment (`calibrate_threshold`); without that, the strongest tier is unreachable
    unless YARA independently agrees.

Manifest (CSV or DataFrame), columns auto-detected: host (host/hostname/computername/...), path (path/file/filepath/image/sample); optional first_seen
(when the file appeared on the host; files without it are scored but can never reach the strongest tier on the model alone).
Files are only ever parsed, never executed. Treat the manifest's files as hostile: score them on an analysis machine, not on a production host.
Tiers: CRITICAL = flagged AND (a YARA rule matches OR (threshold calibrated on benign files AND the file's time is known)); HIGH = flagged otherwise; NONE = not flagged / not scorable.
Priority: CRITICAL lifts one level, HIGH lifts P3 -> P2 only; budgeted with exposure.budget_raises exactly like the vulnerability-exposure step."""
import hashlib, importlib.util, re, sys
from pathlib import Path
import numpy as np, pandas as pd
RANK = ["P3", "P2", "P1"]
MAX_BYTES = 64 * 2 ** 20                     # files larger than this are skipped (the classifier parses headers; huge installers are not its domain)
ALIASES = {"host": ["host", "hostname", "host name", "computername", "computer name", "devicename", "device name", "fqdn", "asset"],
           "path": ["path", "file", "filepath", "file path", "filename", "image", "sample", "binary"],
           "first_seen": ["first_seen", "first seen", "seen", "observed", "timestamp", "created"]}

# ---------------- loading ----------------
def load_manifest(src):
    """src = CSV path or DataFrame. Returns host (short, lower-case), path, first_seen (datetime or NaT)."""
    base = None if isinstance(src, pd.DataFrame) else Path(src).resolve().parent         # relative paths in a CSV are relative to the CSV's own folder, not to wherever the script is run
    d = src.copy() if isinstance(src, pd.DataFrame) else pd.read_csv(src)
    norm = lambda x: re.sub(r"[^a-z0-9]", "", str(x).lower()); low = {norm(c): c for c in d.columns}; ren = {}
    for k, names in ALIASES.items():
        for n in names:
            if norm(n) in low: ren[low[norm(n)]] = k; break
    d = d.rename(columns=ren)
    if "host" not in d or "path" not in d: raise ValueError(f"binary manifest needs a host column and a path column; found {list(d.columns)}")
    h = d.host.astype(str).str.lower().str.strip(); d["host"] = h.where(h.str.fullmatch(r"\d{1,3}(\.\d{1,3}){3}"), h.str.split(".").str[0])
    d["path"] = d.path.astype(str)
    if base is not None: d["path"] = d.path.map(lambda p: p if Path(p).is_absolute() or re.match(r"^[A-Za-z]:[\\/]", p) else str(base / p))
    d["first_seen"] = pd.to_datetime(d["first_seen"], errors="coerce") if "first_seen" in d else pd.NaT
    return d.drop_duplicates(["host", "path"]).reset_index(drop=True)[["host", "path", "first_seen"]]

def safe_name(path, n=60):
    """file names are attacker-controlled: keep a short, printable, instruction-free token (it is passed to tickets and, as DATA, to any LLM)."""
    return re.sub(r"[^\w .+()\[\]-]", "_", Path(str(path).replace("\\", "/")).name)[:n] or "unnamed"

# ---------------- scorers ----------------
class ClassifierScorer:
    """Wraps malware-classifier/src/predict.py. `classifier_dir` = the project folder (contains src/ and models/). The model bundle is loaded once.
    SECURITY: a .joblib bundle is a pickle; only load model files you built or trust."""
    name = "static-pe-classifier"
    def __init__(self, classifier_dir):
        import joblib
        root = Path(classifier_dir); src = root / "src" / "predict.py"
        if not src.exists(): raise FileNotFoundError(f"{src} not found; pass the malware-classifier project folder")
        sys.path.insert(0, str(root / "src"))
        try:
            spec = importlib.util.spec_from_file_location("_mc_predict", src); self._mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(self._mod)
        finally:
            sys.path.remove(str(root / "src"))
        self.bundle = joblib.load(root / "models" / "multisource_rich.joblib"); self.threshold = float(self.bundle["threshold"])
    def __call__(self, path):
        prob, f, thr = self._mod.predict(path, self.bundle)
        keys = ("SectionsMaxEntropy", "ImportsNb", "ResourcesNb", "NumberOfSections")
        return {"score": float(prob), "signals": {k: round(float(f[k]), 2) for k in keys if k in f}}

class YaraScanner:
    """Optional. Compiles every .yar/.yara file in `rules_dir`. If yara-python is missing, `available` is False and the layer is skipped (reported in the metrics)."""
    def __init__(self, rules_dir):
        self.available = False; self.rules = None
        try: import yara
        except ImportError: return
        files = {p.stem: str(p) for p in Path(rules_dir).glob("*.yar*")}
        if files: self.rules = yara.compile(filepaths=files); self.available = True
    def __call__(self, path):
        return sorted({m.rule for m in self.rules.match(str(path))}) if self.available else []

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""): h.update(chunk)
    return h.hexdigest()

def score_manifest(man, scorer, yara_scan=None):
    """Score each distinct file once (cache by SHA-256). Failures are recorded, never raised: an unparseable or missing file simply carries no signal."""
    rows, cache = [], {}
    for r in man.itertuples():
        rec = {"host": r.host, "name": safe_name(r.path), "first_seen": r.first_seen, "sha256": None, "score": np.nan, "yara": [], "error": None}
        try:
            p = Path(r.path)
            if not p.is_file(): raise FileNotFoundError("file not found")
            if p.stat().st_size > MAX_BYTES: raise ValueError("file too large")
            rec["sha256"] = sha256_of(p)
            if rec["sha256"] not in cache:
                res = scorer(str(p)); cache[rec["sha256"]] = (float(res["score"]), yara_scan(str(p)) if yara_scan is not None else [])
            rec["score"], rec["yara"] = cache[rec["sha256"]]
        except Exception as e: rec["error"] = f"{type(e).__name__}: {str(e)[:80]}"
        rows.append(rec)
    return pd.DataFrame(rows, columns=["host", "name", "first_seen", "sha256", "score", "yara", "error"])

def calibrate_threshold(benign_scores, fpr=0.01, min_files=100):
    """Cutoff such that about `fpr` of benign files from the deployment environment score above it. A 1 % rate cannot be estimated from fewer than ~100 files."""
    s = np.asarray([x for x in benign_scores if x == x], dtype=float)
    if len(s) < min_files: raise ValueError(f"need at least {min_files} scored benign files to calibrate a {fpr:.0%} false-alarm cutoff, got {len(s)}")
    return float(np.quantile(s, 1 - fpr))

# ---------------- assessment ----------------
def assess(host, scored, ts_first, ts_last, threshold, calibrated=False, lookback_h=24, slack_min=10):
    """Files count toward an incident when they sit on its host and (if their first_seen is known) appeared between `lookback_h` hours before the incident and `slack_min` minutes after
    it ended: an executable that has sat on the host for weeks is baseline software, not incident evidence."""
    rows = scored[scored.host == str(host).lower()]; skipped = {"outside_time_window": 0}; use = []
    lo, hi = pd.Timestamp(ts_first) - pd.Timedelta(hours=lookback_h), pd.Timestamp(ts_last) + pd.Timedelta(minutes=slack_min)
    for r in rows.itertuples():
        if pd.notna(r.first_seen) and not (lo <= r.first_seen <= hi): skipped["outside_time_window"] += 1; continue
        use.append(r)
    is_err = lambda r: isinstance(r.error, str)                          # pandas turns None into NaN (truthy) once the column holds any string
    errors = [r for r in use if is_err(r)]; ok = [r for r in use if not is_err(r) and r.score == r.score]
    flagged = [r for r in ok if r.score >= threshold]; flagged.sort(key=lambda r: (len(r.yara) > 0, r.score), reverse=True)
    def strong(r): return len(r.yara) > 0 or (calibrated and pd.notna(r.first_seen))
    tier = "CRITICAL" if any(strong(r) for r in flagged) else ("HIGH" if flagged else "NONE")
    top = [{"name": r.name, "sha256": r.sha256, "score": round(r.score, 4), "yara": list(r.yara), "time_known": bool(pd.notna(r.first_seen))} for r in flagged[:3]]
    return {"tier": tier, "files_considered": len(use), "files_scored": len(ok), "files_flagged": len(flagged), "files_unscorable": len(errors), "threshold": round(float(threshold), 4),
            "calibrated": bool(calibrated), "top": top, "skipped": skipped, "strength": (int(tier == "CRITICAL"), int(any(len(r.yara) for r in flagged)), max((r.score for r in flagged), default=0.0))}

def adjust(priority, tier):
    """CRITICAL lifts one level, HIGH lifts P3 -> P2; never lowers."""
    if tier == "CRITICAL": return RANK[min(RANK.index(priority) + 1, 2)]
    if tier == "HIGH" and priority == "P3": return "P2"
    return priority

def sentence(bt, alert_priority, policy_priority):
    """one analyst-readable sentence for the template summary (no file names: they are attacker-controlled)."""
    t = bt["top"][0]; s = (f" Binary triage {bt['tier']}: {bt['files_flagged']} executable(s) flagged by the static classifier on this host (top score {t['score']:.2f} vs cutoff {bt['threshold']:.2f}, "
                           f"{'calibrated on benign files' if bt['calibrated'] else 'uncalibrated'}{'; YARA ' + ', '.join(t['yara']) if t['yara'] else ''}); a static score is triage, not a verdict.")
    if bt.get("raise_granted") and bt.get("would_raise"): s += f" Priority raised from {alert_priority} to {policy_priority}."
    elif bt.get("raise_denied"): s += " Priority raise withheld by the raise budget; the sandbox-analysis step stands."
    return s
