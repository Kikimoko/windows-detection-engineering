"""Build data/events.pkl.gz from a sparse clone of OTRF/Security-Datasets (real Windows Sysmon + Security + PowerShell telemetry from attack simulations).
  git clone --depth 1 --filter=blob:none --no-checkout https://github.com/OTRF/Security-Datasets.git sds
  cd sds && git sparse-checkout init --cone && git sparse-checkout set datasets/atomic/_metadata \\
     datasets/atomic/windows/{credential_access,discovery,execution,persistence,privilege_escalation,defense_evasion,lateral_movement,collection,other}/host && git checkout
Usage: python src/build_events.py /path/to/sds
Each dataset ("run") is one attack simulation recorded on a lab Windows host; ground truth = the ATT&CK technique(s) in its metadata. Files are read as JSON text only."""
import sys, os, json, glob, zipfile, io, re
from multiprocessing import Pool
import pandas as pd, yaml
KEEP = ["Channel", "EventID", "Hostname", "TimeCreated", "EventTime", "UtcTime", "Image", "CommandLine", "ParentImage", "ParentCommandLine", "SourceImage", "TargetImage", "GrantedAccess", "CallTrace",
        "TargetObject", "Details", "EventType", "ImageLoaded", "TargetFilename", "User", "SourceUser", "TargetUser", "LogonType", "ServiceName", "ServiceFileName", "TaskName", "TaskContent", "NewProcessName",
        "ProcessName", "SubjectUserName", "TargetUserName", "ObjectName", "AccessMask", "Message", "ContextInfo", "Payload", "Application", "DestAddress", "DestPort", "SourceAddress", "ScriptBlockText",
        "OriginalFileName", "Hashes", "PipeName", "Destination", "Operation", "Consumer", "Filter", "Name", "Type", "QueryName", "DestinationIp", "DestinationPort", "IpAddress", "AuthenticationPackageName", "WorkstationName"]
def read_zip(path):
    run = path.split("/windows/")[1].replace("/host/", "__").replace("/", "_")[:-4]; rows = []
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if not n.endswith(".json"): continue
            for line in io.TextIOWrapper(z.open(n), encoding="utf-8", errors="ignore"):
                line = line.strip()
                if not line: continue
                try: d = json.loads(line)
                except Exception: continue
                r = {k: d.get(k) for k in KEEP if d.get(k) not in (None, "")}; r["run"] = run; rows.append(r)
    return rows
if __name__ == "__main__":
    root = sys.argv[1]; zips = sorted(glob.glob(f"{root}/datasets/atomic/windows/*/host/*.zip"))
    with Pool(2) as p: rows = [r for chunk in p.map(read_zip, zips) for r in chunk]
    df = pd.DataFrame(rows); df["Channel"] = df.Channel.str.lower(); df["EventID"] = pd.to_numeric(df.EventID, errors="coerce").astype("Int64")
    for c in df.columns:
        if df[c].dtype == object and c not in ("run",): df[c] = df[c].astype(str).where(df[c].notna(), None)
    # ground truth from the dataset metadata
    gt = {}
    for f in glob.glob(f"{root}/datasets/atomic/_metadata/*.yaml"):
        m = yaml.safe_load(open(f)); techs = sorted({a["technique"] + (("." + a["sub-technique"]) if a.get("sub-technique") else "") for a in (m.get("attack_mappings") or [])})
        for x in m.get("files", []):
            if x.get("type") == "Host" and "/windows/" in x["link"]: gt[x["link"].split("/windows/")[1].replace("/host/", "__").replace("/", "_")[:-4]] = {"title": m["title"], "techniques": techs, "tactics": sorted({t for a in (m.get("attack_mappings") or []) for t in a.get("tactics", [])})}
    meta = pd.DataFrame([{"run": r, **gt.get(r, {"title": None, "techniques": [], "tactics": []})} for r in sorted(df.run.unique())])
    meta["tool"] = meta.run.str.split("__").str[1].str.split("_").str[0]; meta["tactic_dir"] = meta.run.str.split("__").str[0]
    os.makedirs("data", exist_ok=True); df.to_pickle("data/events.pkl.gz"); meta.to_pickle("data/runs.pkl.gz")
    print("events", df.shape, "runs", len(meta), "runs without ground truth:", int((meta.techniques.str.len() == 0).sum())); print(meta.tool.value_counts().head(12).to_dict())
