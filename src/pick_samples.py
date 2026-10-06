"""Copy a small random sample of DikeDataset PE files into plain folders for the binary-triage demo.
Malware: files the classifier did NOT see are preferred. 'Seen' = every sha256 in the classifier's data_external/dike_features.csv (the pool it was trained and tested on).
Benign: chosen at random; almost all 982 benign files were in that pool, and the few that are not are files the classifier's parser could not read, so they are not preferred.
Files are only copied, never opened or run.
  python src/pick_samples.py --dike ~/triage-samples/DikeDataset --features "$MALWARE_CLASSIFIER_DIR/data_external/dike_features.csv" --out ~/triage-samples"""
import argparse, random, shutil
from pathlib import Path
import pandas as pd

ap = argparse.ArgumentParser(); ap.add_argument("--dike", required=True); ap.add_argument("--features", required=True); ap.add_argument("--out", required=True)
ap.add_argument("--n-malware", type=int, default=40); ap.add_argument("--n-benign", type=int, default=250); ap.add_argument("--seed", type=int, default=7); a = ap.parse_args()
seen = set(pd.read_csv(Path(a.features).expanduser(), usecols=["sha256"]).sha256.astype(str)); rnd = random.Random(a.seed); out = Path(a.out).expanduser()
for label, n in (("malware", a.n_malware), ("benign", a.n_benign)):
    src = Path(a.dike).expanduser() / "files" / label
    fs = sorted(src.glob("*.exe")); rnd.shuffle(fs)
    unseen = [f for f in fs if f.stem not in seen]
    chosen = ((unseen + [f for f in fs if f.stem in seen]) if label == "malware" else fs)[:n]
    dst = out / label; dst.mkdir(parents=True, exist_ok=True)
    for f in chosen: shutil.copyfile(f, dst / f.name)
    n_unseen = sum(f.stem not in seen for f in chosen)
    print(f"{label}: {len(fs)} .exe available, {len(unseen)} not in the classifier's pool; copied {len(chosen)} to {dst} ({n_unseen} unseen, {len(chosen) - n_unseen} in the pool)")
