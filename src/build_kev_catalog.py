"""Build data/kev_catalog.csv.gz from CISA's Known Exploited Vulnerabilities JSON (git clone https://github.com/cisagov/kev-data).
Keeps the fields the exposure step uses: date added, CISA due date (the real remediation deadline), known-ransomware-use flag. Also writes data/cve_data_meta.json (freshness record).
Usage: python src/build_kev_catalog.py path/to/known_exploited_vulnerabilities.json"""
import json, sys, os, datetime
import pandas as pd
ROOT = os.path.join(os.path.dirname(__file__), "..")
def main(path):
    j = json.load(open(path)); v = pd.DataFrame(j["vulnerabilities"])
    out = pd.DataFrame({"cve": v.cveID, "vendor": v.vendorProject, "product": v.product, "name": v.vulnerabilityName, "date_added": v.dateAdded, "due_date": v.dueDate,
                        "ransomware": (v.knownRansomwareCampaignUse == "Known").astype(int), "short_description": v.shortDescription.str[:300]})
    out.to_csv(os.path.join(ROOT, "data/kev_catalog.csv.gz"), index=False)
    meta_p = os.path.join(ROOT, "data/cve_data_meta.json"); meta = json.load(open(meta_p)) if os.path.exists(meta_p) else {}
    meta.update({"kev_catalog_version": j.get("catalogVersion"), "kev_entries": len(out), "kev_built": datetime.date.today().isoformat()})
    json.dump(meta, open(meta_p, "w"), indent=1); print(len(out), "KEV entries, catalog", j.get("catalogVersion"))
if __name__ == "__main__": main(sys.argv[1])
