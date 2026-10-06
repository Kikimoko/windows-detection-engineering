#!/usr/bin/env bash
# Refresh the vulnerability data used by the exposure step (run weekly; the pipeline warns when data is older than 14 days).
# 1) CISA KEV (real due dates, ransomware flag)   2) CVE list -> exploit-likelihood scores
set -euo pipefail
cd "$(dirname "$0")"
rm -rf /tmp/kev-data && git clone --depth 1 https://github.com/cisagov/kev-data.git /tmp/kev-data
python src/build_kev_catalog.py /tmp/kev-data/known_exploited_vulnerabilities.json
# Scores need the CVE table from the vuln-prioritization project (src/build_dataset.py <cvelistV5 clone> <kev-data clone> -> data/cves.csv.gz):
#   git clone --depth 1 https://github.com/CVEProject/cvelistV5.git /tmp/cvelist
#   python path/to/vuln-prioritization/src/build_dataset.py /tmp/cvelist /tmp/kev-data
[ -n "${1:-}" ] && python src/build_cve_scores.py "$1" || echo "(pass the path to cves.csv.gz as \$1 to also rebuild the scores)"
