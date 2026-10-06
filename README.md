# Windows Detection Engineering on Real Attack Telemetry

21 Sigma-style detection rules (18 single-event + 3 aggregation), a small Sigma-subset engine, an alert-to-incident-to-SOAR pipeline, a SIEM exporter, and an evaluation on **real Windows event logs from 107 attack runs** (OTRF Security-Datasets / Mordor, Sysmon + Security + System + PowerShell channels, ~749k events). Everything is scored against the ATT&CK techniques each dataset's metadata says was executed.

The headline is not a high number. It is the **gap between tuned and unseen tools**:

| Split | Runs | Runs whose technique has a rule | Detected by the targeted rule | Recall where a rule exists |
|---|---|---|---|---|
| Dev (Empire + cmd runs; rules tuned here) | 58 | 48 | 37 | **77%** |
| Test (every other tool; scored once, rules frozen) | 49 | 43 | 14 | **33%** |

Rules that look good on the attacks you wrote them against lose most of their recall against the same techniques run with a different tool. The split is by **tool**, not random, precisely to expose this.

## Method

1. `src/build_events.py` flattens the Mordor zips (JSON lines) into one table (786,312 events x 57 columns) and a run table with ground-truth techniques from each dataset's YAML metadata. 7 runs without technique labels are dropped.
2. `src/sigma_engine.py` evaluates Sigma-format YAML (`contains/startswith/endswith/re/all`, `1 of sel*`, `not`, parentheses). Aggregation is supported as `selection | count([Field]) [by Group] >= N` with a `timeframe` (distinct count when a field is given, sliding window); `near` and temporal sequences are not.
3. `rules/` holds 21 rules tagged with ATT&CK techniques (credential access, defence evasion, lateral movement, persistence, execution, discovery).
4. `src/evaluate.py --split dev|test` scores run-level recall per rule, off-target firing, and alerts per 10k events.
5. **Tuning discipline:** rules were written and tuned only on Empire and cmd runs. They were then frozen (`rules_frozen.md5`) and the held-out tools scored once. No rule was changed after seeing test numbers.

## Dev tuning log (Empire + cmd only; the 18 single-event rules)

| Version | Change (all generic patterns, not run-specific) | Detected / runs with rule |
|---|---|---|
| v1 | first draft | 26 / 48 (54%) |
| v2 | DCSync falls back to Control Access (0x100) on DS objects when the message isn't rendered; `reg save` of SAM/SECURITY/SYSTEM; `esentutl /vss`; `sc` regex tolerant of extra spaces; `net`/`net1` discovery with any path | 32 / 48 |
| v3 | quoted `reg.exe`; event-log tampering (wevtutil set-log path, MiniNt and EventLog service registry edits); `net user` | 38 / 48 |
| v4 | LSASS rule: dropped the over-generic 0x40/0x1400 access masks and excluded Azure/VM guest agents | 37 / 48 (one run lost) |

The v4 trade-off was deliberate: LSASS alerts fell from **30.3 to 0.14 per 10k events** for one lost detection.

## Where it breaks on unseen tools (test split)

Covenant (12 of 17 runs missed) and PowerShell-script (psh, 12 of 16 missed) datasets account for 24 of the 29 test misses. Per-rule test recall: DCSync 1/3, LSASS 1/3, service install 1/11, WinRM 1/11, admin share 2/11, Defender registry 0/11, LOLBin proxy execution **0/7** (3/3 on dev), remote-thread injection **0/3** (2/3 on dev). Rules keyed to the command lines Empire and cmd produce do not generalise; reliable coverage would need behaviour-based signals (process lineage, named pipes, network logons) rather than strings.

## Noise

Noise is measured as *off-target firing*: how often a rule fires on runs whose ground truth is a different technique. Attack chains legitimately contain multiple techniques, so this is a **proxy, not a false-positive rate**. There is no clean benign baseline in these datasets. Worth knowing:

- `win_audit_log_cleared` (Security 1102) fires on 27.5% (dev) / 34% (test) of off-target runs; log clearing is a lab-reset artefact here. It would need an allowlist for the lab's reset process.
- `win_powershell_suspicious_command` fires on 21% of dev off-target runs; Empire/PowerShell stagers make this expected but it is the noisiest command-line rule.
- Volume on the test set is low (under 1.3 alerts per 10k events for every rule).

## Phase 2: aggregation rules, response pipeline, SIEM export, benign baseline

The headline tables above are for the 18 single-event rules (`results_dev.json`, `results_test.json`). Phase 2 added three aggregation rules; rerunning all 21 rules gives the same run-level totals (dev 37/48, test 14/43; `results_*_v2.json`) because the new rules add per-rule signal rather than new run-level detections. The 3 new rules were written after the first test scoring, evaluated on dev, then on test once, and not modified afterwards (`rules_frozen.md5` covers all 21).

### Aggregation rules (count / distinct-count in a time window)
| Rule | Dev (target runs detected / off-target runs fired) | Test |
|---|---|---|
| `win_agg_admin_share_burst` (3+ ADMIN$/C$ checks from one source in 60s, non-machine account) | 0/4 / 2 | 2/11 / 1 |
| `win_agg_discovery_burst` (4+ distinct discovery commands on one host in 60s) | 0/5 / 1 | 0/1 / 0 |
| `win_agg_logon_failure_burst` (5+ failed logons on one host in 60s) | no labelled runs | 1/1 (PurpleSharp, labelled T1110.003) |

What this shows: the Mordor "atomic" runs execute one action each, so most of them contain no burst and the discovery burst rule cannot score well here by construction. The burst rules do fire where a real burst exists: 25 distinct discovery commands in 91 seconds inside an Empire persistence run (labelled T1547, so it counts as off-target in the table even though the behaviour is real discovery), and ADMIN$/C$ access in SMB-based lateral movement runs labelled T1047/T1574/T1021.003. The table therefore understates them, because ground truth is technique-labelled at run level. The logon-failure rule has exactly one real validation run.

### Alerts to incidents to SOAR dry-run (`src/respond.py`)
Alerts are grouped into incidents by host and time gap (10 min); run labels are not used. A deterministic policy assigns P1/P2/P3 from rule levels and the number of distinct ATT&CK tactics; an enrichment step (deterministic template, or a local LLM through Ollama) writes the summary; a claim verifier rejects summaries that mention technique IDs or hosts not in the incident; the model can raise a priority but never lower the policy's; command lines are treated as attacker-controlled (masked, truncated, passed as data). P1 incidents produce an approval-gated isolation proposal and never auto-act; domain controllers are refused.

Result over all 114 runs (`respond_run/metrics.json`): 388 alerts became 88 incidents (77% fewer, 4.4 alerts per incident); priorities P1 24 / P2 61 / P3 3; 21 containment proposals awaiting approval; 3 refused for critical hosts; 0 unsupported claims in the template summaries. Grouping quality: 6 incidents mix alerts from more than one run (same host, runs close in time) and 14 runs are split across several incidents (lateral movement crosses hosts). The real-LLM path is implemented but was not run (no Ollama in the build environment).

### Vulnerability exposure inside the incident workflow (`src/exposure.py`, `src/build_cve_scores.py`, `src/build_kev_catalog.py`)
Exposure is one step of the incident pipeline, not a separate module. After alerts are grouped into incidents, each incident's host is joined to an inventory and to a CVE score table, and the result can (a) raise the priority, (b) add a patch step to the ticket and (c) feed a remediation queue.

What the step does:
- **Scores:** CISA KEV membership (real due dates, ransomware flag) plus an exploit-likelihood model (gradient boosting on CVSS components and description keywords, no vendor priors, trained on CVEs up to 2022 against KEV labels). Tiers: CRITICAL = KEV-listed CVE open on the host, HIGH = top-5% model score, NONE otherwise.
- **Relevance to the alert:** each CVE is mapped to a vulnerability class (for example remote code execution, privilege escalation, auth bypass) and each class to the ATT&CK tactics it plausibly enables (`CLASS_TACTICS`). A CVE counts as relevant only if its tactics overlap the incident's. This mapping is a heuristic I wrote, not a validated one.
- **Temporal applicability:** a CVE only counts if it was already open when the incident happened (`first_seen` <= incident time < `patched_date`). On the illustrative inventory this alone cut raises from 47 to 8 of 88 incidents.
- **Asset context:** inventory columns `criticality`, `internet_facing`, `first_seen`, `patched_date`, `owner` are used; the ticket names criticality and exposure.
- **Raise budget (`--max-raise-share`, default 0.25):** at most that share of incidents may be lifted by exposure; candidates are ranked by strength and the rest keep their alert-only priority, with the patch recommendation still attached. A raise is one level at most and never a lowering.
- **Remediation queue (`remediation_queue.csv`):** open CVEs per host ordered by CISA due date, days overdue as of `--asof`, owner, linked incidents.
- **Scanner exports:** `load_inventory` accepts a CSV/DataFrame/dict and auto-detects common column names (host/ip/asset, cve/cve_id/vulnerability id, and so on).
- **Data freshness:** `cve_data_meta.json` records catalog version and build dates; the metrics report them. `refresh_data.sh` rebuilds KEV and scores. The shipped data is a snapshot (KEV built 2026-09-30); labels for recent CVEs are immature because exploitation is reported late.
- **EPSS:** an optional hook exists, but EPSS could not be downloaded in the build environment, so it is **untested**.

Result with the illustrative inventory (`respond_run_exposure/metrics.json`): 8 of 88 incidents raised (9.1%), P1 24 -> 32, 0 withheld by the budget, 7 remediation items of which 4 overdue at incident time, containment still refused for domain controllers.

**Sensitivity (`exposure_sensitivity.json`, `src/exposure_sensitivity.py`)** - a simulation of policy behaviour when a random share of hosts carries a KEV CVE (20 draws per cell, baseline P1 share 0.273). It shows how the policy inflates priority in bad estates and what the budget does; it is **not** evidence that exposure improves triage.

| Hosts with a KEV CVE | P1 share, no budget | P1 share, budget 0.25 | Max raised share with budget |
|---|---|---|---|
| 5% | 0.295 | 0.295 | 0.19 |
| 25% | 0.379 | 0.355 | 0.25 |
| 50% | 0.567 | 0.453 | 0.25 |
| 100% | 0.823 | 0.508 | 0.25 |

**What is not solved:**
- `assets/example_inventory.csv` is ILLUSTRATIVE: I assigned well-known CVEs to the lab hostnames; nobody scanned them. Use a real scan export.
- There are no analyst verdicts, so there is no measurement that the boost helps. `src/evaluate_priority.py` is a ready harness (P1 precision/recall before and after, and severity share among lifted incidents) for when verdicts exist.
- The SOC alert-triage model (UNSW-NB15) has no hosts, so it does not use vulnerability data; exposure lives only in this pipeline.
- Without `--inventory` the pipeline behaves exactly as before (`respond_run/`).

### Binary triage inside the incident workflow (`src/binary_triage.py`)
The static malware classifier from the companion `malware-classifier` project is one step of the incident pipeline, not a separate tool. After alerts are grouped into incidents, the executables collected from each incident's host (a manifest: `host, path, optional first_seen`) are scored by that classifier (header + section/import/resource features; files are parsed, never executed), optionally matched against YARA rules, and the result can (a) lift the incident one level, (b) add a sandbox-analysis step to the ticket. Run it with `python src/respond.py --binaries manifest.csv --classifier-dir ../malware-classifier`.

It is a bounded, soft signal, because of what the classifier project measured about itself: on a source the model never saw, the training-source threshold gave 3-43 % benign false alarms, and forging a handful of fields hides most malware (recall 7.5-17 % when all 8 tested fields were forged). So a high score is a lead, and a low score proves nothing.

| Tier | Meaning | Priority effect |
|---|---|---|
| CRITICAL | a file scores above the cutoff AND (a YARA rule matches OR the cutoff was calibrated on benign files from this environment and the file's first-seen time is known) | lifts one level |
| HIGH | above the cutoff, nothing corroborating (uncalibrated cutoff, time unknown, no YARA) | lifts P3 to P2 only |
| NONE | below the cutoff, unscorable, off-host, or outside the time window | nothing |

Guardrails (each has a test): it never lowers a priority; it shares the raise-budget mechanism with the exposure step (`--max-binary-raise-share`, default 0.25, strongest candidates first, YARA-corroborated first); it does not stack with exposure (each signal lifts at most one level and the highest wins, so enrichment lifts an incident at most one level in total); only files that appeared on the host in the 24 h before to 10 min after the incident count (software that has sat on the host for weeks is baseline); unscorable, missing or oversized files carry no signal and are counted in the metrics; file names are attacker-controlled, so they are sanitised, kept out of the template summary and passed to any LLM as data only. `--benign-manifest` (at least 100 known-benign files from the same environment) sets the cutoff at their 99th percentile, which is what the classifier project says a deployment must do.

**Verified:** 25 new tests (`tests/test_binary_triage.py`) with a fake scorer; a before/after check that a run without `--binaries` reproduces the previous tickets, queues, metrics and audit log exactly (timestamps aside), with and without the exposure step; a command-line run against a stub classifier project, including benign-file calibration; and a contract test that `ClassifierScorer` loads a project folder, loads the model bundle once and reads the threshold from it.
**Not verified / not solved:**
- The real trained model was not run through this step in the build environment (scikit-learn version mismatch with the pickled model). `test_classifier_scorer_loads_the_project_and_returns_a_probability` runs the real thing when `MALWARE_CLASSIFIER_DIR` is set; run it where scikit-learn matches the model.
- The Mordor runs contain no binaries, so there is no labelled data on which to measure whether binary triage improves triage. The tests prove the plumbing and the guardrails, not detection value.
- Collecting the binaries for the manifest (for example by the hashes in Sysmon events) is out of scope. The YARA hook is wired but no rules ship, and `yara-python` is optional.
- The classifier's own limits carry over: AUC 0.92 on an unseen source and 47 % detection at 1 % false alarms only with a cutoff tuned on that source.

**Demo on real PE files (synthetic placement; `src/pick_samples.py`, `src/demo_binary_triage.py`).** The Mordor runs contain no binaries, so 40 DikeDataset malware files the classifier never saw (none is listed in its `dike_features.csv`) and 48 benign files were placed on the hosts of the 88 baseline incidents (random, seed 7). Because neighbouring incidents on one host share a 24 h window, 66 incidents have a malware file in their window and 22 do not; that is the ground truth the report uses. No priority was lowered in any run.

| Setting | Malware-window incidents flagged | No-malware incidents flagged | Incidents raised | P1 / P2 / P3 | Containment proposals |
|---|---|---|---|---|---|
| Baseline (no binary triage) | - | - | - | 24 / 61 / 3 | 21 |
| Model's own cutoff 0.9715, no raise cap | 61 / 66 (92 %), all HIGH | 0 / 22 | 2 | 24 / 63 / 1 | 21 |
| Cutoff calibrated on 150 benign files (0.7186), no raise cap | 64 / 66 (97 %), all CRITICAL | 0 / 22 | 45 | 67 / 20 / 1 | 60 |
| Same, default raise cap (25 %) | 64 / 66 (97 %), all CRITICAL | 0 / 22 | 22 (23 withheld) | 46 / 39 / 3 | 42 |

How far to trust it:
- The placement is artificial: 75 % of incidents carry a malware file, far above real prevalence. The jump in P1 (24 to 67 without a cap) is an artefact of that and shows why the raise budget exists; it is not a prediction.
- The malware files are unseen by the classifier but come from the same source (DikeDataset) it was trained on. The classifier project shows detection falls sharply on other sources, so 92-97 % is a same-source figure.
- The benign files, and the 150 used to calibrate the cutoff, are almost all (248 of 250 placed) in the classifier's training pool. That is why the calibrated cutoff (0.7186) came out lower than the model's own (0.9715), and why 0 / 22 false flags says nothing about real, unseen benign software. A deployment must calibrate on benign files from its own environment.

### SIEM export (`src/siem_export.py`, `exported/`)
All 21 rules compile to Splunk SPL, Microsoft Sentinel KQL and Elasticsearch DSL. **Verified:** an independent evaluator that reads only the DSL returns exactly the same events as the Sigma engine for every rule on all 786,312 events (`exported/local_equivalence.json`). **Not verified:** the SPL and KQL text has not been run in Splunk or Sentinel; the DSL has not been run against a real Elasticsearch (run `siem/load_and_verify.py` against the compose file to do that; regex atoms are sent as painless scripts, and the local check uses Python `re`, so Java-vs-Python regex differences are not covered). Aggregation windows are approximated in SIEM form (SPL `streamstats` trailing window, KQL tumbling bins) and can flag a different subset of events than the sliding-window engine. Field names must be mapped to your schema.

### Benign baseline (`src/benign_baseline.py`): harness only, NOT run
There is no benign window in the Mordor runs, and the clean-log set I identified (Nextron `evtx-baseline`) is distributed as GitHub release files that the build environment could not download, and no EVTX parser was installable. So **no true false-positive rate has been measured**. The script converts `evtx_dump -o jsonl` output, runs all rules and reports alerts per 10k events per rule; its converter is unit-tested on a synthetic record. Rules that match on the rendered `Message` (admin share, DCSync GUIDs, machine-account filters) will under-fire on evtx JSON, and the report flags them.

## Limitations (please read)

- Ground truth is **run-level and base-technique-level** (e.g. T1003). A rule targeting T1003.006 is credited on any T1003 run, so per-rule recall understates precision-of-targeting; the run-level coverage table is the more reliable number.
- Small numbers: 49 test runs, many techniques with 1-3 runs. Treat percentages as indicative, not precise.
- I briefly inspected a Covenant DCSync event while debugging the 4662 message format. No rule was changed from that; the rule's GUIDs are the standard DS-Replication GUIDs and the AccessMask fallback was derived from Empire events.
- DCSync's AccessMask fallback is broader than the GUID match and would be noisy on a real domain (other extended rights such as password reset).
- 6 of 49 test techniques and 10 of 58 dev techniques have no rule at all.
- Noise is still only a proxy until the benign baseline is run on real goodware logs.
- Known dev misses left unfixed: PowerShell-in-memory NinjaCopy, Rubeus ticket requests, `netprofm` eventlog stop.

## Reproduce

```bash
pip install -r requirements.txt
git clone --depth 1 https://github.com/OTRF/Security-Datasets.git sds    # needs the Mordor dataset zips
python src/build_events.py sds            # -> data/events.pkl.gz, data/runs.pkl.gz
python src/evaluate.py --split dev --out results_dev.json
python src/evaluate.py --split test --out results_test.json
python src/respond.py --out respond_run          # incidents, tickets, approval queue (dry-run)
python src/respond.py --out respond_run_exposure --inventory assets/example_inventory.csv   # with vulnerability exposure
python src/respond.py --out respond_run_binaries --binaries manifest.csv --classifier-dir ../malware-classifier   # with binary triage (add --benign-manifest benign.csv to calibrate the cutoff)
python src/exposure_sensitivity.py                 # policy sensitivity simulation
bash refresh_data.sh                               # rebuild KEV + CVE score data
python src/siem_export.py --verify                # SPL/KQL/DSL + local DSL equivalence
python src/benign_baseline.py baseline/*.jsonl    # after converting goodware .evtx with evtx_dump
python -m pytest -q tests
```
Add a rule by dropping a Sigma YAML into `rules/` with `attack.tXXXX` tags.

## Layout

`rules/` Sigma YAML, `src/` (engine, builder, evaluator, respond, exposure, binary_triage, evaluate_priority, exposure_sensitivity, siem_export, benign_baseline), `siem/` (Elasticsearch compose + verifier), `exported/`, `assets/`, `respond_run/`, `respond_run_exposure/`, `tests/` (30 + 25 for binary triage), result JSONs, `rules_frozen.md5`.
