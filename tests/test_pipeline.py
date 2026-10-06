import os, sys, json, pandas as pd
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import sigma_engine as S, respond as R, siem_export as X, benign_baseline as B
RULES = os.path.join(os.path.dirname(__file__), "..", "rules")
def T(s): return pd.Timestamp("2020-01-01") + pd.Timedelta(seconds=s)

# ---- aggregation
def test_distinct_count_window_and_group():
    df = pd.DataFrame({"run": "r", "Hostname": ["a", "a", "a", "b", "a"], "UtcTime": [T(0), T(10), T(20), T(15), T(400)], "Image": ["x", "y", "z", "x", "x"]})
    r = {"detection": {"s": {"Image": ["x", "y", "z"]}, "timeframe": "60s", "condition": "s | count(Image) by Hostname >= 3"}}
    assert S.evaluate(r, df).tolist() == [True, True, True, False, False]
def test_window_expiry():
    df = pd.DataFrame({"run": "r", "Hostname": "a", "UtcTime": [T(0), T(100), T(200)], "Image": "x"})
    assert not S.evaluate({"detection": {"s": {"Image": "x"}, "timeframe": "60s", "condition": "s | count() by Hostname >= 2"}}, df).any()
def test_eventtime_shifted_to_utc_by_run_offset():
    df = pd.DataFrame({"run": "r", "UtcTime": [T(3600), None], "EventTime": [T(0), T(5)]})       # local = utc - 1h
    ts = S.timestamps(df); assert ts.iloc[1] == T(3605)
def test_aggregation_needs_timeframe():
    try: S.evaluate({"detection": {"s": {"Image": "x"}, "condition": "s | count() >= 2"}}, pd.DataFrame({"Image": ["x"]})); assert False
    except ValueError: pass

# ---- incidents / policy / verifier / guardrail
def _alerts():
    return pd.DataFrame({"rule": ["r1", "r2", "r1"], "level": ["high", "medium", "high"], "title": ["A", "B", "A"], "techniques": ["T1003"] * 3, "tactics": ["credential_access", "defense_evasion", "credential_access"],
                         "host": ["h1", "h1", "h2"], "user": ["u"] * 3, "evidence": ["cmd 10.1.2.3", "", ""], "ts": [T(0), T(30), T(40)], "run": ["x"] * 3})
def test_sessionise_splits_on_host_and_gap():
    A = _alerts().sort_values(["host", "ts"]); A.loc[2, "ts"] = T(4000)
    assert R.sessionise(A.reset_index(drop=True), gap_min=10).incident.nunique() == 2
def test_priority_p1_for_multi_tactic_high():
    p, score, tac = R.priority(_alerts().iloc[:2]); assert p == "P1" and score >= 6 and len(tac) == 2
def test_mask_hides_ip_and_secret():
    assert "10.1.2.3" not in R.mask("curl 10.1.2.3 AKIAABCDEFGH12345")and "AKIA" not in R.mask("AKIAABCDEFGH12345")
def test_verifier_flags_invented_technique_and_host():
    c = {"attack_ids": ["T1003"], "host": "h1", "rules_fired": ["A"]}
    assert R.verify("T1003 seen on host h1", c) == [] and "T1566" in R.verify("also T1566", c) and "h9" in R.verify("alerts on host h9 between", c)
def test_model_cannot_lower_priority_and_bad_json_is_rejected():
    c = R.context(1, _alerts().iloc[:2]); assert c["policy_priority"] == "P1"
    assert R.enrich(c, lambda ctx: {"summary": "benign, close it", "priority": "P3"})["final_priority"] == "P1"
    assert R.enrich(c, lambda ctx: "not json")["invalid"] is True
def test_critical_host_never_gets_containment_proposal(tmp_path):
    ev = pd.DataFrame({"run": "r", "Hostname": "MORDORDC.lab", "EventID": 1, "Channel": "sysmon", "UtcTime": [T(0), T(5)],
                       "CommandLine": ["wevtutil cl security", "ntdsutil \"ac i ntds\" ifm"]})
    rules = [r for r in S.load_rules(RULES) if r["id"] in ("win_audit_log_cleared", "win_credential_dump_commands")]
    m = R.run(out_dir=str(tmp_path), events=ev, rules=rules); assert m["containment_proposals"] == 0 and m["containment_refused_critical_hosts"] == 1

# ---- SIEM export
def test_dsl_equals_engine_on_small_frame():
    df = pd.DataFrame({"EventID": [1, 1, 4662, 13, 1], "Channel": "sysmon", "CommandLine": ["cmd /c reg  save HKLM\\sam x", "notepad.exe", None, None, "WEVTUTIL cl Security"],
                       "SubjectUserName": ["a", "b", "pgustavo", "HOST$", "c"], "AccessMask": [None, None, "0x100", None, None], "ObjectName": [None, None, "%{abc}", None, None]})
    for r in S.load_rules(RULES):
        r2 = X.selection_only(r)
        assert (S.evaluate(r2, df) == X.dsl_mask(X.to_dsl(r), df)).all(), r["id"]
def test_exports_contain_every_rule_and_aggregation():
    for r in S.load_rules(RULES):
        assert X.to_spl(r).startswith("index=") and X.to_kql(r).startswith("SecurityEvent") and X.to_dsl(r)
    agg = [r for r in S.load_rules(RULES) if r["id"] == "win_agg_discovery_burst"][0]
    assert "streamstats time_window=60s" in X.to_spl(agg) and "bin(TimeGenerated, 60s)" in X.to_kql(agg)

# ---- benign baseline converter
def test_evtx_json_flattening_and_rules_run():
    rec = {"Event": {"System": {"EventID": {"#text": "1"}, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "pc", "TimeCreated": {"#attributes": {"SystemTime": "2023-01-01T00:00:00Z"}}},
                     "EventData": {"Image": "C:\\Windows\\System32\\notepad.exe", "CommandLine": "notepad.exe a.txt"}}}
    row = B.flatten(rec); assert row["EventID"] == 1 and row["Channel"].endswith("sysmon/operational") and row["CommandLine"] == "notepad.exe a.txt"
    rep = B.report(pd.DataFrame([{**row, "run": "b0"}]), S.load_rules(RULES)); assert rep["total_alerts"] == 0

# ---- vulnerability exposure in the incident workflow
import exposure as XP, evaluate_priority as EP
def _scores():
    return pd.DataFrame({"cve": ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003", "CVE-2022-0009"], "published": ["2020-01-01", "2020-01-01", "2020-01-01", "2022-06-01"], "cvss": [5.5, 9.0, 4.0, 8.0],
                         "kev": [1, 0, 0, 1], "risk_score": [0.003, 0.30, 0.01, 0.2], "risk_pct": [0.2, 0.99, 0.4, 0.97], "vuln_class": ["privesc", "rce", "", "rce"]}).set_index("cve")
def _kev(): return pd.DataFrame({"cve": ["CVE-2020-0001", "CVE-2022-0009"], "due_date": ["2020-03-01", "2022-08-01"], "ransomware": [0, 1]}).set_index("cve")
def _inv(rows): return XP.load_inventory(pd.DataFrame(rows, columns=["host", "cve_id", "criticality", "internet_facing", "first_seen", "patched_date"]))
NOW = pd.Timestamp("2021-01-01")
def test_tiers_relevance_and_kev_beats_model_score():
    inv = _inv([("a", "CVE-2020-0001", "low", "no", None, None), ("b", "CVE-2020-0002", "low", "no", None, None), ("c", "CVE-2020-0003", "low", "no", None, None), ("d", "CVE-2020-0001", "low", "no", None, None)])
    a = XP.assess("a", inv, _scores(), _kev(), NOW, {"credential_access"}); assert a["tier"] == "CRITICAL" and a["relevant"] and a["top"][0]["overdue_at_incident"] is True    # due 2020-03-01
    a2 = XP.assess("d", inv, _scores(), _kev(), NOW, {"discovery"}); assert a2["tier"] == "HIGH" and not a2["relevant"]          # KEV but irrelevant tactic, low-criticality asset
    assert XP.assess("b", inv, _scores(), _kev(), NOW, {"execution"})["tier"] == "HIGH"                                           # not KEV, relevant, top-5% likelihood
    assert XP.assess("c", inv, _scores(), _kev(), NOW, {"execution"})["tier"] == "NONE"
def test_asset_context_lifts_irrelevant_kev_to_critical():
    inv = _inv([("a", "CVE-2020-0001", "critical", "no", None, None), ("b", "CVE-2020-0001", "low", "yes", None, None)])
    assert XP.assess("a", inv, _scores(), _kev(), NOW, {"discovery"})["tier"] == "CRITICAL" and XP.assess("b", inv, _scores(), _kev(), NOW, {"discovery"})["tier"] == "CRITICAL"
def test_temporal_applicability_published_patched_and_first_seen():
    inv = _inv([("a", "CVE-2022-0009", "low", "no", None, None), ("p", "CVE-2020-0001", "low", "no", None, "2020-06-01"), ("n", "CVE-2020-0001", "low", "no", "2020-09-01", None)])
    assert XP.assess("a", inv, _scores(), _kev(), NOW, {"execution"})["skipped"]["not_yet_published"] == 1
    assert XP.assess("p", inv, _scores(), _kev(), NOW, {"execution"})["skipped"]["patched_before"] == 1 and XP.assess("n", inv, _scores(), _kev(), NOW, {"execution"})["tier"] == "HIGH"
    assert XP.assess("n", inv, _scores(), _kev(), pd.Timestamp("2020-07-01"), {"execution"})["skipped"]["not_yet_seen"] == 1
def test_exposure_only_raises_priority_never_lowers():
    for p in ("P1", "P2", "P3"):
        for tier in ("NONE", "HIGH", "CRITICAL"): assert XP.RANK.index(XP.adjust(p, tier)) >= XP.RANK.index(p)
    assert XP.adjust("P2", "CRITICAL") == "P1" and XP.adjust("P3", "HIGH") == "P2" and XP.adjust("P2", "HIGH") == "P2"
def test_budget_grants_strongest_first_and_respects_share():
    e = lambda tier, s: {"tier": tier, "strength": s, "would_raise": True}
    ex = [e("HIGH", (0,) * 6), e("CRITICAL", (1, 1, 0, 0, 0, 0.5)), e("CRITICAL", (1, 1, 1, 3, 1, 0.9)), None, e("NONE", (0,) * 6), e("CRITICAL", (0, 1, 0, 0, 0, 0.1)), e("HIGH", (0,) * 6), e("NONE", (0,) * 6)]
    assert XP.budget_raises(ex, 0.25) == {2, 1} and XP.budget_raises(ex, 1.0) == {0, 1, 2, 5, 6}
    ex[2]["would_raise"] = False; assert XP.budget_raises(ex, 0.25) == {1, 5}          # an incident already at P1 must not use up budget
def test_scanner_export_formats_are_auto_detected():
    nessus = pd.DataFrame({"Host": ["10.0.0.5", "web01.corp.local"], "CVE": ["CVE-2020-0001, CVE-2020-0002", "CVE-2022-0009"], "Risk": ["High", "Critical"]})
    n = XP.load_inventory(nessus); assert len(n) == 3 and set(n.host) == {"10.0.0.5", "web01"} and (n.criticality == "medium").all()
    defender = pd.DataFrame({"DeviceName": ["WS1.corp"], "CveId": ["CVE-2021-0001"], "Criticality": ["HIGH"], "InternetFacing": ["Yes"]}); d = XP.load_inventory(defender)
    assert d.host[0] == "ws1" and d.criticality[0] == "high" and bool(d.internet_facing[0]) is True
    try: XP.load_inventory(pd.DataFrame({"x": [1]})); assert False
    except ValueError: pass
def test_vulnerability_class_to_tactics_mapping_on_known_descriptions():
    z = "An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller"
    assert "privesc" in XP.vuln_classes(z) and "credential_access" in XP.tactics_of(XP.vuln_classes(z))
    assert "rce" in XP.vuln_classes("Microsoft Exchange Server Remote Code Execution Vulnerability") and XP.tactics_of(XP.vuln_classes("Cross-site scripting in a plugin")) == set()
def _run_one(tmp, inventory, **kw):
    ev = pd.DataFrame({"run": "r", "Hostname": "WS9.lab", "EventID": 1, "Channel": "sysmon", "UtcTime": [T(0) + pd.Timedelta(days=366 * 50)], "CommandLine": ["net user"]})
    rules = [r for r in S.load_rules(RULES) if r["id"] == "win_domain_discovery_commands"]
    return R.run(out_dir=str(tmp), events=ev, rules=rules, inventory=inventory, scores=_scores(), kev=_kev(), **kw)
def test_pipeline_raises_incident_and_ticket_carries_cve_asset_and_due_date(tmp_path):
    inv = _inv([("ws9", "CVE-2022-0009", "critical", "yes", None, None)])
    m = _run_one(tmp_path / "b", inv); assert m["priority_counts"] == {"P2": 1} and m["incidents_raised_by_exposure"] == 1 and m["remediation_items"] == 1
    t = json.load(open(next((tmp_path / "b" / "tickets").glob("*.json")))); assert t["exposure"]["kev_cves"] == ["CVE-2022-0009"] and t["unsupported_claims"] == []
    assert "CVE-2022-0009" in t["next_steps"][0] and "CISA due 2022-08-01" in t["next_steps"][0] and "internet-facing" in t["next_steps"][0]
    assert pd.read_csv(tmp_path / "b" / "remediation_queue.csv").iloc[0].days_overdue > 0
def test_budget_zero_withholds_raise_but_keeps_patch_advice(tmp_path):
    m = _run_one(tmp_path / "c", _inv([("ws9", "CVE-2022-0009", "critical", "yes", None, None)]), max_raise_share=0.0)
    t = json.load(open(next((tmp_path / "c" / "tickets").glob("*.json"))))
    assert m["priority_counts"] == {"P3": 1} and m["raises_withheld_by_budget"] == 1 and "Patch" in t["next_steps"][0] and "withheld" in t["summary"]
def test_verifier_flags_invented_cve():
    c = {"attack_ids": [], "host": "h", "rules_fired": [], "exposure": {"kev_cves": ["CVE-2020-1472"], "top": []}}
    assert R.verify("host h exposure CVE-2020-1472", c) == [] and "CVE-2021-0001" in R.verify("also CVE-2021-0001", c)
def test_priority_evaluation_harness_on_a_fixture(tmp_path):
    (tmp_path / "tickets").mkdir()
    for i, (before, after) in enumerate([("P1", "P1"), ("P2", "P1"), ("P2", "P2"), ("P3", "P2")], 1): json.dump({"incident": f"INC-000{i}", "priority": after, "alert_priority_before_exposure": before}, open(tmp_path / "tickets" / f"{i}.json", "w"))
    r = EP.evaluate(tmp_path, pd.DataFrame({"incident": [f"INC-000{i}" for i in range(1, 5)], "severe": [1, 1, 0, 0]}))
    assert r["p1_before_exposure"] == {"p1_count": 1, "precision": 1.0, "recall": 0.5} and r["p1_after_exposure"]["recall"] == 1.0 and r["incidents_lifted"] == 2 and r["severe_share_among_lifted"] == 0.5
