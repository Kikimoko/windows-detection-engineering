import os, sys, pandas as pd
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src")); import sigma_engine as S
RULES = os.path.join(os.path.dirname(__file__), "..", "rules")
DF = pd.DataFrame({"EventID": [1, 1, 4662, 13], "CommandLine": ["cmd /c reg  save HKLM\\sam x", "notepad.exe", None, None],
                   "SubjectUserName": ["a", "b", "pgustavo", "HOST$"], "AccessMask": [None, None, "0x100", None], "ObjectName": [None, None, "%{abc}", None], "Channel": ["sysmon"] * 4})
def R(det): return {"id": "t", "detection": det}
def test_contains_and_not():
    assert S.evaluate(R({"s": {"CommandLine|contains": "reg"}, "f": {"EventID": 4662}, "condition": "s and not f"}), DF).tolist() == [True, False, False, False]
def test_regex_handles_double_space():
    assert S.evaluate(R({"s": {"CommandLine|re": r"(?i)reg\s+save"}, "condition": "s"}), DF).tolist() == [True, False, False, False]
def test_one_of_and_all_of():
    d = {"a1": {"EventID": 4662}, "a2": {"EventID": 13}, "condition": "1 of a*"}; assert S.evaluate(R(d), DF).tolist() == [False, False, True, True]
    d = {"a1": {"EventID": 4662}, "a2": {"AccessMask": "0x100"}, "condition": "all of them"}; assert S.evaluate(R(d), DF).tolist() == [False, False, True, False]
def test_missing_field_never_matches():
    assert not S.evaluate(R({"s": {"NoSuchField|contains": "x"}, "condition": "s"}), DF).any()
def test_dcsync_control_access_rule_excludes_machine_accounts():
    r = [x for x in S.load_rules(RULES) if x["id"] == "win_dcsync_replication_rights"][0]
    assert S.evaluate(r, DF).tolist() == [False, False, True, False]
def test_all_rules_load_and_have_attack_tags():
    rules = S.load_rules(RULES); assert len(rules) == 21
    for r in rules: assert S.techniques(r), r["id"]
