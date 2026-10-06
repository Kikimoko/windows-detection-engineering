"""Feature engineering for exploit-likelihood ranking. Only information available when the CVE is published.
Vendor/product/CWE exploitation priors are computed from TRAINING-period labels only (smoothed), so nothing from the test period leaks."""
import re, numpy as np, pandas as pd
BASE = ["v3_AV", "v3_AC", "v3_PR", "v3_UI", "v3_S", "v3_C", "v3_I", "v3_A"]
KW = {"rce": r"remote code execution|arbitrary code|execute arbitrary|code execution", "unauth": r"unauthenticated|without authentication|remote attacker",
      "authbypass": r"authentication bypass|bypass authentication|improper authentication", "deser": r"deserializ", "sqli": r"sql injection",
      "cmdi": r"command injection|os command", "traversal": r"path traversal|directory traversal", "uaf": r"use[- ]after[- ]free|memory corruption|buffer overflow|out-of-bounds",
      "privesc": r"privilege|elevation", "xss": r"cross-site scripting|\bxss\b", "ssrf": r"server-side request forgery|\bssrf\b", "upload": r"file upload|arbitrary file"}
def prep(df):
    X = pd.DataFrame(index=df.index)
    X["cvss"] = df.cvss.astype(float)
    for c in BASE: X[c] = df[c].astype("category")
    d = df.desc.fillna("").str.lower()
    for k, p in KW.items(): X["kw_" + k] = d.str.contains(p, regex=True).astype(int)
    X["desc_len"] = d.str.len()
    X["year"] = df.published.str[:4].astype(int)
    return X
def fit_priors(train, alpha=20):
    """smoothed KEV rate per vendor, product, CWE learnt from train labels (empirical-Bayes shrinkage toward the global rate)"""
    g = train.exploited.mean(); P = {"g": g}
    for col in ["vendor", "product", "cwe"]:
        s = train.groupby(col).exploited.agg(["sum", "count"]); P[col] = ((s["sum"] + alpha * g) / (s["count"] + alpha)).to_dict(); P[col + "_n"] = s["count"].to_dict()
    return P
def add_priors(X, df, P):
    X = X.copy()
    for col in ["vendor", "product", "cwe"]:
        X["prior_" + col] = df[col].map(P[col]).fillna(P["g"]).values; X["seen_" + col] = df[col].map(P[col + "_n"]).fillna(0).values
    return X
