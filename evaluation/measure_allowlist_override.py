"""
measure_allowlist_override.py

How load-bearing is the Egyptian-brand allowlist?

risk_scoring.py cancels the URL-derived signals (rule engine URL part,
blacklist, url_model) when the URL's host is a verified Egyptian brand domain
or a subdomain of one. This script counts how many allowlisted brand URLs the
system WOULD flag if that override did not exist. Nothing in the backend is
changed: each URL goes through calculate_final_risk_score() as usual, and the
"no allowlist" verdict is recomputed from the same engine outputs with the
scorer's own decision functions, passing ignore_url_part=False and not zeroing
the blacklist / url_model scores (exactly what the scorer does for a URL that
is not allowlisted).

URL sets (reported separately, never pooled into one number)
  dataset_<split>   real URLs from dataset.csv whose host is allowlisted (crawled
                    legitimate pages and Tranco rows). The split is host-grouped,
                    so TEST rows are on brand hosts the URL model never saw in
                    training; TRAIN rows were fitted by it (optimistic, shown for
                    completeness only). Rows labelled phishing on an allowlisted
                    host are listed by count (the allowlist would hide them).
  constructed_dev   genuine own-domain URLs of the development typosquat benchmark
  constructed_ho    genuine own-domain URLs of the held-out benchmarks (held-out 2
                    reuses held-out 1's genuine URLs; de-duplicated)
  observed          the two genuine CIB URLs seen flagged by the model in browser
                    scans on 2026-10-19/20 (CLAUDE.md)

Against the evaluation database (training-split-only blacklist), refused otherwise.

Usage (project root, venv active, DATABASE_URL -> etis_eval in the same window):
    python evaluation/measure_allowlist_override.py
Outputs: evaluation/allowlist_override_report.txt, evaluation/allowlist_override_scores.csv
"""

import math
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

DATASET_PATH = PROJECT_ROOT / "data" / "processed" / "dataset.csv"
DEV_PATH = PROJECT_ROOT / "data" / "benchmarks" / "egypt_brand_typosquats.csv"
HO_PATHS = [PROJECT_ROOT / "data" / "benchmarks" / "egypt_brand_typosquats_heldout.csv",
            PROJECT_ROOT / "data" / "benchmarks" / "egypt_brand_typosquats_heldout2.csv"]
REPORT_PATH = PROJECT_ROOT / "evaluation" / "allowlist_override_report.txt"
SCORES_PATH = PROJECT_ROOT / "evaluation" / "allowlist_override_scores.csv"
OBSERVED = ["https://www.cibeg.com/", "https://www.cibeg.com/login"]
ENGINES = ("rule_based", "blacklist", "url_model")


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def rate(k: int, n: int) -> str:
    if n == 0:
        return "n/a (n=0)"
    lo, hi = wilson(k, n)
    return f"{100 * k / n:5.1f}% [{100 * lo:5.1f}, {100 * hi:5.1f}] ({k}/{n})"


def main() -> None:
    from app.core.database import SessionLocal, engine
    from app.engines import risk_scoring as rs
    from app.engines.rule_based.domain_typosquatting_detector import normalize_domain

    database = engine.url.database or ""
    print(f"Database: {engine.url.render_as_string(hide_password=True)}")
    if "eval" not in database:
        sys.exit("Refusing to run: DATABASE_URL does not point at the evaluation database (etis_eval).")

    sets: list[tuple[str, str, str, str, str]] = []   # (set name, id, url, label, url type)
    data = pd.read_csv(DATASET_PATH, dtype=str, keep_default_na=False)
    data = data[data["content_type"] == "url"]
    for row in data.itertuples(index=False):
        if rs._is_verified_egyptian_domain(row.text):
            sets.append((f"dataset_{row.split or 'nosplit'}", row.id, row.text, row.label, "real"))
    dev = pd.read_csv(DEV_PATH, dtype=str, keep_default_na=False)
    for row in dev[dev["kind"] == "genuine"].itertuples(index=False):
        sets.append(("constructed_dev", row.id, row.url, "legitimate", "dev_genuine"))
    seen = set()
    for path in HO_PATHS:
        if not path.exists():
            continue
        ho = pd.read_csv(path, dtype=str, keep_default_na=False)
        for row in ho[ho["kind"] == "genuine"].itertuples(index=False):
            if row.url not in seen:
                seen.add(row.url)
                sets.append(("constructed_ho", row.id, row.url, "legitimate", row.technique))
    for i, url in enumerate(OBSERVED, start=1):
        sets.append(("observed", f"OBS-{i}", url, "legitimate", "observed"))
    print(f"{len(sets):,} URLs: {dict(Counter(s[0] for s in sets))}")

    db = SessionLocal()
    records = []
    brand_domains = sorted(rs.EGYPTIAN_BRAND_DOMAIN_SET, key=len, reverse=True)

    def brand_of(host: str) -> str:
        return next((b for b in brand_domains if host == b or host.endswith("." + b)), host)

    for name, rid, url, label, url_type in sets:
        host = normalize_domain(url)
        rec = {"set": name, "id": rid, "label": label, "url_type": url_type, "host": host,
               "brand_domain": brand_of(host)}
        try:
            r = rs.calculate_final_risk_score(url=url, db=db)
            d = r["engine_details"]
            raw = {
                "rule_based": rs._rule_based_decision_score(d["rule_based"], True, False, ignore_url_part=False),
                "blacklist": rs._blacklist_decision_score(d["blacklist"]),
                "url_model": rs._model_decision_score(d["url_model"]),
            }
            no_allow = rs._tier_from_score(max(raw.values()))
            rec.update({
                "allowlisted": int(r["allowlisted"]), "verdict_live": r["verdict"], "verdict_no_allowlist": no_allow,
                "decided_by_no_allowlist": max(raw, key=raw.get) if no_allow != "LOW" else "",
                **{f"tier_{e}_no_allowlist": rs._tier_from_score(raw[e]) for e in ENGINES},
                "url_model_probability": d["url_model"]["probability"], "error": "",
            })
        except Exception as exc:
            db.rollback()
            rec["error"] = f"{type(exc).__name__}: {exc}"[:200]
        records.append(rec)
    db.close()
    df = pd.DataFrame(records)
    df.to_csv(SCORES_PATH, index=False)

    errors = df[df["error"] != ""]
    df = df[df["error"] == ""]
    out = ["ETIS allowlist override measurement: allowlisted Egyptian-brand URLs the system would flag WITHOUT the override",
           "Live scorer + evaluation DB (training-split-only blacklist); 'no allowlist' recomputed from the same engine outputs.",
           f"errors excluded: {len(errors)}",
           "Rates are per URL; URLs of one brand host are not independent, so also read the per-host counts."]
    order = sorted(df["set"].unique(), key=lambda s: (not s.startswith("dataset_test"), s))
    for name in order:
        part = df[df["set"] == name]
        legit = part[part["label"] == "legitimate"]
        phish = part[part["label"] == "phishing"]
        out += ["", f"== {name} (legitimate n = {len(legit):,}, hosts = {legit['host'].nunique()}, brand domains = {legit['brand_domain'].nunique()}) =="]
        if name == "dataset_train":
            out.append("  NOTE: training rows; the URL model was fitted on them, so this understates the effect.")
        if len(legit):
            out.append(f"  allowlisted (live): {rate(int(legit['allowlisted'].sum()), len(legit))}")
            out.append(f"  live verdict >= MEDIUM: {rate(int(legit['verdict_live'].isin(['MEDIUM', 'HIGH']).sum()), len(legit))}")
            med = legit["verdict_no_allowlist"].isin(["MEDIUM", "HIGH"])
            out.append(f"  WITHOUT allowlist >= MEDIUM: {rate(int(med.sum()), len(legit))}")
            out.append(f"  WITHOUT allowlist HIGH:      {rate(int((legit['verdict_no_allowlist'] == 'HIGH').sum()), len(legit))}")
            for e in ENGINES:
                k = int(legit[f"tier_{e}_no_allowlist"].isin(["MEDIUM", "HIGH"]).sum())
                out.append(f"    {e:<11} alone >= MEDIUM: {rate(k, len(legit))}")
            if legit["url_type"].nunique() > 1:
                out.append("  by URL type (without allowlist >= MEDIUM):")
                for t, g in legit.groupby("url_type"):
                    out.append(f"    {t:<20} {rate(int(g['verdict_no_allowlist'].isin(['MEDIUM', 'HIGH']).sum()), len(g))}")
            hosts = legit.groupby("brand_domain").agg(n=("id", "size"), flagged=("verdict_no_allowlist",
                                                                           lambda s: int(s.isin(["MEDIUM", "HIGH"]).sum())))
            hosts = hosts[hosts["flagged"] > 0].sort_values("flagged", ascending=False)
            out.append(f"  brand domains with >= 1 URL flagged without the allowlist: {len(hosts)} of {legit['brand_domain'].nunique()} (flagged / URLs)")
            for host, r in hosts.head(25).iterrows():
                out.append(f"    {host:<32} {r['flagged']:>4} / {r['n']:<4}")
        if len(phish):
            out.append(f"  rows labelled PHISHING on an allowlisted host: {len(phish)} "
                       f"(live >= MEDIUM {int(phish['verdict_live'].isin(['MEDIUM', 'HIGH']).sum())}, "
                       f"without allowlist >= MEDIUM {int(phish['verdict_no_allowlist'].isin(['MEDIUM', 'HIGH']).sum())}); "
                       f"hosts: {sorted(phish['host'].unique())[:10]}")
    obs = df[df["set"] == "observed"]
    if len(obs):
        out += ["", "== observed browser URLs (url_model probability; MEDIUM threshold from the artifact) =="]
        for r in obs.itertuples(index=False):
            out.append(f"  {r.id}: p = {float(r.url_model_probability):.4f}, without allowlist {r.verdict_no_allowlist}, live {r.verdict_live}")
    out += ["", "Reading guide",
            " - The constructed sets are the allowlist's own test rows (paths, subdomains, quirks on the brands' domains);",
            "   dataset_test is the only set of REAL brand URLs the model never trained on. Quote it, with its host count.",
            " - A high 'without allowlist' rate means the allowlist is load-bearing: removing or shrinking it would raise",
            "   false positives on the brands' own sites. It is not a reason to retune anything on these rows."]
    report = "\n".join(out)
    print(report)
    REPORT_PATH.write_text(report + "\n", encoding="utf-8")
    print(f"\nSaved {REPORT_PATH} and {SCORES_PATH}")


if __name__ == "__main__":
    main()
