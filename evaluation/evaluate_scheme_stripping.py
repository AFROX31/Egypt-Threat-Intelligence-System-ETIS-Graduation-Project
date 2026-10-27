"""
evaluate_scheme_stripping.py

What does the scheme-less "https://" assumption cost?

url_model_inference.ensure_scheme() scores a URL typed without a scheme
("cibeg-verify.top/login") as if it were "https://...". Every URL in the
dataset carries a scheme, so the headline numbers never exercise that path.
This script takes the TEST-split URL rows, strips the scheme, and rescores
them through the real scorer (calculate_final_risk_score), in three variants:

  original   the URL exactly as stored (http:// or https://)
  stripped   scheme removed -> served as https:// by ensure_scheme(); the rule
             engine's no_https flag no longer fires (it needs an explicit http://)
  as_http    scheme replaced by http:// (what the opposite assumption would give)

The cost of the assumption is original -> stripped, measured separately for
URLs that were http:// and https:// originally (for https:// rows the model
input is identical, so any change there comes from the rule engine or the
blacklist key). as_http shows what the other choice would have cost.

Honesty rules
  * TEST split only, against the evaluation database (training-split-only
    blacklist); refused otherwise. Nothing here changes a threshold or a rule.
  * Unseen-host rows (group_type == 'host') are the headline; shared-platform
    rows are reported separately, never pooled. Wilson 95% intervals; paired
    exact McNemar between variants on the same rows.
  * The stripped URLs are SYNTHETIC inputs (real users paste both forms; how
    often they omit the scheme is not measured here).

Outputs (counts only, no URLs in the report):
  evaluation/scheme_stripping_scores.csv   per row and variant: id, label, group, tiers
  evaluation/scheme_stripping_report.txt

Usage (project root, venv active, DATABASE_URL -> etis_eval in the same window):
    python evaluation/evaluate_scheme_stripping.py
    python evaluation/evaluate_scheme_stripping.py --analyze-only
"""

import argparse
import math
import re
import sys
import time
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

DATASET_PATH = PROJECT_ROOT / "data" / "processed" / "dataset.csv"
GROUPS_PATH = PROJECT_ROOT / "data" / "processed" / "split_groups.csv"
SCORES_PATH = PROJECT_ROOT / "evaluation" / "scheme_stripping_scores.csv"
REPORT_PATH = PROJECT_ROOT / "evaluation" / "scheme_stripping_report.txt"
SYNTHETIC_SOURCE = "synthetic_egyptian_brands"
ENGINES = ("rule_based", "blacklist", "url_model")
VARIANTS = ("original", "stripped", "as_http")
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def variant_url(url: str, variant: str) -> str:
    if variant == "original":
        return url
    bare = SCHEME_RE.sub("", url.strip(), count=1)
    return bare if variant == "stripped" else "http://" + bare


def original_scheme(url: str) -> str:
    m = SCHEME_RE.match(url.strip())
    return m.group(0)[:-3].lower() if m else "none"


def score(args) -> None:
    from app.core.database import SessionLocal, engine
    from app.engines.risk_scoring import calculate_final_risk_score

    database = engine.url.database or ""
    print(f"Database: {engine.url.render_as_string(hide_password=True)}")
    if "eval" not in database:
        sys.exit("Refusing to run: DATABASE_URL does not point at the evaluation database (etis_eval).")

    df = pd.read_csv(DATASET_PATH, dtype=str, keep_default_na=False)
    df = df[(df["split"] == "test") & (df["content_type"] == "url") & (df["source"] != SYNTHETIC_SOURCE)]
    df = df.merge(pd.read_csv(GROUPS_PATH, dtype=str)[["id", "group_type"]], on="id", how="left")
    print(f"{len(df):,} test URL rows x {len(VARIANTS)} variants")

    db = SessionLocal()
    records, start = [], time.time()
    for n, row in enumerate(df.itertuples(index=False), start=1):
        for variant in VARIANTS:
            rec = {"id": row.id, "label": row.label, "group_type": row.group_type,
                   "scheme": original_scheme(row.text), "variant": variant}
            try:
                r = calculate_final_risk_score(url=variant_url(row.text, variant), db=db)
                rec.update({"verdict": r["verdict"], "allowlisted": int(r["allowlisted"]),
                            **{f"tier_{e}": r["engine_tiers"].get(e, "") for e in ENGINES}, "error": ""})
            except Exception as exc:
                db.rollback()
                rec["error"] = f"{type(exc).__name__}: {exc}"[:200]
            records.append(rec)
        if n % 1000 == 0:
            print(f"  ...{n:,}/{len(df):,} ({time.time() - start:.0f}s)")
    db.close()
    pd.DataFrame(records).to_csv(SCORES_PATH, index=False)
    print(f"Scored in {time.time() - start:.0f}s -> {SCORES_PATH}")


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
        return "n/a (n=0)".ljust(34)
    lo, hi = wilson(k, n)
    return f"{100 * k / n:5.1f}% [{100 * lo:5.1f}, {100 * hi:5.1f}] ({k}/{n})".ljust(34)


def mcnemar_exact(b: int, c: int) -> float:
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def flag(series: pd.Series, level: str) -> pd.Series:
    return series.isin(["MEDIUM", "HIGH"]) if level == "MEDIUM+" else series == "HIGH"


def block(out: list, title: str, wide: pd.DataFrame) -> None:
    out += ["", f"== {title} =="]
    if wide.empty:
        out.append("  (no rows)")
        return
    for name, what in (("phishing", "recall"), ("legitimate", "false-positive rate")):
        part = wide[wide["label"] == name]
        out.append(f"  {name} (n = {len(part):,}), {what}:")
        for scheme in ["all", "https", "http"]:
            sub = part if scheme == "all" else part[part["scheme"] == scheme]
            if sub.empty:
                continue
            for level in ("MEDIUM+", "HIGH"):
                cells = []
                for column in ("verdict", "tier_url_model"):
                    flags = {v: flag(sub[f"{column}_{v}"], level) for v in VARIANTS}
                    k = {v: int(flags[v].sum()) for v in VARIANTS}
                    b = int((flags["original"] & ~flags["stripped"]).sum())
                    c = int((~flags["original"] & flags["stripped"]).sum())
                    cells.append((column, k, b, c))
                for column, k, b, c in cells:
                    who = "system   " if column == "verdict" else "url_model"
                    out.append(f"    {scheme:<5} {level:<7} {who}  original {rate(k['original'], len(sub))} "
                               f"stripped {rate(k['stripped'], len(sub))} as_http {rate(k['as_http'], len(sub))} "
                               f"orig->stripped lost {b}, gained {c}, McNemar p = {mcnemar_exact(b, c):.4f}")


def analyze() -> None:
    df = pd.read_csv(SCORES_PATH, dtype=str, keep_default_na=False)
    errors = df[df["error"] != ""]
    ok_ids = set(df["id"]) - set(errors["id"])
    df = df[df["id"].isin(ok_ids)]
    wide = df.pivot(index="id", columns="variant",
                    values=["verdict", "tier_url_model", "tier_rule_based", "tier_blacklist", "allowlisted"])
    wide.columns = [f"{a}_{b}" for a, b in wide.columns]
    meta = df[df["variant"] == "original"].set_index("id")[["label", "group_type", "scheme"]]
    wide = meta.join(wide).reset_index()

    out = ["ETIS scheme-stripping test: cost of the scheme-less 'https://' assumption (TEST split, final system)",
           "Variants: original (as stored) | stripped (no scheme -> ensure_scheme() serves it as https://) | as_http.",
           "The stripped/as_http URLs are SYNTHETIC inputs; thresholds and rules unchanged; evaluation DB only.",
           f"rows: {len(wide):,} URLs scored in all three variants; rows with an error in any variant excluded: "
           f"{errors['id'].nunique()}",
           f"original schemes: {wide['scheme'].value_counts().to_dict()}",
           *[f"  errors: variant={v}, group={g}: {n} rows; first message: {m}" for (v, g), n, m in
             ((key, len(part), part['error'].iloc[0][:110]) for key, part in errors.groupby(['variant', 'group_type']))],
           *(["  (A 400 'no host name' on the stripped variant is an input-handling bug, not a scoring miss: a scheme-less",
              "   URL with '://' later in it, e.g. a redirect 'l.wl.co/l?u=https://...', was taken as already having a scheme.",
              "   Fixed 2026-10-26 by url_validation.has_scheme(); the pre-fix run is scheme_stripping_report_prefix.txt.)"]
             if len(errors) else []),
           "Paired exact McNemar compares original vs stripped on the same rows (lost = flagged only as original)."]
    block(out, "UNSEEN-HOST test URLs (group_type == 'host')  <- headline", wide[wide["group_type"] == "host"])
    for group in sorted(set(wide["group_type"]) - {"host"}):
        block(out, f"group_type == '{group}' (separate, never pooled)", wide[wide["group_type"] == group])

    host = wide[wide["group_type"] == "host"]
    out += ["", "== Which engine changed? unseen-host rows whose system verdict moved original -> stripped =="]
    moved = host[host["verdict_original"] != host["verdict_stripped"]]
    out.append(f"  rows with a different verdict: {len(moved):,}")
    for engine in ENGINES:
        changed = int((moved[f"tier_{engine}_original"] != moved[f"tier_{engine}_stripped"]).sum())
        out.append(f"    {engine:<11} tier changed in {changed:,} of them")
    out.append(f"  allowlist decision changed anywhere: "
               f"{int((wide['allowlisted_original'] != wide['allowlisted_stripped']).sum())} rows")

    out += ["", "Reading guide",
            " - For originally-https rows the URL model sees the same input after stripping, so their numbers should",
            "   hardly move; the cost of the assumption sits in the originally-http rows (a small share of the data).",
            " - 'as_http' is the counterfactual assumption. Compare stripped vs as_http on the http rows to see what",
            "   the https choice gives away (missed phishing) and on legitimate rows what it saves (fewer false positives).",
            " - The share of users who omit the scheme is unknown; this measures the per-URL cost, not its frequency."]
    report = "\n".join(out)
    print(report)
    REPORT_PATH.write_text(report + "\n", encoding="utf-8")
    print(f"\nSaved {REPORT_PATH}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analyze-only", action="store_true", help="re-read the saved scores, no rescoring")
    args = parser.parse_args()
    if not args.analyze_only:
        score(args)
    analyze()


if __name__ == "__main__":
    main()
