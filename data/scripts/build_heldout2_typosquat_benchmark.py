"""
build_heldout2_typosquat_benchmark.py

Builds the SECOND held-out Egyptian-brand typosquat benchmark ("held-out 2").

Why a second one: the first held-out set (egypt_brand_typosquats_heldout.csv,
2026-10-22) was frozen against the v1 URL model. The live URL model is now the
TLD-masked v2 artifact, so the freeze no longer holds, and the first set's
per-technique results have been read and written into CLAUDE.md. Held-out 2 is
generated BEFORE any result on it is seen and is scored against the current
live system only.

DEFENSIVE USE ONLY. Output is a CSV of URL STRINGS for testing detectors.
Nothing is registered, resolved, fetched or published; no organisation is
contacted. Never use it for training, and never tune rules on its results.

It reuses the technique generators of build_heldout_typosquat_benchmark.py
(same 31 technique names, so classes A-D stay comparable) and replaces every
vocabulary they draw from:
  * seed 20261026 (dev: 42, held-out 1: 20261021), chosen before any result;
  * keywords: none of the 12 dev keywords and none of the 57 held-out-1
    keywords. in_detector_vocab = the CONTEXT_TOKENS words neither earlier set
    used (only 8 are left, so that stratum is small); novel = new English and
    Franco-Arabic words, none a substring hit of SUSPICIOUS_MODIFIER_PATTERN;
  * aliases and full-name spellings: none from the registry, the dev ALIASES
    or held-out 1;
  * TLD pools: ordinary / abuse-prone-in-the-detector's-list / abuse-prone-NOT-
    in-the-list, with different TLDs from held-out 1 where the pools allow;
  * new paths, query parameters and word-based random hosts;
  * every typosquat row whose host is in the dev set, in held-out 1 or in
    dataset.csv is DROPPED;
  * real-company handling: same `ambiguity` column as held-out 1 (excluded from
    the headline, reported separately), plus a few more curated namesakes.
  * technique name brand_as_subdomain (never brand_subdomain).

Genuine and control rows: the genuine own-domain URLs are the same constructed
URLs as held-out 1 (they test the allowlist, not generalisation); controls are
the same real other organisations with new paths, written from memory (NOT
verified live) -- a warning only.

Usage (project root, venv active):
    python data/scripts/build_heldout2_typosquat_benchmark.py
Then, without changing any detector/scoring/model file:
    python evaluation/evaluate_heldout_typosquat_benchmark.py --set heldout2
"""

import csv
import json
import random
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_heldout_typosquat_benchmark as ho  # noqa: E402
from app.core.egyptian_brands import EGYPTIAN_BRAND_ALIAS_LABELS, EGYPTIAN_BRAND_DOMAINS  # noqa: E402

OUT_PATH = PROJECT_ROOT / "data" / "benchmarks" / "egypt_brand_typosquats_heldout2.csv"
MANIFEST_PATH = PROJECT_ROOT / "data" / "benchmarks" / "heldout2_manifest.json"
HELDOUT1_PATH = PROJECT_ROOT / "data" / "benchmarks" / "egypt_brand_typosquats_heldout.csv"

SEED = 20261026

# ---- vocabularies (checked against the two earlier sets below) -------------------------------
HO1_KEYWORDS = set(ho.KW_IN_DETECTOR_VOCAB) | set(ho.KW_NOVEL)

KW_IN_DETECTOR_VOCAB = ["services", "pay", "banking", "ebanking", "cards", "customers", "offers", "web"]
KW_NOVEL = [
    "access", "review", "pending", "blocked", "renew", "approval", "register", "balance", "cashback",
    "points", "voucher", "coupon", "checkout", "order", "track", "sms", "code", "pin", "token", "agent",
    "desk", "dashboard", "profile", "settings", "reward", "winner", "lucky", "free", "urgent", "now",
    "flous", "mahfaza", "tasdeek", "talab", "ta2keed", "geneeh",
]

ALIASES_HO2 = {
    "cibeg.com": ["cibegy", "cib-bank-eg", "cibmasr"],
    "nbe.com.eg": ["ahlybank", "elahly-bank", "nbe-ahly"],
    "banquemisr.com": ["banquemisrbank", "bmisr", "banque-masr"],
    "qnbalahli.com": ["alahliqnb", "qnb-alahly", "qnbalahlibank"],
    "qnb.com.eg": ["qnbegy", "qnb-masr-bank", "qnbegypt-bank"],
    "aaib.com": ["aaibegy", "aaib-bank", "arab-african-bank"],
    "vodafone.com.eg": ["vodafonmasr", "voda-cash", "vf-masr"],
    "orange.eg": ["orangemasr", "orange-cash-eg", "orangeegypt-cash"],
    "etisalat.eg": ["etisalatmasr", "etisalat-cash", "etisalategy"],
    "eand.com.eg": ["eandmasr", "eand-money", "e-and-cash"],
    "te.eg": ["we-masr", "wetelecom", "te-masr"],
    "instapay.eg": ["insta-pay-masr", "instapaymasr", "instapay-egy"],
    "fawry.com": ["fawrymasr", "fawry-payment-eg", "fawryegy"],
    "jumia.com.eg": ["jumiaegy", "jumia-masr", "jumia-store-eg"],
    "noon.com": ["noonegy", "noon-masr", "noon-store-eg"],
    "amazon.eg": ["amazonegy", "amazon-masr-store", "amazn-eg"],
    "talabat.com": ["talabategy", "talabat-masr", "talabat-order"],
    "breadfast.com": ["breadfastegy", "breadfast-masr", "breadfastorder"],
    "egyptair.com": ["egyptairways", "egypt-airways", "masr-lilteran"],
    "digital.gov.eg": ["masrdigital", "digitalegypt-gov", "gov-digital-masr"],
}
FULLNAMES_HO2 = {
    "cibeg.com": ["commercial-intl-bank-egypt", "cibcommercialbank"],
    "nbe.com.eg": ["national-bank-egypt-ahly", "albankalahly"],
    "banquemisr.com": ["banque-misr-egypt"],
    "qnbalahli.com": ["qnb-al-ahli-egypt", "qatarnationalbankalahli"],
    "aaib.com": ["arab-african-intl-bank", "arabafricanintlbank"],
    "te.eg": ["telecom-egypt-company", "telecomegyptco"],
    "egyptair.com": ["egypt-air-lines"],
    "digital.gov.eg": ["egypt-digital-government", "digitalegyptportal"],
}

ORD_TLDS = [".com", ".net", ".org", ".co", ".us", ".tv", ".ai"]
ABUSE_IN_LIST = [".top", ".xyz", ".online", ".buzz", ".cfd", ".sbs", ".work"]
ABUSE_NOT_IN_LIST = [".rest", ".monster", ".quest", ".beauty", ".hair", ".skin", ".mom", ".autos", ".boats", ".cyou"]
PATHS_HO2 = ["/ar/verify-code", "/wallet/limit", "/card/blocked", "/otp/resend", "/profile/edit",
             "/reward/redeem", "/session/expired", "/pay/confirm-order"]
QUERY_PARAMS_HO2 = ["dest", "target", "r", "back", "link", "to"]
WORDS_HO2 = ["coral", "sahara", "oasis", "zephyr", "ember", "willow", "quartz", "lagoon", "comet",
             "atlas", "papyrus", "mango"]
CONTROL_PATHS_HO2 = ["/sports", "/en", "/search", "/privacy"]
EXTRA_REAL_ORGS = {"cib.com", "nbe.com", "fawry.net", "amazon.co", "noon.co", "orange.co", "talabat.net"}


def check_vocab() -> None:
    from app.engines.rule_based.domain_typosquatting_detector import CONTEXT_TOKENS, SUSPICIOUS_MODIFIER_PATTERN

    kws = set(KW_IN_DETECTOR_VOCAB) | set(KW_NOVEL)
    assert not kws & ho.DEV_KEYWORDS, "keyword overlaps the dev set"
    assert not kws & HO1_KEYWORDS, f"keyword overlaps held-out 1: {kws & HO1_KEYWORDS}"
    assert set(KW_IN_DETECTOR_VOCAB) <= CONTEXT_TOKENS, "in_detector_vocab word missing from CONTEXT_TOKENS"
    assert not set(KW_NOVEL) & CONTEXT_TOKENS, "novel word is in CONTEXT_TOKENS"
    hits = [k for k in KW_NOVEL if SUSPICIOUS_MODIFIER_PATTERN.search(k)]
    assert not hits, f"novel word hits SUSPICIOUS_MODIFIER_PATTERN: {hits}"
    new_aliases = {a for v in ALIASES_HO2.values() for a in v} | {a for v in FULLNAMES_HO2.values() for a in v}
    old_aliases = ({a for v in EGYPTIAN_BRAND_ALIAS_LABELS.values() for a in v}
                   | {a for v in ho.ALIASES_HO.values() for a in v} | {a for v in ho.FULLNAMES_HO.values() for a in v})
    dev_aliases = set()
    try:
        import build_typosquat_benchmark as dev
        dev_aliases = {a for v in dev.ALIASES.values() for a in v}
    except Exception as exc:  # the dev builder is optional for this check
        print(f"WARNING: could not import the dev builder's ALIASES ({exc}); dev-alias overlap not checked")
    clash = new_aliases & (old_aliases | dev_aliases)
    assert not clash, f"alias overlaps an earlier set or the registry: {clash}"


def install_vocabulary() -> None:
    """Point the held-out-1 generators at the held-out-2 vocabulary (they read module globals)."""
    ho.SEED = SEED
    ho.KW_IN_DETECTOR_VOCAB = KW_IN_DETECTOR_VOCAB
    ho.KW_NOVEL = KW_NOVEL
    ho.VOCABS = [("in_detector_vocab", KW_IN_DETECTOR_VOCAB), ("novel", KW_NOVEL)]
    ho.ORD_TLDS, ho.ABUSE_IN_LIST, ho.ABUSE_NOT_IN_LIST = ORD_TLDS, ABUSE_IN_LIST, ABUSE_NOT_IN_LIST
    ho.ALL_TLDS = ORD_TLDS + ABUSE_IN_LIST + ABUSE_NOT_IN_LIST
    ho.TLD_GROUP = {
        **{t.lstrip("."): "ordinary" for t in ORD_TLDS},
        **{t.lstrip("."): "abuse_in_detector_list" for t in ABUSE_IN_LIST},
        **{t.lstrip("."): "abuse_not_in_detector_list" for t in ABUSE_NOT_IN_LIST},
    }
    ho.ABUSE_ALL = ho.ABUSE_ALL | {t.lstrip(".") for t in ABUSE_IN_LIST + ABUSE_NOT_IN_LIST}
    ho.PATHS_HO, ho.QUERY_PARAMS, ho.WORDS = PATHS_HO2, QUERY_PARAMS_HO2, WORDS_HO2
    ho.ALIASES_HO, ho.FULLNAMES_HO = ALIASES_HO2, FULLNAMES_HO2
    ho.CONTROL_PATHS = CONTROL_PATHS_HO2
    ho.REAL_ORG_REGISTRABLES = ho.REAL_ORG_REGISTRABLES | EXTRA_REAL_ORGS


def main() -> None:
    check_vocab()
    install_vocabulary()

    for path in (ho.DEV_PATH, HELDOUT1_PATH):
        if not path.exists():
            sys.exit(f"{path} not found: without it overlap cannot be excluded.")
    excluded = ho.load_hosts_from_csv(ho.DEV_PATH) | ho.load_hosts_from_csv(HELDOUT1_PATH)
    dataset_hosts = ho.load_hosts_from_csv(ho.DATASET_PATH, lambda r: r.get("content_type") == "url") \
        if ho.DATASET_PATH.exists() else None
    if dataset_hosts is None:
        print(f"WARNING: {ho.DATASET_PATH} not found; overlap with the dataset NOT excluded.")

    rows, stats = ho.build(excluded, dataset_hosts)
    # ho.build counts dev+held-out-1 overlaps under its dev label; rename for clarity
    if "dropped_host_in_dev_benchmark" in stats:
        stats["dropped_host_in_dev_or_heldout1"] = stats.pop("dropped_host_in_dev_benchmark")
    for r in rows:
        r["id"] = r["id"].replace("HT-", "H2T-").replace("HG-", "H2G-").replace("HC-", "H2C-")
        r["host_in_dataset"] = ("unknown" if dataset_hosts is None else str(int(ho.host_of(r["url"]) in dataset_hosts)))

    fields = ["id", "url", "brand", "brand_domain", "technique", "kind", "family", "keyword_vocab",
              "tld_group", "brand_size", "ambiguity", "host_in_dataset"]
    with open(OUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    typo = [r for r in rows if r["kind"] == "typosquat"]
    kinds = Counter(r["kind"] for r in rows)
    manifest = {
        "set": "heldout2", "seed": SEED, "per_technique": ho.PER_TECHNIQUE,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "csv_sha256": ho.normalised_sha256(OUT_PATH),
        "rows": dict(kinds), "dropped": dict(stats),
        "ambiguity_counts": dict(Counter(r["ambiguity"] or "none" for r in typo)),
        "git": ho.git_state(), "freeze_files": ho.fingerprint(),
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"Wrote {len(rows):,} rows to {OUT_PATH}")
    print(f"  typosquat={kinds['typosquat']:,}  genuine={kinds['genuine']:,}  control={kinds['control']:,}")
    print(f"  typosquats marked ambiguous (excluded from headline): {sum(1 for r in typo if r['ambiguity']):,}")
    print(f"  dropped candidates: {dict(stats)}")
    per_tech = Counter(r["technique"] for r in typo)
    print("typosquats per technique:")
    for t in sorted(per_tech):
        print(f"  {t:<28}{per_tech[t]:>5}")
    print(f"\nManifest: {MANIFEST_PATH}")
    print("Do not change the detector, registry, scoring or model files before running the evaluation.")


if __name__ == "__main__":
    random.seed(SEED)
    main()
