# Evaluation hardening run, 26 Oct 2026

All numbers below come from a cloud copy of the project folder (snapshot taken 26 Oct around 17:50 UTC), scored against a freshly seeded `etis_eval` database (blacklist from the TRAIN split only: 44,272 entries, 18 brands / 20 domains). That copy used the same Python package versions as `requirements.txt`, but PostgreSQL 16, not 15. **Live URL model = the TLD-masked v2 artifact** (`ml/models/url_ensemble.joblib`, created 2026-10-26, thresholds MEDIUM 0.668 / HIGH 0.872; its scores are identical to `ml/ablation/url_ensemble_tldmasked.joblib`). No backend, rule or model file was changed.

## 1. Second held-out typosquat benchmark ("held-out 2")

Why: the first held-out set (22 Oct) was frozen against the v1 URL model, so its freeze check now fails, and its per-technique results are already written in CLAUDE.md. Held-out 2 was generated before any result on it was seen.

- Builder `data/scripts/build_heldout2_typosquat_benchmark.py`. It reuses the held-out-1 generators, so the 31 technique names and classes A to D stay comparable. Seed 20261026. Keywords: none from the dev set or held-out 1 (in-detector stratum = the only 8 `CONTEXT_TOKENS` words left; novel = 36 new English and Franco-Arabic words). New aliases and full names, new TLD pools, paths and word hosts. Real-company rows are marked in the `ambiguity` column and left out of the headline. `brand_as_subdomain` naming. 1,759 candidates were dropped because their host is in the dev set or held-out 1, and 2 because it is in `dataset.csv`.
- Files: `data/benchmarks/egypt_brand_typosquats_heldout2.csv` (1,668 typosquats: 1,626 headline + 42 ambiguous; 280 genuine; 84 controls) and `heldout2_manifest.json` (the freeze fingerprint). The evaluator is `evaluate_heldout_typosquat_benchmark.py --set heldout2` (new option; the default still runs held-out 1). Freeze check: **PASSED**. Report: `evaluation/heldout2_typosquat_report.txt`. Afterwards, the `has_scheme()` fix changed four frozen files (url_validation, url_model_inference, url_pattern_analyzer, domain_typosquatting_detector). It came from the scheme-stripping bug, not from these results. A development re-run (`heldout2_typosquat_report_postfix_check.txt`) scored all 2,032 rows byte-identically, so the frozen result stands. The freeze check will now refuse a plain re-run, which is expected; use `--allow-changed-files` and call it a check run.
- **Caveat on design:** the deterministic single-edit techniques are almost used up by the two earlier sets. Omission, repetition, transposition and IDN have n = 1 to 4, and digit_lookalike and hyphen_insertion are gone, so class A is now mostly embedding and userinfo rows.

Results (>= MEDIUM, Wilson 95%; the CIs are optimistic because rows share 20 brands):

| Class | n | Held-out 2 (v2 model) | Held-out 1 (v1 model, 22 Oct) |
|---|---|---|---|
| A rule built before dev set (partly circular) | 250 | 100.0% [98.5, 100.0] | 100% [99.1, 100.0] |
| B pre-existing edit-distance rule | 336 | 97.6% [95.4, 98.8] | 96.1% [93.8, 97.5] |
| C rules built from dev misses | 697 | 81.3% [78.3, 84.1] | 84.6% [81.8, 87.1] |
| **D no dedicated rule (generalisation)** | 343 | **37.0% [32.1, 42.3]** | 43.5% [38.7, 48.4] |

- Novel keywords 62.1% [56.6, 67.3] vs in-detector words 78.0% [73.1, 82.3]. Short brands 67.8% vs normal 82.0%; te.eg 44.2%. The rule engine names the intended brand 97.8% of the time. HIGH 22.1% overall. The pooled 78.2% must not be quoted as "the" result.
- Genuine own-domain: 0/280 flagged, 280/280 allowlisted. Ambiguous rows: 0/42 flagged.
- **Controls, a new warning about v2:** real other organisations were flagged 22/48 URLs (v1 on held-out 1: 7/48). The v2 model reads `amazon.de`, `orange.fr`, `jumia.co.ke` and similar sites as "brand.tld", so every Amazon/Orange/Jumia country site scores about the same (Amazon 0.72 to 0.77, Orange about 0.85, Jumia ng/ke 0.92 = HIGH; v1 gave most of them about 0.5). Real Egyptian sites: 9/36 URLs, 5 hosts (youm7 and olx.com.eg reach HIGH). The control lists were written from memory and the effective n is the number of domains (18 to 24), so treat this as a warning. Still, the 24 Oct promotion criterion C3 only checked `.eg` sites, and this is a side effect it did not cover.
- Not comparable with held-out 1 as a before/after: the vocabulary and the model both changed. Report them side by side.

## 2. Cost of the scheme-less "https://" assumption

`evaluation/evaluate_scheme_stripping.py` scores every TEST URL three times through the real scorer: as stored, with the scheme stripped (`ensure_scheme()` then serves it as https://), and as http://. Report: `evaluation/scheme_stripping_report.txt`.

Post-fix run (after the backend thread's `has_scheme()` fix; all 13,639 test URLs scored, 0 errors). Unseen-host test URLs (phishing n = 5,676, legitimate n = 4,147), >= MEDIUM:

| | original | stripped | as_http |
|---|---|---|---|
| phishing recall, all | 93.4% [92.7, 94.0] | 92.5% [91.8, 93.2] | 95.2% [94.6, 95.7] |
| phishing recall, originally http:// (n = 505) | 89.9% [87.0, 92.2] | **80.4% [76.7, 83.6]** | 89.9% |
| phishing recall, originally https:// | 93.7% | 93.7% (identical) | 95.7% |
| FPR, all legitimate | 0.9% [0.7, 1.3] | 0.9% [0.6, 1.2] | 2.0% [1.7, 2.5] |

- **Cost:** 48 of 505 http:// phishing URLs (9.5 points) drop to LOW when the scheme is missing (exact McNemar p < 0.0001), and HIGH falls from 80.0% to 71.7%. Every change came from the URL model; the rule engine and blacklist never moved. https:// URLs are unaffected.
- **Why keep it:** assuming http:// instead would recover those misses, but it would roughly double the FPR on legitimate URLs (0.9% to 2.0%) and add HIGH false positives (0 to 10 of 4,147). The https:// default is the right trade. State the cost in Chapter 7.
- **Bug found and fixed the same day:** in the first run, 84 test URLs (15 unseen-host, 69 shared-platform) could not be scanned at all once the scheme was stripped. They are redirect URLs like `l.wl.co/l?u=https://...`, which got a 400 "no host name" because a later `://` was taken as the scheme. The backend thread added `has_scheme()` (`app/core/url_validation.py`), which only counts a scheme at the start of the URL, and the table above is the post-fix re-run. The pre-fix report is kept as `scheme_stripping_report_prefix.txt`.
- The stripped inputs are synthetic; how often real users omit the scheme is not measured.

## 3. How load-bearing is the allowlist?

`evaluation/measure_allowlist_override.py` scores allowlisted brand URLs normally and recomputes the verdict without the override from the same engine outputs. Report: `evaluation/allowlist_override_report.txt`.

| Set | URLs (brand domains) | Flagged >= MEDIUM without allowlist | HIGH |
|---|---|---|---|
| Real crawled brand URLs, TEST split (hosts unseen in training) | 33 (7) | 0.0% [0.0, 10.4] | 0 |
| Constructed genuine, dev benchmark | 260 (20) | 38.1% [32.4, 44.1] | 15.8% |
| Constructed genuine, held-out sets | 280 (20) | 40.4% [34.8, 46.2] | 21.4% |
|   of which genuine subdomains (secure./my./portal./careers./help.) | 100 | 83.0% [74.5, 89.1] | |
|   URL quirks (upper case, :443, trailing dot, http) | 80 | 35.0% [25.5, 45.9] | |
|   paths on the bare domain | 100 | 2.0% [0.6, 7.0] | |
| Browser-observed cibeg.com URLs | 2 | 1 (homepage p = 0.76) | 0 |

- All of it comes from `url_model`; the rule engine and blacklist flag none of these URLs.
- So, with the v2 model, the allowlist is load-bearing for **brand subdomains and URL quirks** (19 to 20 of 20 brands affected), but the few real crawled brand pages in the test split were not flagged even without it. Only 33 real URLs from 7 brands, so this cannot rule out false positives on real brand pages. `www.cibeg.com/` still scores 0.76 (v1: 0.95), and `/login` now 0.58 (v1: 0.69), below the threshold.

## 4. Cleanup and latency

- Retired to `evaluation/retired/` (with a README): `calibrate_thresholds.py`, `evaluate_test_configurations.py` and their reports and figures. **If your laptop folder is the git repo, record the move with `git mv` (commands in the README).** I updated the references in `benchmark_api_performance.py` and `data/scripts/seed_database.py`.
- `benchmark_api_performance.py` needed two fixes. /analyze is now rate limited to 20/minute, so most benchmark requests would get a 429. A new `evaluation/serve_for_benchmark.py` starts the normal app with the limiter off in that process only, and the benchmark now stops with a clear message on a 429. The report also records which machine it ran on.
- Cloud run (4 vCPU Linux container, **not the laptop, so these are not Chapter 5.7 numbers**): `evaluation/api_benchmark_report_cloud_2026-10-26.txt`. /analyze median: URL 14.1 ms, text 5.1 ms, both about 14 ms. 85 req/s sequential, 82 req/s with 10 concurrent workers, 0 non-200 responses. About 325 MB RSS. Text is now much faster than in the old report (about 174 ms), because that report timed the BiLSTM.

### Re-run the latency benchmark on the laptop (for Chapter 5.7)

Window 1 (Command Prompt, project root): activate the same venv you use for uvicorn (`venv\Scripts\activate.bat`), then

    set ETIS_SKIP_WARMUP=
    python evaluation\serve_for_benchmark.py

Wait for "Rate limit DISABLED", then in Window 2 (project root, same venv activated):

    set ETIS_BENCHMARK_MACHINE=AFRO laptop
    python evaluation\benchmark_api_performance.py

Use `python` (not `py -3.13`) once the venv is active, or the venv's packages are skipped. Make sure no other uvicorn is running on port 8000 first.
This overwrites `evaluation/api_benchmark_report.txt` and the two PNGs. Close Window 1 afterwards (Ctrl+C). The scans are saved into whichever database `DATABASE_URL` points at.

## Suggested CLAUDE.md updates
- The live URL model is v2 (TLD-masked); held-out 1 is now historical (v1), and held-out 2 is the current held-out result.
- If any rule, scoring or model file changes after reading `heldout2_typosquat_report.txt`, held-out 2 becomes a development set. The single-edit candidate space is nearly used up, so a third set would need new technique families.
- Open: a verified real-site false-positive measurement is now more urgent (namesake sites under v2). The scheme-less redirect-URL 400 bug is fixed (`has_scheme()`).
