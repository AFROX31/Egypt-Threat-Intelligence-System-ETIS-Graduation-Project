"""
serve_for_benchmark.py

Starts the real ETIS FastAPI app for benchmark_api_performance.py with the
/analyze rate limit (20/minute, app/core/rate_limit.py) switched OFF in this
process only. The benchmark sends ~220 /analyze requests in a few seconds;
with the limit on, almost all of them come back as 429 and the latency
numbers would time the rejection, not the scan. Nothing in backend/ is
changed: the limiter object is disabled after import, before serving.

(If app/core/config.py's ETIS_ANALYZE_RATE_LIMIT setting is available, setting
it to e.g. "100000/minute" for a plain uvicorn run is equivalent.)

Everything else is the normal app (same routers, models, warm-up, database).
Leave ETIS_SKIP_WARMUP UNSET so the models are loaded before the first request
(otherwise the first scan pays the ~7 s model load).

Run from the project root (venv active), in its own terminal:
    python evaluation/serve_for_benchmark.py
then, in a second terminal:
    python evaluation/benchmark_api_performance.py

Never use this to serve the demo: the rate limit protects the hosted /analyze.
"""

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

import uvicorn  # noqa: E402

from app.core.rate_limit import limiter  # noqa: E402
from app.main import app  # noqa: E402

limiter.enabled = False

if __name__ == "__main__":
    if os.getenv("ETIS_SKIP_WARMUP"):
        print("WARNING: ETIS_SKIP_WARMUP is set; the first request will include the model load.")
    print("Rate limit DISABLED in this process (benchmark only).")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
