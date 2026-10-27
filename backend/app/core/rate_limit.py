"""
rate_limit.py

Rate limiting via slowapi (built on the `limits` package).

POST /analyze has two limits, both checked on every scan:
    ETIS_ANALYZE_RATE_LIMIT     per caller: one dashboard session or one API
                                client (default 20/minute)
    ETIS_ANALYZE_IP_RATE_LIMIT  per client IP (default 60/minute), so one
                                machine cannot multiply its allowance by
                                opening many sessions
POST /session has its own per-IP limit (ETIS_SESSION_RATE_LIMIT, default
10/minute), on top of the Turnstile bot check.

/analyze is the expensive endpoint (model inference + a DB write per call).
/threats and /stats are cheap reads and are left unlimited.

The per-caller key comes from request.state.caller, which the
require_caller dependency sets before the route (and so the limit check)
runs. With authentication off, the caller is the IP address.
"""

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings

ANALYZE_RATE_LIMIT = settings.analyze_rate_limit
ANALYZE_IP_RATE_LIMIT = settings.analyze_ip_rate_limit
SESSION_RATE_LIMIT = settings.session_rate_limit


def caller_key(request: Request) -> str:
    caller = getattr(request.state, "caller", None)
    return caller.rate_limit_key if caller is not None else f"ip:{get_remote_address(request)}"


limiter = Limiter(key_func=get_remote_address)
