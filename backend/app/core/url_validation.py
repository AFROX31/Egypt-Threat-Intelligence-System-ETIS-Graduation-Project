"""
url_validation.py

Input check shared by the scoring layer: a submitted URL must have a host.

Before this check, a bare "https://" (or "http:///login", "https://@") reached
the engines and came back LOW (4.53 in a browser scan on 2026-10-19), because
the URL model scored an empty string. There is nothing to analyse in such an
input, and a green "no indicators" result is the wrong answer to it, so it is
rejected with a 400 like any other unusable input.

Deliberately NOT rejected here: URLs that have a host but cannot be fully
parsed (javascript:alert(1), a non-numeric or out-of-range port, a broken IPv6
literal). The rule engine already reports those with a malformed_url flag, and
changing that would change documented, tested behaviour.
"""

import re
from urllib.parse import urlsplit

from app.core.exceptions import InvalidScanInputError

# A scheme only counts at the START of the URL. Testing `"://" in url` (as
# this module, ensure_scheme() and url_pattern_analyzer.py once did) treats a
# scheme-less redirect such as "l.wl.co/l?u=https://qr-codes.io/x" as if it
# had a scheme, so no scheme was added and the host was lost (found
# 2026-10-26: 84 of 13,639 test URLs once their scheme was stripped).
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def has_scheme(url: str) -> bool:
    """True when `url` starts with a scheme such as https:// (leading spaces ignored)."""
    return _SCHEME_RE.match(url.lstrip()) is not None


def ensure_url_has_host(url: str) -> None:
    candidate = url.strip()
    if candidate.startswith("//"):  # scheme-relative, e.g. //example.com/path
        with_scheme = "http:" + candidate
    elif has_scheme(candidate):
        with_scheme = candidate
    else:  # scheme-less, e.g. wikipedia.org (scored as https:// by the URL model)
        with_scheme = "http://" + candidate
    try:
        host = urlsplit(with_scheme).hostname
    except ValueError:
        return  # unparseable but not hostless: left to the existing malformed_url handling
    if not host:
        raise InvalidScanInputError("The URL has no host name (for example 'https://' on its own).")
