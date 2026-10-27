"""
link_extraction.py

Finds the links inside a message text, so POST /analyze can send them to the
URL engines (blacklist + learned URL model) instead of judging the message by
its words alone. Added 2026-10-26; before this, only the dashboard looked for a
link in pasted text (the first http(s) one, in ScanPage.tsx), and API or
extension callers that sent text only never had their links checked.

Three shapes are recognised, in the order they appear in the text:
    1. scheme links          https://nbe-update.com/login, http://1.2.3.4/x
    2. www. links            www.cib-egypt.net/verify
    3. bare domains          nbe-update.com/login (common in SMS phishing)
Bare domains only count when their last label is in COMMON_BARE_TLDS: a
general "word.word" rule would turn "file.txt", "e.g" or a missing space after
a full stop ("done.Next") into links. A bare domain directly after "@" is an
email address, not a link, and is skipped.

Trailing punctuation that ends a sentence (. , ; : ! ? and the Arabic ، ؛ ؟)
and unbalanced closing brackets/quotes are trimmed. Links without a host
(a lone "https://") are dropped, so they can never turn a valid text scan
into a 400. Duplicates are removed, keeping the first occurrence.

This finds links; it does not judge them. Every link found is scored by the
same engines as a URL typed into the URL field.
"""

import re
from urllib.parse import urlsplit

from app.core.exceptions import InvalidScanInputError
from app.core.url_validation import ensure_url_has_host, has_scheme

# Short, deliberately conservative list: generic TLDs seen in phishing feeds
# plus Egypt's own. A bare domain with any other TLD is not picked up (a
# scheme or www. link always is, whatever its TLD).
COMMON_BARE_TLDS = frozenset({
    "com", "net", "org", "info", "biz", "eg", "io", "co", "me", "app", "dev",
    "xyz", "top", "online", "site", "website", "link", "live", "click", "shop",
    "store", "support", "services", "vip", "icu", "buzz", "cc", "ly", "tk",
    "ml", "ga", "cf", "gq", "sbs", "cfd", "bond", "help", "today", "work",
})

_URL_BODY = r"[^\s<>\"'`]+"

_SCHEME_OR_WWW_RE = re.compile(
    rf"(?:\b(?:https?|ftp)://{_URL_BODY})|(?:(?<![\w.-])www\.{_URL_BODY})",
    re.IGNORECASE,
)

# host: one or more labels, then a letters-only TLD; optional port and path.
_BARE_DOMAIN_RE = re.compile(
    r"(?<![\w@.-])"
    r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))"
    rf"(?::\d{{1,5}})?(?:[/?#]{_URL_BODY})?",
    re.IGNORECASE,
)

_TRAILING_PUNCTUATION = ".,;:!?،؛؟…"
_BRACKET_PAIRS = {")": "(", "]": "[", "}": "{"}


def _trim(candidate: str) -> str:
    while candidate:
        last = candidate[-1]
        if last in _TRAILING_PUNCTUATION:
            candidate = candidate[:-1]
        elif last in _BRACKET_PAIRS and candidate.count(last) > candidate.count(_BRACKET_PAIRS[last]):
            candidate = candidate[:-1]
        else:
            break
    return candidate


def _has_host(candidate: str) -> bool:
    try:
        ensure_url_has_host(candidate)
    except InvalidScanInputError:
        return False
    return True


def link_identity(link: str) -> str:
    """Comparison key for de-duplication: the scheme, the host's letter case
    and a trailing slash are ignored, so https://X.com/ and x.com are one link."""
    candidate = link.strip()
    if not has_scheme(candidate):
        candidate = "http://" + candidate
    try:
        parts = urlsplit(candidate)
        host = (parts.hostname or "").lower()
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return link.strip().lower()
    rest = parts.path.rstrip("/")
    if parts.query:
        rest += "?" + parts.query
    return host + port + rest


def extract_links(text: str | None) -> list[str]:
    """Return the links in `text`, in order of appearance, de-duplicated."""
    if not text:
        return []

    found: list[tuple[int, str]] = []
    taken: list[tuple[int, int]] = []

    for match in _SCHEME_OR_WWW_RE.finditer(text):
        found.append((match.start(), match.group(0)))
        taken.append(match.span())

    for match in _BARE_DOMAIN_RE.finditer(text):
        start, end = match.span()
        if any(start < t_end and end > t_start for t_start, t_end in taken):
            continue  # part of a scheme/www link already found
        if match.group(2).lower() not in COMMON_BARE_TLDS:
            continue
        found.append((start, match.group(0)))

    links: list[str] = []
    seen: set[str] = set()
    for _, raw in sorted(found):
        link = _trim(raw)
        if not link or not _has_host(link):
            continue
        key = link_identity(link)
        if key in seen:
            continue
        seen.add(key)
        links.append(link)
    return links
