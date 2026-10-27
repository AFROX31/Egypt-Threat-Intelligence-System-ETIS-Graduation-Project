"""
anonymise_messages.py

Step A of the real-message collection: turn a contributor's raw file into an
anonymised messages_<initials>.csv that ingest_real_messages.py accepts.
Runs fully offline on the collector's own laptop. Nothing is sent anywhere.

Input   data/raw/real_messages/raw_<initials>.csv
        same columns as data/raw/collection_template.csv
        (text, label, category, channel, language, brand, contributor,
         received_in_real_life), saved as CSV UTF-8.
Output  data/raw/real_messages/messages_<initials>.csv   anonymised, ready for ingest
        data/raw/real_messages/_review_<initials>.csv    before/after of every changed
                                                         row, for a human check
        Both stay in the git-ignored raw folder.

What it replaces (COLLECTION_GUIDE.md rule 2)
  - e-mail addresses                          -> [EMAIL]
  - phone numbers (Egyptian mobiles, +codes,
    landlines starting with 0)                -> [PHONE]
  - IBANs and 13+ digit numbers (cards,
    accounts, 14-digit national IDs)          -> XXXX
  - last-4 / masked card or account digits
    ("ending 1234", "المنتهي بـ 1234", "**1234") -> XXXX
  - money amounts next to a currency word     -> a similar made-up amount
  - OTP / verification codes                  -> random digits, same length
  - 9-12 digit reference numbers              -> random digits, same length
  - links with a path or query                -> domain kept, rest -> /[ID]
  - names given with --names / --names-file   -> [NAME]
  - a word right after a greeting
    ("Dear X", "عزيزي X", "أستاذ X")          -> [NAME]
Short hotlines (e.g. 19623) are company numbers, not personal data, and are kept.

What it CANNOT do: find every name, address or real balance. Always open the
_review file, read each changed row, and fix or delete anything it missed.

The console output never shows message text, only  row : what was replaced.

Usage (from the project root):
    python data/scripts/anonymise_messages.py data/raw/real_messages/raw_AF.csv
    python data/scripts/anonymise_messages.py data/raw/real_messages/raw_AF.csv --names "Ahmed,Mona Ali"
    python data/scripts/anonymise_messages.py data/raw/real_messages/raw_AF.csv --names-file my_names.txt
"""

import argparse
import csv
import random
import re
import sys
from collections import Counter
from pathlib import Path

REQUIRED_COLUMNS = ["text", "label", "category", "channel", "language",
                    "brand", "contributor", "received_in_real_life"]

# \d in Python matches Arabic-Indic digits too, so every rule below works on both
# 0-9 and ٠-٩. Replacement digits keep the script of the digit they replace.
_ARABIC_INDIC = "٠١٢٣٤٥٦٧٨٩"
_PERSIAN = "۰۱۲۳۴۵۶۷۸۹"
_SEP = r"[ \-.]?"  # people write 010 1234 5678 or 010-1234-5678

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
_IBAN = re.compile(r"\bEG\d{2}(?:\s?\d){23,25}\b", re.IGNORECASE)
# literal digits written as classes so Arabic-Indic numbers (٠١٠...) match as well
_D0, _D1, _D2, _D5 = "[0٠۰]", "[1١۱]", "[2٢۲]", "[5٥۵]"
_EG_MOBILE = re.compile(
    rf"(?<!\d)(?:(?:\+|{_D0}{_D0})\s?{_D2}{_D0}{_SEP}|{_D0}){_D1}(?:{_D0}|{_D1}|{_D2}|{_D5})\d(?:{_SEP}\d){{7}}(?!\d)")
_INTERNATIONAL = re.compile(rf"(?<![\w\d])(?:\+|{_D0}{_D0})\d(?:{_SEP}\d){{7,14}}(?!\d)")
_LANDLINE = re.compile(rf"(?<!\d){_D0}\d(?:{_SEP}\d){{8,9}}(?!\d)")
_LONG_NUMBER = re.compile(r"(?<!\d)\d(?:[ \-]?\d){12,}(?!\d)")
_MASKED_DIGITS = re.compile(r"(?:\*{2,}|[xX]{2,}|•{2,})[ \-]?\d{2,6}(?!\d)")
_LAST_DIGITS = re.compile(
    r"((?:ending|ending in|ending with|ends with|ends in|last 4|last four|"
    r"المنتهي|المنتهية|ينتهي|تنتهي|منتهي)\s*(?:ب|بـ|ب\s*ـ|in|with|digits|:)?\s*(?:رقم\s*)?)(\d{3,6})(?!\d)",
    re.IGNORECASE)
_AMOUNT_NUMBER = r"\d{1,3}(?:[,٬]\d{3})+(?:[.٫]\d+)?|\d+(?:[.٫]\d+)?"
_CURRENCY = r"(?:جنيه(?:ا|ات)?|جم|ج\.م\.?|ج\.م|ج|EGP|LE|L\.E\.?|pounds?|USD|\$|دولار)"
_AMOUNT_AFTER = re.compile(rf"(?<![\d.,])({_AMOUNT_NUMBER})(\s*{_CURRENCY})(?![A-Za-z\u0600-\u06FF])", re.IGNORECASE)
_AMOUNT_BEFORE = re.compile(rf"((?<![A-Za-z]){_CURRENCY}\s*)({_AMOUNT_NUMBER})(?![\d])", re.IGNORECASE)
_OTP_CONTEXT = re.compile(
    r"\b(?:otp|code|pin|password|passcode|verification|verify|one[- ]time)\b|"
    r"كود|رمز|الرمز|كلمة السر|كلمة المرور|الرقم السري|التحقق|التفعيل|مرة واحدة",
    re.IGNORECASE)
_CODE = re.compile(r"(?<![\d.,٫٬])\d{4,8}(?![\d.,٫٬])")
_REFERENCE = re.compile(r"(?<![\d.,٫٬])\d{9,12}(?![\d.,٫٬])")
_GREETING = re.compile(
    r"((?:\bdear|\bhi|\bhello|\bmr\.?|\bmrs\.?|\bms\.?|\beng\.?|\bdr\.?|"
    r"عزيزي|عزيزتي|العميل|العميلة|أستاذ|استاذ|أستاذة|استاذة|الأستاذ|الاستاذ|"
    r"السيد|السيدة|مرحبا|أهلا|اهلا|يا)\s+)"
    r"([A-Za-z][A-Za-z'-]+|[ء-ي]{2,})",
    re.IGNORECASE)
# Words that often follow a greeting but are not names.
_NOT_NAMES = {
    "customer", "client", "user", "sir", "madam", "valued", "all", "there", "team",
    "عميلنا", "العزيز", "العزيزة", "الكريم", "الكريمة", "عميل", "حضرتك", "بيك", "بكم",
    "بك", "جماعة", "شباب", "عزيزي", "عزيزتي", "مشتركنا", "المشترك", "صديقي", "يا",
}


def _same_script_digits(original: str, rng: random.Random) -> str:
    """Random digits of the same length and digit script; no new leading zero."""
    out = []
    for i, ch in enumerate(original):
        if not ch.isdigit():
            out.append(ch)
            continue
        d = rng.randint(1 if i == 0 and int(ch) != 0 else 0, 9)
        out.append(_ARABIC_INDIC[d] if ch in _ARABIC_INDIC else _PERSIAN[d] if ch in _PERSIAN else str(d))
    return "".join(out)


def _fake_amount(original: str, rng: random.Random) -> str:
    """A similar made-up amount with the same formatting (thousands separators, decimals)."""
    ascii_ = original.translate(str.maketrans(_ARABIC_INDIC + _PERSIAN, "0123456789" * 2))
    ascii_ = ascii_.replace("٬", ",").replace("٫", ".")
    has_comma = "," in ascii_
    decimals = len(ascii_.split(".", 1)[1]) if "." in ascii_ else 0
    try:
        value = float(ascii_.replace(",", ""))
    except ValueError:
        return _same_script_digits(original, rng)
    new = value * rng.uniform(0.55, 1.45) if value else rng.uniform(5, 500)
    if decimals == 0:
        new = max(1, round(new))
    text = f"{new:,.{decimals}f}" if has_comma else f"{new:.{decimals}f}"
    if any(c in _ARABIC_INDIC for c in original):
        text = text.translate(str.maketrans("0123456789", _ARABIC_INDIC)).replace(",", "٬").replace(".", "٫")
    return text


def _url_keep_domain(match: re.Match) -> str | None:
    """domain + /[ID] for a link with a path or query; None when there is nothing to hide."""
    url = match.group(0)
    trailing = ""
    while url and url[-1] in ".,;:!?)]}،؛":
        trailing = url[-1] + trailing
        url = url[:-1]
    scheme, sep, rest = url.partition("://")
    if not sep:
        scheme, rest = "", url
    host, slash, path = rest.partition("/")
    host_only, q, query = host.partition("?")
    path, q2, query2 = path.partition("?")
    parts = [p for p in re.split(r"[/?&=#]", path + " " + query + " " + query2) if p.strip()]
    # only links that carry a personal token / tracking id are cut: plain paths like /offers stay
    if any(len(p) >= 16 or (len(p) >= 5 and re.search(r"\d", p)) for p in parts) or q or q2:
        return f"{scheme}{sep}{host_only}/[ID]{trailing}"
    return None


def anonymise(text: str, names: list[str], rng: random.Random) -> tuple[str, Counter]:
    hits: Counter = Counter()

    def sub(pattern, repl, s, rule):
        new, n = pattern.subn(repl, s)
        if n:
            hits[rule] += n
        return new

    t = text
    t = sub(_EMAIL, "[EMAIL]", t, "email")

    def link(m: re.Match) -> str:
        new = _url_keep_domain(m)
        if new is None:
            return m.group(0)
        hits["link"] += 1
        return new

    t = _URL.sub(link, t)
    t = sub(_IBAN, "XXXX", t, "iban")
    t = sub(_EG_MOBILE, "[PHONE]", t, "phone")
    t = sub(_INTERNATIONAL, "[PHONE]", t, "phone")
    t = sub(_LANDLINE, "[PHONE]", t, "phone")
    t = sub(_LONG_NUMBER, "XXXX", t, "card_account_or_id")
    t = sub(_MASKED_DIGITS, "XXXX", t, "masked_digits")
    t = sub(_LAST_DIGITS, lambda m: m.group(1) + "XXXX", t, "last_digits")
    t = sub(_AMOUNT_AFTER, lambda m: _fake_amount(m.group(1), rng) + m.group(2), t, "amount")
    t = sub(_AMOUNT_BEFORE, lambda m: m.group(1) + _fake_amount(m.group(2), rng), t, "amount")
    if _OTP_CONTEXT.search(t):
        t = sub(_CODE, lambda m: _same_script_digits(m.group(0), rng), t, "otp_code")
    t = sub(_REFERENCE, lambda m: _same_script_digits(m.group(0), rng), t, "reference_number")
    for name in sorted(names, key=len, reverse=True):
        pattern = re.compile(rf"(?<![\w\u0621-\u064A]){re.escape(name)}(?![\w\u0621-\u064A])", re.IGNORECASE)
        t = sub(pattern, "[NAME]", t, "listed_name")

    def greeting(m: re.Match) -> str:
        word = m.group(2)
        if word.lower() in _NOT_NAMES or word.startswith("[") or word.isupper():
            return m.group(0)
        hits["name_after_greeting"] += 1
        return m.group(1) + "[NAME]"

    t = _GREETING.sub(greeting, t)
    return t, hits


def load_names(args) -> list[str]:
    names = [n.strip() for n in (args.names or "").split(",") if n.strip()]
    if args.names_file:
        with open(args.names_file, encoding="utf-8-sig") as f:
            names += [line.strip() for line in f if line.strip() and not line.startswith("#")]
    # also add each single word of a multi-word name (first name alone is common)
    words = {w for n in names for w in n.split() if len(w) >= 3}
    return sorted(set(names) | words)


def main() -> None:
    parser = argparse.ArgumentParser(description="Anonymise a contributor's raw message file (offline).")
    parser.add_argument("raw_file", type=Path, help="data/raw/real_messages/raw_<initials>.csv")
    parser.add_argument("--names", help='comma-separated names to replace, e.g. "Ahmed,Mona Ali,أحمد"')
    parser.add_argument("--names-file", type=Path, help="text file with one name per line")
    parser.add_argument("--seed", type=int, default=None, help="random seed (default: random)")
    args = parser.parse_args()

    raw = args.raw_file
    if not raw.exists():
        sys.exit(f"File not found: {raw}")
    if not raw.stem.startswith("raw_"):
        sys.exit("Name the input raw_<initials>.csv (e.g. raw_AF.csv) so it is never mistaken for a finished file.")
    initials = raw.stem[len("raw_"):]
    out_path = raw.with_name(f"messages_{initials}.csv")
    review_path = raw.with_name(f"_review_{initials}.csv")
    if out_path.exists():
        answer = input(f"{out_path.name} already exists. Overwrite it? (yes/no) ").strip().lower()
        if answer != "yes":
            sys.exit("Nothing was changed.")

    with open(raw, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        fieldnames = [(n or "").strip().lower() for n in (reader.fieldnames or [])]
        missing = [c for c in REQUIRED_COLUMNS if c not in fieldnames]
        if missing:
            sys.exit(f"Missing column(s): {', '.join(missing)}. Start from collection_template.csv.")
        reader.fieldnames = fieldnames
        rows = [{k: (v or "") for k, v in r.items() if k} for r in reader]

    rng = random.Random(args.seed)
    names = load_names(args)
    totals: Counter = Counter()
    review, changed_rows = [], []
    for number, row in enumerate(rows, start=2):  # row 1 is the header
        new_text, hits = anonymise(row["text"], names, rng)
        if hits:
            totals.update(hits)
            changed_rows.append(f"  row {number}: " + ", ".join(f"{k} x{v}" for k, v in sorted(hits.items())))
            review.append({"row": number, "replaced": ";".join(sorted(hits)),
                           "before": row["text"], "after": new_text})
        row["text"] = new_text

    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:  # BOM so Excel shows Arabic
        writer = csv.DictWriter(f, fieldnames=REQUIRED_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    with open(review_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["row", "replaced", "before", "after"])
        writer.writeheader()
        writer.writerows(review)

    print(f"Rows read: {len(rows)}   rows changed: {len(review)}")
    print("Replacements: " + (", ".join(f"{k}={v}" for k, v in totals.most_common()) or "none"))
    print("\n".join(changed_rows[:80]) + (f"\n  (+{len(changed_rows) - 80} more)" if len(changed_rows) > 80 else ""))
    print(f"\nWrote {out_path}")
    print(f"Wrote {review_path}  (before/after; open it and check every row)")
    print("Names, addresses and some balances can still slip through: read the file once before ingest.")
    print(f"Next: python data/scripts/ingest_real_messages.py --dry-run")


if __name__ == "__main__":
    main()
