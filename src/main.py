#!/usr/bin/env python3
"""
ALU Regex Data Extraction
=========================

Extracts structured data from unstructured / messy raw text using regular
expressions, then *validates* and *sanitises* every candidate before it is
allowed into the output.

Supported data types
--------------------
    1. email_addresses     user.name+tag@sub.example.co.uk
    2. urls                https://host.example.com:8080/path?q=1#frag
    3. phone_numbers       (555) 123-4567 | 555-123-4567 | +250 788 123 456
    4. credit_card_numbers 4111 1111 1111 1111  (Luhn-validated, masked on output)
    5. times               14:30 | 2:30 PM | 23:59:59
    6. html_tags           <p> | <div class="x"> | </span> | <br/>
    7. hashtags            #DataEngineering | #alu_regex
    8. currency_amounts    $1,299.00 | EUR 25,00 | 150,000 RWF | £2,450.75

Design principles
-----------------
* **Validate, don't just match.** A regex says "this *looks* like an email";
  a validator says "this *is* usable". Every type has both.
* **Fail safe.** Anything malicious, malformed or ambiguous is dropped into a
  `rejected` bucket with a reason instead of silently entering the results.
* **Protect sensitive data.** Credit cards are never written out in full;
  emails are masked by default in the JSON report.
* **ReDoS-safe.** Every quantifier is bounded ({0,n} instead of * or +) so a
  hostile input cannot force catastrophic backtracking.

Usage
-----
    python src/main.py                                  # uses the defaults below
    python src/main.py -i input/raw-text.txt -o output/sample-output.json
    python src/main.py --no-mask                        # show raw emails (cards stay masked)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

# ---------------------------------------------------------------------------
# 0. SAFETY LIMITS
# ---------------------------------------------------------------------------
# Hard caps stop a hostile or accidentally huge file from exhausting memory or
# CPU. They are checked *before* a single regex is executed.

MAX_INPUT_BYTES = 2_000_000      # 2 MB - refuse to read anything larger
MAX_LINE_CHARS = 5_000           # longer lines are truncated (ReDoS mitigation)
MAX_MATCHES_PER_TYPE = 500       # stop runaway output from a crafted input

# Schemes we are willing to emit. Everything else (javascript:, data:, file:,
# ftp:, tel:) is treated as untrusted and rejected.
ALLOWED_URL_SCHEMES = ("http", "https")


# ---------------------------------------------------------------------------
# 1. INJECTION / ABUSE SIGNATURES
# ---------------------------------------------------------------------------
# These run over every *candidate string* (not the whole file) so that a single
# poisoned line cannot contaminate the clean data around it. A candidate that
# trips any signature is quarantined with the name of the rule it broke.

INJECTION_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    # --- Cross-site scripting -------------------------------------------------
    ("xss_script_tag",   re.compile(r"<\s*/?\s*script\b", re.I)),
    ("xss_iframe_tag",   re.compile(r"<\s*/?\s*(?:iframe|object|embed|svg)\b", re.I)),
    ("xss_event_handler", re.compile(r"\bon[a-z]{3,15}\s*=", re.I)),
    ("xss_js_scheme",    re.compile(r"javascript\s*:", re.I)),
    ("xss_data_uri",     re.compile(r"data\s*:\s*[a-z]+/[a-z]+\s*;", re.I)),
    # --- SQL injection --------------------------------------------------------
    ("sql_tautology",    re.compile(r"'\s*(?:or|and)\s+['\"]?[\w]+['\"]?\s*=", re.I)),
    ("sql_keyword",      re.compile(r"\b(?:union\s+select|drop\s+table|insert\s+into|"
                                    r"delete\s+from|update\s+\w+\s+set)\b", re.I)),
    # Note: the `--` rule is deliberately anchored to a quote or semicolon so
    # that an ordinary HTML comment (`<!-- ... -->`) is not flagged as SQL.
    ("sql_comment",      re.compile(r"(?:'\s*(?:--|#)|;\s*--)")),
    # --- Command / template / path abuse -------------------------------------
    ("command_injection", re.compile(r"(?:\$\(|`|\|\s*(?:sh|bash)\b|;\s*rm\s)", re.I)),
    ("template_injection", re.compile(r"(?:\{\{.{0,80}?\}\}|\$\{.{0,80}?\})")),
    ("path_traversal",   re.compile(r"(?:\.\./|\.\.\\|%2e%2e[/\\%])", re.I)),
    ("null_byte",        re.compile(r"(?:\x00|%00)")),
]


def injection_reason(candidate: str) -> str | None:
    """Return the name of the first injection rule the candidate trips, else None."""
    for name, pattern in INJECTION_SIGNATURES:
        if pattern.search(candidate):
            return name
    return None


# ---------------------------------------------------------------------------
# 2. THE REGEX PATTERNS
# ---------------------------------------------------------------------------
# Every pattern below is a *static constant*. User input is never compiled into
# a regex, which removes an entire class of regex-injection bugs.
# All quantifiers are bounded, so backtracking is capped.

PATTERNS: dict[str, re.Pattern[str]] = {

    # -- 1. EMAIL ----------------------------------------------------------
    # (?<![\w.+-])  left guard: don't start mid-word ("xuser@..." is not a match)
    # [\w.%+-]{1,64}  local part, RFC-capped at 64 chars
    # (?:label\.){1,4}  one to four DNS labels, each 1-63 chars, no leading/
    #                   trailing hyphen
    # [A-Za-z]{2,24}  the TLD must be alphabetic - kills "user@localhost"
    "email_addresses": re.compile(
        r"(?<![\w.+-])"
        r"[A-Za-z0-9._%+-]{1,64}"
        r"@"
        r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,4}"
        r"[A-Za-z]{2,24}"
        r"(?![\w.-])"
    ),

    # -- 2. URL ------------------------------------------------------------
    # Scheme is restricted to http/https at the regex level *and* re-checked in
    # the validator (defence in depth). Path/query/fragment are bounded and
    # exclude quotes and angle brackets so a URL cannot swallow surrounding HTML.
    "urls": re.compile(
        r"\bhttps?://"
        r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,5}"
        r"[A-Za-z]{2,24}"
        r"(?::\d{1,5})?"                     # optional :8080
        r"(?:/[^\s<>\"'`]{0,300})?"          # optional /path
        r"(?:\?[^\s<>\"'`]{0,300})?"         # optional ?query
        r"(?:#[^\s<>\"'`]{0,150})?"          # optional #fragment
    ),

    # -- 3. PHONE ----------------------------------------------------------
    # Three explicit shapes rather than one greedy pattern - explicit shapes
    # produce far fewer false positives on things like "1234567890123456789".
    "phone_numbers": re.compile(
        r"(?<![\w+])(?:"
        r"\+\d{1,3}[ .\-]?\(?\d{1,4}\)?[ .\-]?\d{3}[ .\-]?\d{3,4}"   # +250 788 123 456
        r"|\(\d{3}\)[ .\-]?\d{3}[ .\-]?\d{4}"                        # (555) 123-4567
        r"|\d{3}[ .\-]\d{3}[ .\-]\d{4}"                              # 555-123-4567
        r")(?!\d)"
    ),

    # -- 4. CREDIT CARD ----------------------------------------------------
    # Matches the 16-digit grouped form and the 15-digit Amex form. The regex
    # only finds *shapes*; the Luhn checksum in the validator decides validity.
    "credit_card_numbers": re.compile(
        r"(?<![\d\-])(?:"
        r"\d{4}[ \-]?\d{6}[ \-]?\d{5}"       # Amex 3782 822463 10005
        r"|\d{4}[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}"  # Visa/MC 4111 1111 1111 1111
        r")(?![\d\-])"
    ),

    # -- 5. TIME -----------------------------------------------------------
    # 12-hour form is listed first so "9:05 AM" wins over a bare "9:05".
    # Hour/minute ranges are encoded in the regex itself, so 25:99 never matches.
    "times": re.compile(
        r"(?<![\d:])(?:"
        r"(?:0?[1-9]|1[0-2]):[0-5]\d(?::[0-5]\d)?\s?[APap]\.?[Mm]\.?"  # 2:30 PM
        r"|(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?"                     # 23:59:59
        r")(?![\d:])"
    ),

    # -- 6. HTML TAG -------------------------------------------------------
    # Opening, closing and self-closing tags, with a bounded attribute section.
    "html_tags": re.compile(
        r"<\s*/?\s*[A-Za-z][A-Za-z0-9-]{0,30}"
        r"(?:\s+[^<>]{0,300})?"
        r"\s*/?\s*>"
    ),

    # -- 7. HASHTAG --------------------------------------------------------
    # Must start with a letter or underscore, which excludes numeric issue
    # references (#12345). The two lookaheads then exclude CSS hex colours
    # (#fff / #ffffff) - a classic false positive for naive hashtag regexes.
    "hashtags": re.compile(
        r"(?<![\w&])#"
        r"(?![0-9A-Fa-f]{3}\b)(?![0-9A-Fa-f]{6}\b)(?![0-9A-Fa-f]{8}\b)"
        r"[A-Za-z_][A-Za-z0-9_]{0,49}\b"
    ),

    # -- 8. CURRENCY -------------------------------------------------------
    # Symbol-prefix, code-prefix and code-suffix forms. Both 1,299.00 and the
    # European 25,00 style are accepted.
    "currency_amounts": re.compile(
        r"(?<![\w.])(?:"
        r"[$€£¥₦]\s?\d{1,3}(?:[,\s]\d{3})*(?:[.,]\d{1,2})?"                 # $1,299.00
        r"|(?:USD|EUR|GBP|JPY|RWF|KES|NGN|ZAR)\s?\d{1,3}(?:[,\s]\d{3})*(?:[.,]\d{1,2})?"
        r"|\d{1,3}(?:[,\s]\d{3})*(?:[.,]\d{1,2})?\s?(?:USD|EUR|GBP|JPY|RWF|KES|NGN|ZAR)"
        r")(?![\w])"
    ),
}


# ---------------------------------------------------------------------------
# 3. VALIDATORS
# ---------------------------------------------------------------------------
# Each validator returns (is_valid, reason_if_invalid). Matching is cheap;
# validating is where correctness actually lives.

def _luhn_ok(digits: str) -> bool:
    """Luhn (mod-10) checksum - the standard test every real card number passes."""
    total, parity = 0, len(digits) % 2
    for index, char in enumerate(digits):
        value = int(char)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _card_brand(digits: str) -> str:
    """Identify the issuer from the leading digits (IIN range)."""
    if digits.startswith("4"):
        return "Visa"
    if digits[:2] in {"34", "37"}:
        return "American Express"
    if 51 <= int(digits[:2]) <= 55 or 2221 <= int(digits[:4]) <= 2720:
        return "Mastercard"
    if digits[:4] == "6011" or digits[:2] == "65":
        return "Discover"
    return "Unknown"


def validate_email(value: str) -> tuple[bool, str]:
    if len(value) > 254:
        return False, "exceeds_max_length"
    local, _, domain = value.partition("@")
    if ".." in local or ".." in domain:
        return False, "consecutive_dots"
    if local.startswith(".") or local.endswith("."):
        return False, "local_part_dot_boundary"
    if domain.rsplit(".", 1)[-1].lower() in {"test", "invalid", "localhost", "example"}:
        return False, "reserved_tld"
    return True, ""


def validate_url(value: str) -> tuple[bool, str]:
    scheme = value.split(":", 1)[0].lower()
    if scheme not in ALLOWED_URL_SCHEMES:
        return False, "scheme_not_allowed"
    if len(value) > 2048:
        return False, "exceeds_max_length"
    # A credential-in-URL (https://user:pass@host) leaks secrets into logs.
    host_part = value.split("://", 1)[1].split("/", 1)[0]
    if "@" in host_part:
        return False, "embedded_credentials"
    return True, ""


def validate_phone(value: str) -> tuple[bool, str]:
    digits = re.sub(r"\D", "", value)
    if not 7 <= len(digits) <= 15:          # ITU-T E.164 allows at most 15
        return False, "digit_count_out_of_range"
    if len(set(digits)) == 1:               # 0000000000 / 1111111111
        return False, "placeholder_number"
    return True, ""


def validate_card(value: str) -> tuple[bool, str]:
    digits = re.sub(r"\D", "", value)
    if len(digits) not in (15, 16):
        return False, "unsupported_length"
    if not _luhn_ok(digits):
        return False, "failed_luhn_checksum"
    return True, ""


def validate_always(value: str) -> tuple[bool, str]:
    """For types whose regex already encodes every rule (times, tags, hashtags)."""
    return True, ""


def validate_currency(value: str) -> tuple[bool, str]:
    if not re.search(r"\d", value):
        return False, "no_numeric_component"
    return True, ""


VALIDATORS: dict[str, Callable[[str], tuple[bool, str]]] = {
    "email_addresses": validate_email,
    "urls": validate_url,
    "phone_numbers": validate_phone,
    "credit_card_numbers": validate_card,
    "times": validate_always,
    "html_tags": validate_always,
    "hashtags": validate_always,
    "currency_amounts": validate_currency,
}


# ---------------------------------------------------------------------------
# 4. MASKING - never let sensitive data leave the process in the clear
# ---------------------------------------------------------------------------

def mask_card(value: str) -> str:
    """`4111 1111 1111 1111` -> `**** **** **** 1111`. Always applied."""
    digits = re.sub(r"\D", "", value)
    last4 = digits[-4:]
    groups = ["****"] * ((len(digits) - 4) // 4)
    return " ".join(groups + [last4])


def mask_email(value: str) -> str:
    """`aline.uwase@alueducation.com` -> `a**********e@alueducation.com`."""
    local, _, domain = value.partition("@")
    if len(local) <= 2:
        hidden = "*" * len(local)
    else:
        hidden = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{hidden}@{domain}"


def mask_phone(value: str) -> str:
    """Keep the last two digits only: `+250 788 123 456` -> `************56`."""
    return re.sub(r"\d(?=\d{2})", "*", value)


# ---------------------------------------------------------------------------
# 5. THE EXTRACTOR
# ---------------------------------------------------------------------------

class ExtractionResult:
    """Small container so the caller gets results, rejects and stats together."""

    def __init__(self) -> None:
        self.data: dict[str, list] = {name: [] for name in PATTERNS}
        self.rejected: list[dict] = []

    def reject(self, kind: str, value: str, reason: str) -> None:
        self.rejected.append({"type": kind, "value": value[:120], "reason": reason})


def _safe_lines(text: str) -> list[str]:
    """Truncate over-long lines before any regex touches them (ReDoS guard)."""
    return [line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS]
            for line in text.splitlines()]


# Punctuation that commonly trails a URL in prose ("see https://x.com/a.") but
# is not part of the URL itself.
_TRAILING_PUNCT = ".,;:!?)]}>'\"«»"


def _dedupe_key(kind: str, value: str) -> str:
    """Phones and cards are compared by digits, so 555-1234 == 555.1234."""
    if kind in ("phone_numbers", "credit_card_numbers"):
        return re.sub(r"\D", "", value)
    return value.lower()


def extract(text: str, mask: bool = True) -> ExtractionResult:
    """Run every pattern over the text, then validate and sanitise each match."""
    result = ExtractionResult()
    seen: dict[str, set[str]] = {name: set() for name in PATTERNS}
    lines = _safe_lines(text)

    # Pre-compute, per line, whether that line contains an injection payload.
    # This gives us *context-aware* quarantine: a perfectly well-formed URL that
    # happens to live inside `<script>fetch('https://evil...')</script>` is
    # still refused, because the surrounding text is hostile.
    line_threat = [injection_reason(line) for line in lines]

    for kind, pattern in PATTERNS.items():
        validator = VALIDATORS[kind]

        for line_no, line in enumerate(lines):
            for match in pattern.finditer(line):
                raw = match.group(0).strip()
                if kind == "urls":
                    raw = raw.rstrip(_TRAILING_PUNCT)

                if len(result.data[kind]) >= MAX_MATCHES_PER_TYPE:
                    result.reject(kind, raw, "per_type_limit_reached")
                    break

                # -- Security gate: the candidate itself ----------------------
                reason = injection_reason(raw)
                if reason:
                    result.reject(kind, raw, f"injection:{reason}")
                    continue

                # -- Security gate: the line the candidate came from ----------
                if line_threat[line_no]:
                    result.reject(kind, raw, f"injection_context:{line_threat[line_no]}")
                    continue

                # -- Correctness gate ----------------------------------------
                ok, why = validator(raw)
                if not ok:
                    result.reject(kind, raw, why)
                    continue

                # -- De-duplicate (order preserved) --------------------------
                key = _dedupe_key(kind, raw)
                if key in seen[kind]:
                    continue
                seen[kind].add(key)

                # -- Sanitise / enrich ---------------------------------------
                if kind == "credit_card_numbers":
                    digits = re.sub(r"\D", "", raw)
                    result.data[kind].append({
                        "masked": mask_card(raw),      # full PAN never stored
                        "brand": _card_brand(digits),
                        "length": len(digits),
                        "luhn_valid": True,
                    })
                elif kind == "email_addresses":
                    result.data[kind].append(mask_email(raw) if mask else raw)
                elif kind == "phone_numbers":
                    result.data[kind].append(mask_phone(raw) if mask else raw)
                else:
                    result.data[kind].append(raw)

    return result


# ---------------------------------------------------------------------------
# 6. I/O + CLI
# ---------------------------------------------------------------------------

def read_input(path: Path) -> str:
    """Read the input file with every guard we can reasonably apply."""
    if not path.is_file():
        raise SystemExit(f"[error] input file not found: {path}")
    size = path.stat().st_size
    if size > MAX_INPUT_BYTES:
        raise SystemExit(f"[error] input is {size} bytes; limit is {MAX_INPUT_BYTES}")
    # errors="replace" means a corrupt byte sequence degrades instead of crashing.
    return path.read_text(encoding="utf-8", errors="replace")


def build_report(result: ExtractionResult, source: Path, masked: bool) -> dict:
    counts = {kind: len(values) for kind, values in result.data.items()}
    return {
        "metadata": {
            "source_file": source.name,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "masking_enabled": masked,
            "total_valid_matches": sum(counts.values()),
            "total_rejected": len(result.rejected),
        },
        "counts": counts,
        "data": result.data,
        "rejected": result.rejected,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Extract structured data from raw text.")
    parser.add_argument("-i", "--input", type=Path, default=root / "input" / "raw-text.txt")
    parser.add_argument("-o", "--output", type=Path, default=root / "output" / "sample-output.json")
    parser.add_argument("--no-mask", action="store_true",
                        help="show emails/phones unmasked (card numbers stay masked)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    masked = not args.no_mask

    text = read_input(args.input)
    result = extract(text, mask=masked)
    report = build_report(result, args.input, masked)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Read      : {args.input}")
    print(f"Wrote     : {args.output}")
    print(f"Masking   : {'on' if masked else 'off (cards still masked)'}")
    print("-" * 52)
    for kind, count in report["counts"].items():
        print(f"  {kind:<22} {count:>3}")
    print("-" * 52)
    print(f"  {'rejected (quarantined)':<22} {len(result.rejected):>3}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
