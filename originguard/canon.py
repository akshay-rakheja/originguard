"""Typed canonicalizers.

Each function turns a raw value into one canonical string, or raises
CanonError. Two values are the same identity iff their canonical forms are
equal. Rules:

- Invisible / bidi-control characters are rejected outright (never stripped).
- Text is NFKC-normalized.
- Domains are IDNA-encoded, so a Cyrillic look-alike ("аcme.com") becomes a
  distinct punycode name instead of colliding with "acme.com".
- Email local parts must be ASCII. Plus-addressing is kept: "a+x@y" != "a@y".
- URLs with userinfo ("https://trusted.com@evil.example") are rejected.
- IBANs must pass the mod-97 checksum.
- Amounts are compared as Decimal values, never as strings.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit

INVISIBLE = re.compile("[­؜ᅟᅠ᠎​-‏‪-‮⁠-⁤⁪-⁯﻿]")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_LOCAL = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}$")
_IBAN = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$")
CURRENCY_SYMBOLS = {"$": "USD", "€": "EUR", "£": "GBP", "¥": "JPY", "₹": "INR"}
CURRENCY_WORDS = {"dollar": "USD", "dollars": "USD", "usd": "USD", "euro": "EUR", "euros": "EUR",
                  "eur": "EUR", "pound": "GBP", "pounds": "GBP", "gbp": "GBP", "jpy": "JPY",
                  "yen": "JPY", "inr": "INR", "rupees": "INR", "chf": "CHF", "cad": "CAD",
                  "aud": "AUD", "sgd": "SGD"}


class CanonError(ValueError):
    """The value cannot be canonicalized safely. Callers must treat it as untrusted."""


def clean(value) -> str:
    s = str(value)
    if INVISIBLE.search(s):
        raise CanonError("contains invisible or bidi-control characters")
    s = unicodedata.normalize("NFKC", s).strip()
    if not s:
        raise CanonError("empty value")
    return s


def domain(value) -> str:
    s = clean(value).lower().rstrip(".")
    try:
        ascii_ = s.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise CanonError(f"bad domain: {e}") from None
    labels = ascii_.split(".")
    if len(labels) < 2 or not all(_LABEL.match(lb) for lb in labels):
        raise CanonError(f"bad domain {s!r}")
    return ascii_


def email(value) -> str:
    s = clean(value)
    if s.lower().startswith("mailto:"):
        s = s[7:]
    if s.count("@") != 1:
        raise CanonError("email must contain exactly one @")
    local, dom = s.split("@")
    if not _LOCAL.match(local) or local.startswith(".") or local.endswith(".") or ".." in local:
        raise CanonError(f"bad email local part {local!r}")
    return f"{local.lower()}@{domain(dom)}"


def url(value) -> str:
    s = clean(value)
    parts = urlsplit(s)
    if parts.scheme.lower() not in ("http", "https"):
        raise CanonError("only http(s) URLs are supported")
    if "@" in parts.netloc:
        raise CanonError("URLs with userinfo are rejected")
    host = parts.hostname or ""
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        host = domain(host)
    try:
        port = parts.port
    except ValueError:
        raise CanonError("bad port") from None
    scheme = parts.scheme.lower()
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    return f"{scheme}://{host}{path}{query}"


def url_host(value) -> str:
    return url(value).split("//", 1)[1].split("/", 1)[0]


def iban(value) -> str:
    s = re.sub(r"[\s-]", "", clean(value)).upper()
    if not _IBAN.match(s):
        raise CanonError("not an IBAN")
    digits = "".join(str(int(c, 36)) for c in s[4:] + s[:4])
    if int(digits) % 97 != 1:
        raise CanonError("IBAN checksum failed")
    return s


def phone(value) -> str:
    s = clean(value)
    if re.search(r"[^\d\s+().-]", s):
        raise CanonError("bad phone number")
    digits = re.sub(r"\D", "", s)
    if not 7 <= len(digits) <= 15:
        raise CanonError("phone numbers have 7-15 digits")
    return ("+" if s.startswith("+") else "") + digits


def parse_money(value) -> tuple[Decimal, str | None]:
    """'$1,250.00' -> (1250.00, 'USD'); '1250 EUR' -> (1250, 'EUR'); 1250 -> (1250, None)."""
    if isinstance(value, bool):
        raise CanonError("boolean is not an amount")
    if isinstance(value, (int, float, Decimal)):
        num, cur = str(value), None
    else:
        s = clean(value)
        cur = None
        for sym, code in CURRENCY_SYMBOLS.items():
            if sym in s:
                cur, s = code, s.replace(sym, "")
        m = re.fullmatch(r"\s*([A-Za-z]{3,7})?\s*([\d.,]+)\s*([A-Za-z]{3,7})?\s*", s)
        if not m:
            raise CanonError(f"not an amount: {value!r}")
        for word in (m.group(1), m.group(3)):
            if word:
                code = CURRENCY_WORDS.get(word.lower())
                if code is None:
                    raise CanonError(f"unknown currency {word!r}")
                if cur and cur != code:
                    raise CanonError("conflicting currencies")
                cur = code
        num = m.group(2)
        if re.fullmatch(r"\d{1,3}(,\d{3})+(\.\d+)?", num):
            num = num.replace(",", "")
        elif "," in num:
            raise CanonError(f"ambiguous number format {num!r}")
    try:
        d = Decimal(num)
    except InvalidOperation:
        raise CanonError(f"not a number: {num!r}") from None
    if not d.is_finite() or d < 0:
        raise CanonError("amount must be a finite, non-negative number")
    return d.normalize(), cur


def amount(value) -> str:
    d, cur = parse_money(value)
    return f"{d:f}" + (f" {cur}" if cur else "")


def currency(value) -> str:
    s = clean(value).lower()
    code = CURRENCY_WORDS.get(s) or CURRENCY_SYMBOLS.get(s)
    if code is None and re.fullmatch(r"[a-z]{3}", s):
        code = s.upper()
    if code is None:
        raise CanonError(f"unknown currency {value!r}")
    return code


def identifier(value) -> str:
    """Opaque IDs, file paths, repo names: exact match after NFKC, case-sensitive."""
    if isinstance(value, bool):
        raise CanonError("boolean is not an identifier")
    return clean(value)


def date(value) -> str:
    s = clean(value)
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", s)
    if not m:
        raise CanonError("only ISO dates (YYYY-MM-DD) are supported")
    return m.group(0)


CANON = {
    "email": email, "domain": domain, "url": url, "iban": iban, "phone": phone,
    "amount": amount, "currency": currency, "id": identifier, "date": date,
}
