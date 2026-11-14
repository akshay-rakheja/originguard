"""Typed extraction of the values a user stated in trusted text.

Every extracted value is bound to ONE type. A number the user wrote as an
account or invoice number is an `id`, not an `amount`. "Q3" is a word, not
the number 3. Digits inside an IBAN or phone number ground nothing else.
"""
from __future__ import annotations

import re

from . import canon

_EMAIL = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_URL = re.compile(r"https?://[^\s<>\"'`]+")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]{4}){2,7}(?:[ -]?[A-Z0-9]{1,3})?\b")
_PHONE = re.compile(r"\+\d[\d\s().-]{5,}\d")
_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
_SYM = "".join(re.escape(s) for s in canon.CURRENCY_SYMBOLS)
_CUR_WORDS = "|".join(sorted(canon.CURRENCY_WORDS, key=len, reverse=True))
_NUM = r"\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?"
_MONEY = re.compile(
    rf"(?:(?<![\w.])(?:[{_SYM}]\s?)({_NUM})(?![\w.,]?\d)"
    rf"|(?<![\w.,])({_NUM})\s?(?:{_CUR_WORDS})\b"
    rf"|(?:\b(?:{_CUR_WORDS})\s?)({_NUM})(?![\w.,]?\d))",
    re.I,
)
_BARE_NUM = re.compile(rf"(?<![\w.,$€£¥₹#/-])({_NUM})(?![\w%]|[.,]\d)")
_ID_LABEL = re.compile(
    r"(?:account|acct|a/c|invoice|inv|order|ticket|case|id|ref|reference|no\.?|number|#|"
    r"room|flight|pin|code|zip|postcode|extension|ext|version|v)\s*[:#]?\s*$", re.I)
_QUOTED = re.compile(r"`([^`\n]{1,200})`|\"([^\"\n]{1,200})\"|'([^'\n]{2,200})'")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@:+\-]{2,}")

Fact = tuple[str, str]  # (type, canonical value)


def _add(out: set[Fact], typ: str, raw) -> None:
    try:
        out.add((typ, canon.CANON[typ](raw)))
    except canon.CanonError:
        pass


def extract(text: str) -> set[Fact]:
    """All typed values stated in `text`."""
    out: set[Fact] = set()
    try:
        text = canon.clean(text)
    except canon.CanonError:
        return out  # text containing invisible characters grounds nothing
    consumed: list[tuple[int, int]] = []

    def take(m: re.Match) -> None:
        consumed.append(m.span())

    def free(span: tuple[int, int]) -> bool:
        return not any(a < span[1] and span[0] < b for a, b in consumed)

    for m in _URL.finditer(text):
        raw = m.group(0).rstrip(".,;:!?)]}")
        _add(out, "url", raw)
        take(m)
    for m in _EMAIL.finditer(text):
        if free(m.span()):
            raw = m.group(0).rstrip(".")
            _add(out, "email", raw)
            _add(out, "domain", raw.split("@")[1])
            take(m)
    for m in _IBAN.finditer(text):
        if free(m.span()):
            _add(out, "iban", m.group(0))
            take(m)
    for m in _PHONE.finditer(text):
        if free(m.span()):
            _add(out, "phone", m.group(0))
            take(m)
    for m in _DATE.finditer(text):
        if free(m.span()):
            _add(out, "date", m.group(0))
            take(m)
    for m in _MONEY.finditer(text):
        if free(m.span()):
            _add(out, "amount", m.group(0))
            num = next(g for g in m.groups() if g)
            _add(out, "amount", num)  # "$1,250" also grounds a bare 1250 argument
            take(m)
    for m in _BARE_NUM.finditer(text):
        if not free(m.span()):
            continue
        if _ID_LABEL.search(text[max(0, m.start() - 20):m.start()]):
            _add(out, "id", m.group(1))  # "account 7" is an id, never an amount
        else:
            _add(out, "amount", m.group(1))
        take(m)
    for m in _QUOTED.finditer(text):
        _add(out, "id", next(g for g in m.groups() if g))
    for m in _TOKEN.finditer(text):
        tok = m.group(0).rstrip(".,;:!?")
        if free(m.span()):
            _add(out, "id", tok)
            if "." in tok and "/" not in tok and "@" not in tok:
                _add(out, "domain", tok)
    for code in {canon.CURRENCY_WORDS[w.lower()] for w in re.findall(rf"\b(?:{_CUR_WORDS})\b", text, re.I)}:
        out.add(("currency", code))
    for sym, code in canon.CURRENCY_SYMBOLS.items():
        if sym in text:
            out.add(("currency", code))
    return out


def words(text: str) -> set[str]:
    """Lower-cased words, used to ground enum/boolean control values."""
    try:
        return {w.lower() for w in re.findall(r"[A-Za-z0-9_-]+", canon.clean(text))}
    except canon.CanonError:
        return set()
