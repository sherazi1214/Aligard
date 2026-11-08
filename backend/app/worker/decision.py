"""Faisle ka pure logic (DB/network se alag, taake aasani se test ho): kaunsa action, whitelist match,
text safai. Email ka har hissa attacker-controlled hai."""
import re
from collections.abc import Iterable, Sequence
from email.utils import parseaddr

from engine.heuristics import parse_auth_results
from engine.models import EmailInput

NONE, LABEL, QUARANTINE = "none", "label", "quarantine"

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")  # control + bidi tricks


def clean_text(text: str, limit: int) -> str:
    """Control/newline/bidi characters hata kar ek line; hadd se lamba ho to kaat do."""
    one = " ".join(_CONTROL_RE.sub(" ", str(text or "")).split())
    return one if len(one) <= limit else one[: max(0, limit - 1)] + "…"


def format_sender(name: str, address: str) -> str:
    name, address = clean_text(name, 120), clean_text(address, 200)
    return clean_text(f"{name} <{address}>" if name and address else (address or name), 320)


def decide_action(verdict: str, score: int, confidence: float, *, suspicious_threshold: int,
                  phishing_threshold: int, min_confidence: float) -> str:
    """SAFE: kuch nahi. PHISHING + score/confidence dono hadd se upar: quarantine. Baqi shak wale: label.
    User ki thresholds sirf upar ki taraf (kam alerts) asar karti hain; engine ka verdict kam nahi hota."""
    if verdict == "SAFE":
        return NONE
    if verdict == "PHISHING" and score >= phishing_threshold and confidence >= min_confidence:
        return QUARANTINE
    if score >= suspicious_threshold:
        return LABEL
    return NONE


def sender_domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip().lower() if "@" in address else ""


def whitelist_hit(entries: Iterable[tuple[str, str]], sender_email: str) -> bool:
    """entries: (kind, value). 'sender' exact address; 'domain' exact ya subdomain
    (dot ki hadd par, 'evilexample.com' nahi)."""
    addr = sender_email.strip().lower()
    dom = sender_domain(addr)
    if not addr or not dom:
        return False
    for kind, value in entries:
        v = value.strip().lower()
        if kind == "sender" and addr == v:
            return True
        if kind == "domain" and (dom == v or dom.endswith("." + v)):
            return True
    return False


def dmarc_passed(headers: Sequence[tuple[str, str]], trusted_ids: frozenset) -> bool:
    """Whitelist sirf tab maani jati hai jab hamare receiving server (mx.google.com) ne DMARC pass likha ho.
    Warna attacker whitelisted address spoof karke analysis se bach nikalta."""
    return parse_auth_results(list(headers), trusted_ids).get("dmarc") == "pass"


def email_from_headers(headers: Sequence[tuple[str, str]]) -> EmailInput:
    """Bari email ka fallback: sirf headers se EmailInput (body khali)."""
    lowered = {k.lower(): v for k, v in headers}
    name, addr = parseaddr(lowered.get("from", ""))
    return EmailInput(
        subject=lowered.get("subject", ""),
        sender_name=name,
        sender_email=addr.lower(),
        reply_to=parseaddr(lowered.get("reply-to", ""))[1].lower(),
        headers=[(k, v) for k, v in headers],
    )
