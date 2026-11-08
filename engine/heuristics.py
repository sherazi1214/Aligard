"""Layer 2: weighted heuristics. Har signal ka apna wazan, akeli koi cheez faisla nahi karti."""
from __future__ import annotations

import re

from engine.brands import display_name_brand, lookalike_brand
from engine.config import EngineConfig
from engine.models import EmailInput, Signal
from engine.parsing import Content
from engine.urls import ParsedUrl, defang, parse_url, registrable_domain

# Lafzon ke signals halke hain (3 points), kyunke legit emails mein bhi aate hain.
URGENCY = [
    "urgent", "immediately", "act now", "within 24 hours", "expire", "suspended", "locked",
    "blocked", "deactivated", "final notice", "limited time", "verify your account",
    "confirm your identity", "turant", "foran", "fori", "24 ghante", "band ho jayega",
    "block ho", "فوری", "بلاک", "معطل",
]
CREDENTIALS = [
    "password", "passcode", "otp", "pin code", "cnic", "card number", "cvv", "login",
    "log in", "sign in", "account number", "apna pin", "password dein", "پاس ورڈ", "شناختی کارڈ",
]
LURES = [
    "congratulations", "you have won", "winner", "prize", "lottery", "claim your", "inaam",
    "inam", "mubarak", "8171", "ehsaas", "refund", "gift card", "cash reward", "مبارک", "انعام",
]
DANGEROUS_EXT = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".jar", ".lnk", ".iso", ".msi"}
MACRO_EXT = {".docm", ".xlsm", ".pptm"}
_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_DOMAIN_IN_TEXT = re.compile(r"(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/\S*)?", re.IGNORECASE)


def parse_auth_results(headers: list[tuple[str, str]], trusted_ids: frozenset) -> dict[str, str]:
    """SPF/DKIM/DMARC natije, sirf trusted authserv-id ke headers se.
    Attacker khud 'Authentication-Results: spf=pass' likh kar bhej sakta hai, isliye
    sirf wohi header maane jate hain jo hamare receiving server (jaise mx.google.com) ne lagaya."""
    result: dict[str, str] = {}
    for name, value in headers:
        if name.lower() != "authentication-results":
            continue
        authserv = value.split(";", 1)[0].strip().split()[0].lower() if value.strip() else ""
        if authserv not in trusted_ids:
            continue
        found: dict[str, set[str]] = {}
        for mech, res in _AUTH_RE.findall(value):
            found.setdefault(mech.lower(), set()).add(res.lower())
        for mech, results in found.items():
            if mech in result:
                continue  # sab se upar wala header jeetta hai
            result[mech] = "pass" if "pass" in results else sorted(results)[0]
    return result


def _hits(words: list[str], haystack: str) -> list[str]:
    return [w for w in words if w in haystack]


def score_heuristics(
    email: EmailInput, content: Content, cfg: EngineConfig
) -> tuple[int, list[Signal], dict[str, str]]:
    """(score 0-100, signals, auth). Har signal code sirf ek baar ginta hai."""
    sig: dict[str, Signal] = {}

    def add(code: str, points: float, text: str) -> None:
        if code not in sig:
            sig[code] = Signal(code, "heuristics", points, text)

    parsed: list[ParsedUrl] = []
    for raw in content.urls[: cfg.max_urls_analyzed]:
        p = parse_url(raw)
        if p:
            parsed.append(p)

    for p in parsed:
        shown = defang(p.host)
        if p.is_ip:
            add("ip_in_url", 30, f"Link uses a raw IP address ({shown})")
        if p.has_userinfo:
            add("userinfo_in_url", 25, f"Link hides its real host behind '@' ({shown})")
        if p.is_punycode or p.has_non_ascii:
            add("punycode", 25, f"Link domain uses punycode/non-ASCII characters ({shown})")
        brand = lookalike_brand(p.host, p.registrable)
        if brand:
            add("brand_lookalike", 35, f"Domain {shown} imitates '{brand}' but is not official")
        if p.is_shortener:
            add("shortener", 12, f"Link uses a URL shortener ({shown})")
        if p.tld_suspicious:
            add("suspicious_tld", 10, f"Link uses a frequently abused TLD (.{p.tld})")
        if p.subdomain_labels >= 3:
            add("many_subdomains", 8, "Link has an unusually deep subdomain chain")
        if p.length > 150:
            add("long_url", 5, "Link is unusually long")
        if p.is_http:
            add("insecure_http", 5, "Link uses plain http (not https)")

    # Anchor text kuch aur dikhata hai, href kahin aur jata hai
    for href, anchor in content.anchors:
        ph = parse_url(href) if href.lower().startswith(("http://", "https://", "www.")) else None
        m = _DOMAIN_IN_TEXT.search(anchor or "")
        shown = parse_url(m.group(0)) if m else None
        if ph and shown and shown.registrable != ph.registrable:
            add("anchor_mismatch", 25, f"Link text shows {defang(shown.registrable)} "
                f"but points to {defang(ph.registrable)}")

    # Sender checks
    sender_dom = registrable_domain(email.sender_email.rsplit("@", 1)[-1]) if email.sender_email else ""
    reply_dom = registrable_domain(email.reply_to.rsplit("@", 1)[-1]) if email.reply_to else ""
    if sender_dom:
        brand = display_name_brand(email.sender_name, sender_dom)
        if brand:
            add("display_name_spoof", 30, f"Sender name mentions '{brand}' but the address is "
                f"from {defang(sender_dom)}")
    if sender_dom and reply_dom and sender_dom != reply_dom:
        add("reply_to_mismatch", 15, "Reply-To domain differs from the sender domain")

    # SPF / DKIM / DMARC
    auth = parse_auth_results(email.headers, cfg.trusted_authserv_ids)
    if auth.get("dmarc") == "fail":
        add("dmarc_fail", 25, "DMARC check failed (sender may be spoofed)")
    if auth.get("spf") in ("fail", "softfail"):
        add("spf_fail", 10, "SPF check failed")
    if auth.get("dkim") in ("fail", "neutral", "policy"):
        add("dkim_fail", 10, "DKIM signature check failed")

    # Lafz (halke signals)
    haystack = f"{email.subject}\n{content.text}".lower()
    for code, words, label in (
        ("urgency_words", URGENCY, "uses pressure/urgency wording"),
        ("credential_words", CREDENTIALS, "asks for credentials/sensitive data"),
        ("lure_words", LURES, "uses prize/refund lure wording"),
    ):
        found = _hits(words, haystack)
        if found:
            add(code, min(12, 3 * len(found)), f"Message {label} ({len(found)} match)")

    # Attachments (sirf filename, asli scanner Phase 7 mein)
    for name in email.attachments:
        low = name.lower()
        parts = low.rsplit(".", 2)
        if len(parts) == 3 and f".{parts[2]}" in DANGEROUS_EXT:
            add("double_extension", 40, "Attachment has a double extension (e.g. .pdf.exe)")
        elif f".{parts[-1]}" in DANGEROUS_EXT:
            add("dangerous_attachment", 40, "Attachment is an executable/script file type")
        elif f".{parts[-1]}" in MACRO_EXT:
            add("macro_attachment", 25, "Attachment is a macro-enabled Office file")

    ordered = sorted(sig.values(), key=lambda s: s.points, reverse=True)
    return min(100, int(sum(s.points for s in ordered))), ordered, auth
