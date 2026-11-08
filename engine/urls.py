"""URL tools: extract, parse, normalize, defang. Engine kisi URL ko kabhi VISIT nahi karta."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'`]+", re.IGNORECASE)
_TRAILING = ".,;:!?)]}>'\""
MAX_URL_LEN = 2048

# Do-hisson wale suffixes (registrable domain nikalne ke liye). Chhoti list, tldextract ke baghair.
_MULTI_SUFFIXES = {
    "com.pk", "gov.pk", "org.pk", "edu.pk", "net.pk", "gob.pk", "co.uk", "org.uk", "ac.uk",
    "gov.uk", "com.au", "net.au", "co.in", "co.jp", "com.br", "co.za", "com.tr", "com.sa",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "s.id", "t.ly", "lnkd.in",
}

# Aksar abuse hone wale TLDs (sirf halka sa signal)
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "icu", "buzz", "tk", "ml", "ga", "cf", "gq", "work", "support",
    "rest", "cam", "monster", "zip", "mov", "link", "country", "loan",
}


@dataclass(frozen=True)
class ParsedUrl:
    raw: str
    scheme: str
    host: str
    registrable: str
    path_query: str
    has_userinfo: bool
    is_ip: bool
    is_punycode: bool
    has_non_ascii: bool
    is_shortener: bool
    tld: str
    length: int
    subdomain_labels: int

    @property
    def is_http(self) -> bool:
        return self.scheme == "http"

    @property
    def tld_suspicious(self) -> bool:
        return self.tld in SUSPICIOUS_TLDS


def registrable_domain(host: str) -> str:
    if _is_ip_host(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _MULTI_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # http://3232235777 (decimal) ya http://0xC0A80001 (hex) wale IP tricks
    return bool(re.fullmatch(r"\d{8,10}", host) or re.fullmatch(r"0x[0-9a-f]{6,8}", host))


def parse_url(raw: str) -> ParsedUrl | None:
    """Kharab/anokha URL par None deta hai, kabhi crash nahi karta."""
    try:
        candidate = raw.strip()
        if candidate.lower().startswith("www."):
            candidate = "http://" + candidate
        parts = urlsplit(candidate)
        if parts.scheme.lower() not in ("http", "https"):
            return None
        host = (parts.hostname or "").lower().rstrip(".")
        if not host:
            return None
        labels = host.split(".")
        reg = registrable_domain(host)
        path_query = parts.path + (("?" + parts.query) if parts.query else "")
        return ParsedUrl(
            raw=candidate[:MAX_URL_LEN],
            scheme=parts.scheme.lower(),
            host=host,
            registrable=reg,
            path_query=path_query,
            has_userinfo="@" in parts.netloc,
            is_ip=_is_ip_host(host),
            is_punycode=any(lbl.startswith("xn--") for lbl in labels),
            has_non_ascii=any(ord(c) > 127 for c in host),
            is_shortener=reg in SHORTENERS,
            tld=labels[-1],
            length=len(candidate),
            subdomain_labels=max(0, len(labels) - len(reg.split("."))),
        )
    except ValueError:
        return None


def extract_urls(text: str, limit: int = 100) -> list[str]:
    """Text se URLs (www. wale bhi), duplicate hata kar, order barqarar."""
    seen: dict[str, None] = {}
    for m in URL_RE.finditer(text or ""):
        url = m.group(0).rstrip(_TRAILING)
        if url and url not in seen:
            seen[url[:MAX_URL_LEN]] = None
            if len(seen) >= limit:
                break
    return list(seen)


def defang(url: str) -> str:
    """hxxps://evil[.]com taake galti se click na ho aur auto-link na bane."""
    out = re.sub(r"^http", "hxxp", url, flags=re.IGNORECASE)
    return out.replace(".", "[.]")
