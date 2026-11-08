"""Domain age (RDAP). Naya registered domain phishing ka bohat mazboot signal hai.
Sirf registrable domain (validated) par poochte hain; bhejne wali cheez sirf domain naam hai, email nahi.
RDAP host fixed hai (rdap.org), user input se URL nahi banta (SSRF nahi). Fail ho to chup-chaap None."""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx

from engine.models import Signal

log = logging.getLogger("engine.domainintel")
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,24}$")
_CACHE_TTL = 6 * 3600


@dataclass
class DomainInfo:
    domain: str
    age_days: int | None
    error: str | None = None

    def report(self) -> dict:
        return {"domain": self.domain, "age_days": self.age_days, "error": self.error}


def evaluate_age(domain: str, age_days: int | None) -> Signal | None:
    if age_days is None:
        return None
    if age_days < 7:
        return Signal("domain_brand_new", "domain", 30, f"Domain {domain} was registered only {age_days} day(s) ago")
    if age_days < 30:
        return Signal("domain_very_new", "domain", 20, f"Domain {domain} is only {age_days} days old")
    if age_days < 90:
        return Signal("domain_new", "domain", 8, f"Domain {domain} is less than 3 months old")
    return None


class RdapDomainIntel:
    def __init__(self, client: httpx.Client | None = None, timeout: float = 5.0) -> None:
        self._client = client or httpx.Client(timeout=timeout, follow_redirects=True,
                                              headers={"Accept": "application/rdap+json"})
        self._cache: dict[str, tuple[float, DomainInfo]] = {}

    def lookup(self, domain: str) -> DomainInfo:
        d = domain.strip().lower().rstrip(".")
        if not _DOMAIN_RE.match(d):
            return DomainInfo(d[:80], None, "invalid_domain")
        hit = self._cache.get(d)
        if hit and time.monotonic() - hit[0] < _CACHE_TTL:
            return hit[1]
        info = self._fetch(d)
        if len(self._cache) > 2000:
            self._cache.clear()
        self._cache[d] = (time.monotonic(), info)
        return info

    def _fetch(self, d: str) -> DomainInfo:
        try:
            r = self._client.get(f"https://rdap.org/domain/{d}")
            if r.status_code != 200:
                return DomainInfo(d, None, f"rdap_http_{r.status_code}")
            for ev in r.json().get("events", []):
                if ev.get("eventAction") == "registration":
                    created = datetime.fromisoformat(str(ev["eventDate"]).replace("Z", "+00:00"))
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    return DomainInfo(d, max(0, (datetime.now(timezone.utc) - created).days))
            return DomainInfo(d, None, "no_registration_event")
        except Exception as exc:  # noqa: BLE001
            log.info("RDAP fail %s: %s", d, type(exc).__name__)
            return DomainInfo(d, None, f"rdap_error:{type(exc).__name__}")
