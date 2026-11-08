"""Layer 3: URL reputation (VirusTotal + local threat feeds). Engine URL ko khud kabhi visit nahi
karta, sirf lookup karta hai."""
from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import httpx

from engine.urls import parse_url

log = logging.getLogger("engine.reputation")


class ProviderError(Exception):
    """Provider fail hua (network, rate limit...). Engine isay 'degraded' ke taur par handle karta hai."""


@dataclass
class ReputationResult:
    source: str
    url: str
    malicious: int = 0
    suspicious: int = 0
    total: int = 0
    listed: bool = False  # threat feed mein listed


class ReputationProvider(Protocol):
    name: str

    def lookup(self, url: str) -> ReputationResult | None: ...


class TTLCache:
    """Chhota thread-safe in-memory cache. Phase 3 mein Redis se badal sakte hain (same get/set)."""

    def __init__(self, ttl_seconds: float = 6 * 3600, max_items: int = 5000) -> None:
        self._ttl, self._max = ttl_seconds, max_items
        self._data: dict[str, tuple[float, object]] = {}
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            if item[0] < time.monotonic():
                del self._data[key]
                return None
            return item[1]

    def set(self, key: str, value: object) -> None:
        with self._lock:
            if len(self._data) >= self._max:
                self._data.pop(next(iter(self._data)))
            self._data[key] = (time.monotonic() + self._ttl, value)


class TokenBucket:
    """Rate limiter (VT free tier ~4 requests/min)."""

    def __init__(self, per_minute: int = 4) -> None:
        self._capacity = float(per_minute)
        self._tokens = float(per_minute)
        self._rate = per_minute / 60.0
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            now = time.monotonic()
            self._tokens = min(self._capacity, self._tokens + (now - self._last) * self._rate)
            self._last = now
            if self._tokens >= 1:
                self._tokens -= 1
                return True
            return False


class VirusTotalProvider:
    """VT v3 se pehle se maujood report lookup. URL submit NAHI karta (privacy: submit karne se
    URL VT community ko dikhta hai, aur us mein personal tokens ho sakte hain).

    id_mode "sha256": VT ko sirf URL ka hash jata hai (privacy behtar), lekin VT ki canonical
    form se na milne par report 'unknown' aa sakti hai. "base64": VT docs ka guaranteed tareeqa,
    lekin poora URL VT ko dikhta hai. Real API key ke saath apne URLs par dono try karna."""

    name = "virustotal"

    def __init__(
        self,
        api_key: str,
        client: httpx.Client | None = None,
        cache: TTLCache | None = None,
        limiter: TokenBucket | None = None,
        id_mode: str = "sha256",
        base_url: str = "https://www.virustotal.com/api/v3",
        timeout: float = 8.0,
        retries: int = 1,
        before_request=None,
    ) -> None:
        # before_request: asli network call se theek pehle chalta hai (cache miss ke baad); budget guard yahan lagta hai
        self._before_request = before_request
        self._key = api_key
        self._client = client or httpx.Client(timeout=timeout)
        self._cache = cache or TTLCache()
        self._limiter = limiter or TokenBucket(4)
        self._id_mode, self._base, self._retries = id_mode, base_url.rstrip("/"), retries

    def _url_id(self, url: str) -> str:
        if self._id_mode == "base64":
            import base64

            return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return hashlib.sha256(url.encode()).hexdigest()

    def lookup(self, url: str) -> ReputationResult | None:
        uid = self._url_id(url)
        cached = self._cache.get(uid)
        if cached is not None:
            return cached  # type: ignore[return-value]
        if not self._limiter.allow():
            raise ProviderError("virustotal: local rate limit")
        if self._before_request is not None:
            self._before_request()  # budget khatam ho to ProviderError
        resp = None
        for attempt in range(self._retries + 1):
            try:
                resp = self._client.get(
                    f"{self._base}/urls/{uid}", headers={"x-apikey": self._key}
                )
            except httpx.HTTPError as exc:
                if attempt == self._retries:
                    raise ProviderError(f"virustotal: network error ({type(exc).__name__})") from exc
                time.sleep(0.5 * (2**attempt))
                continue
            if resp.status_code >= 500 and attempt < self._retries:
                time.sleep(0.5 * (2**attempt))
                continue
            break
        assert resp is not None  # noqa: S101
        if resp.status_code == 404:
            result = ReputationResult(self.name, url)  # report maujood nahi: unknown
        elif resp.status_code == 429:
            raise ProviderError("virustotal: rate limited by server")
        elif resp.status_code in (401, 403):
            raise ProviderError("virustotal: auth error (check API key)")
        elif resp.status_code != 200:
            raise ProviderError(f"virustotal: HTTP {resp.status_code}")
        else:
            try:
                stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
                total = sum(int(v) for v in stats.values())
                result = ReputationResult(
                    self.name, url, int(stats.get("malicious", 0)),
                    int(stats.get("suspicious", 0)), total,
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ProviderError("virustotal: unexpected response shape") from exc
        self._cache.set(uid, result)
        return result


class LocalFeed:
    """Local threat feed (URLhaus/OpenPhish dumps). Network nahi, bilkul sasta aur tez.
    Domain-only entries host par match hoti hain; URL entries sirf exact URL par (compromised
    legit hosts par false positive se bachne ke liye)."""

    def __init__(self, name: str, urls: set[str], hosts: set[str]) -> None:
        self.name, self._urls, self._hosts = name, urls, hosts

    @staticmethod
    def _norm(url: str) -> str | None:
        p = parse_url(url)
        return f"{p.scheme}://{p.host}{p.path_query}" if p else None

    @classmethod
    def from_lines(cls, name: str, lines: list[str]) -> LocalFeed:
        urls: set[str] = set()
        hosts: set[str] = set()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "/" in line or line.lower().startswith(("http", "www.")):
                norm = cls._norm(line)
                if norm:
                    urls.add(norm)
            else:
                hosts.add(line.lower().rstrip("."))
        return cls(name, urls, hosts)

    @classmethod
    def from_file(cls, name: str, path: str | Path) -> LocalFeed:
        return cls.from_lines(name, Path(path).read_text(encoding="utf-8").splitlines())

    def lookup(self, url: str) -> ReputationResult | None:
        p = parse_url(url)
        if not p:
            return None
        norm = f"{p.scheme}://{p.host}{p.path_query}"
        listed = norm in self._urls or p.host in self._hosts or p.registrable in self._hosts
        return ReputationResult(self.name, url, listed=listed)
