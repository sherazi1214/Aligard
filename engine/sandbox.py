"""Link sandbox: email ke link ko isolated headless browser mein khol kar "postmortem" karta hai.

Do hisse (jaan-boojh kar alag):
  1) Fetcher (PlaywrightFetcher)  - asli browser, sirf dekhta hai: redirect chain, forms, title, downloads.
  2) evaluate_snapshot()          - pure function: snapshot ko Signal/points mein badalta hai (bina browser test).

Security usool (ye module attacker ke page ko KHOLTA hai, is liye):
  - Har request (redirect ke har hop samet) par host ko DNS se resolve karke check karte hain: private/loopback/
    link-local/metadata IP => abort (SSRF). Sirf http/https, sirf port 80/443.
  - Downloads kabhi save nahi hote, sirf filename note hota hai. Permissions, geolocation, camera sab band.
  - Har page par hard timeout; media/font load nahi hote. Har inspection ke liye naya browser context.
  - DNS rebinding se poori hifazat ke liye is ko ALAG container mein chalao jiska internal network/metadata
    tak raasta na ho (docs/SANDBOX.md). Ye code-level guard us ka badal nahi.
  - Sandbox kabhi exception nahi uchalta; fail ho to SandboxResult(error=...) deta hai, engine notes mein likhta hai.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit

from engine.brands import OFFICIAL, brands_in
from engine.models import Signal
from engine.urls import parse_url, registrable_domain

log = logging.getLogger("engine.sandbox")

ALLOWED_PORTS = {80, 443}
EXECUTABLE_EXT = (".exe", ".msi", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".apk", ".jar",
                  ".dmg", ".iso", ".lnk", ".hta", ".zip", ".rar", ".7z", ".docm", ".xlsm")
MAX_TEXT_CHARS = 4000


# ----------------------------------------------------------------------------- SSRF guard
def is_public_host(host: str, *, allow_private: bool = False) -> bool:
    """True sirf tab jab host ke SAARE resolved IPs public hon."""
    if allow_private:
        return True
    host = host.strip("[]").lower()
    if not host or host in {"localhost", "metadata.google.internal"} or host.endswith(".internal"):
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified):
            return False
    return bool(infos)


def is_allowed_target(url: str, *, allow_private: bool = False) -> bool:
    try:
        parts = urlsplit(url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return False
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return False
    if not allow_private and port not in ALLOWED_PORTS:
        return False
    return is_public_host(parts.hostname, allow_private=allow_private)


# ----------------------------------------------------------------------------- data
@dataclass
class FormInfo:
    action: str = ""
    method: str = "get"
    has_password: bool = False
    input_types: list[str] = field(default_factory=list)


@dataclass
class PageSnapshot:
    """Browser ne asal mein kya dekha. Saari values attacker-controlled hain."""

    requested_url: str
    final_url: str = ""
    redirect_chain: list[str] = field(default_factory=list)  # requested ... final
    status: int | None = None
    title: str = ""
    text: str = ""
    forms: list[FormInfo] = field(default_factory=list)
    hidden_iframes: int = 0
    meta_refresh: bool = False
    downloads: list[str] = field(default_factory=list)  # sirf filenames
    blocked_targets: list[str] = field(default_factory=list)  # SSRF guard ne roke
    elapsed_ms: int = 0
    error: str | None = None
    screenshot_png: bytes | None = None


@dataclass
class SandboxResult:
    url: str
    points: float
    signals: list[Signal]
    snapshot: PageSnapshot

    @property
    def error(self) -> str | None:
        return self.snapshot.error

    def report(self) -> dict:
        """JSON-safe postmortem (UI/client ko dikhane ke liye). Screenshot shamil nahi."""
        s = self.snapshot
        return {
            "url": self.url, "final_url": s.final_url, "redirect_chain": s.redirect_chain,
            "status": s.status, "title": s.title[:200], "elapsed_ms": s.elapsed_ms,
            "forms": [vars(f) for f in s.forms], "hidden_iframes": s.hidden_iframes,
            "downloads": s.downloads, "blocked_targets": s.blocked_targets, "error": s.error,
            "points": self.points, "signals": [vars(x) for x in self.signals],
        }


class Fetcher(Protocol):
    def fetch(self, url: str) -> PageSnapshot: ...


# ----------------------------------------------------------------------------- scoring (pure)
def evaluate_snapshot(snap: PageSnapshot) -> tuple[float, list[Signal]]:
    """Snapshot -> (points 0-80, signals). Koi network/browser nahi."""
    sig: list[Signal] = []
    if snap.error and not snap.final_url:
        return 0.0, sig  # page khula hi nahi: koi saboot nahi (engine notes mein likhega)

    final = parse_url(snap.final_url) if snap.final_url else None
    final_reg = final.registrable if final else ""
    start = parse_url(snap.requested_url)
    start_reg = start.registrable if start else ""
    pts = 0.0

    def add(code: str, points: float, text: str) -> None:
        nonlocal pts
        pts += points
        sig.append(Signal(code, "sandbox", points, text))

    pw_forms = [f for f in snap.forms if f.has_password]
    if pw_forms:
        add("sbx_password_form", 30, "Page opened in sandbox asks for a password (login form)")
        for f in pw_forms:
            act = parse_url(f.action) if f.action.startswith(("http://", "https://")) else None
            if act and final_reg and act.registrable != final_reg:
                add("sbx_form_other_domain", 25,
                    f"Login form submits to a different site ({act.registrable})")
                break
        if final and final.scheme == "http":
            add("sbx_password_over_http", 15, "Password form served without HTTPS")

    # Page kis brand ka dikhta hai vs asli domain
    shown = brands_in(f"{snap.title} {snap.text[:MAX_TEXT_CHARS]}") if (snap.title or snap.text) else set()
    title_brands = brands_in(snap.title) if snap.title else set()
    if final_reg:
        for brand in sorted(shown):
            if final_reg in OFFICIAL[brand]:
                continue
            if brand in title_brands or pw_forms:
                add("sbx_brand_mismatch", 30,
                    f"Page presents itself as {brand.title()} but the real site is {final_reg}")
                break

    hops = max(0, len(snap.redirect_chain) - 1)
    if hops >= 3:
        add("sbx_long_redirect", 10, f"Link bounced through {hops} redirects before the page loaded")
    if start_reg and final_reg and start_reg != final_reg and hops >= 1 and (start and start.is_shortener):
        add("sbx_shortener_landing", 5, f"Shortened link landed on {final_reg}")
    if snap.meta_refresh:
        add("sbx_meta_refresh", 5, "Page forces an automatic redirect (meta refresh)")
    if snap.hidden_iframes:
        add("sbx_hidden_iframe", 10, "Page contains hidden iframes")

    for name in snap.downloads:
        if name.lower().endswith(EXECUTABLE_EXT):
            add("sbx_auto_download_exec", 45, f"Page started an automatic download of a risky file ({name[:60]})")
        else:
            add("sbx_auto_download", 20, f"Page started an automatic file download ({name[:60]})")
        break
    if snap.blocked_targets:
        add("sbx_internal_target", 20, "Link tried to redirect to an internal/private address (blocked)")

    return min(pts, 80.0), sig


# ----------------------------------------------------------------------------- real browser
_JS_PROBE = """() => {
  const forms = [...document.forms].map(f => ({
    action: f.action || '', method: (f.method || 'get').toLowerCase(),
    types: [...f.querySelectorAll('input')].map(i => (i.type || 'text').toLowerCase()),
  }));
  const loose_pw = document.querySelectorAll('input[type=password]').length;
  const hidden = [...document.querySelectorAll('iframe')].filter(fr => {
    const r = fr.getBoundingClientRect(), s = getComputedStyle(fr);
    return s.display === 'none' || s.visibility === 'hidden' || r.width < 3 || r.height < 3;
  }).length;
  const meta = !!document.querySelector('meta[http-equiv="refresh" i]');
  return {forms, loose_pw, hidden, meta,
          title: document.title || '', text: (document.body ? document.body.innerText : '')};
}"""


class PlaywrightFetcher:
    """Chromium headless. `pip install playwright && playwright install chromium` (requirements-sandbox.txt)."""

    def __init__(self, *, timeout_ms: int = 12_000, allow_private: bool = False,
                 screenshot: bool = False,
                 user_agent: str = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")) -> None:
        self.timeout_ms, self.allow_private, self.screenshot, self.user_agent = (
            timeout_ms, allow_private, screenshot, user_agent)

    def fetch(self, url: str) -> PageSnapshot:  # noqa: C901
        snap = PageSnapshot(requested_url=url)
        t0 = time.monotonic()
        if not is_allowed_target(url, allow_private=self.allow_private):
            snap.blocked_targets.append(url)
            snap.error = "target_not_allowed"
            return snap
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            snap.error = "playwright_not_installed"
            return snap
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage",
                                                   "--disable-gpu"])
                try:
                    ctx = browser.new_context(user_agent=self.user_agent, accept_downloads=True,
                                              java_script_enabled=True, permissions=[],
                                              viewport={"width": 1280, "height": 800})
                    page = ctx.new_page()
                    page.set_default_timeout(self.timeout_ms)

                    def guard(route):
                        req = route.request
                        if req.resource_type in {"media", "font"}:
                            return route.abort()
                        if not is_allowed_target(req.url, allow_private=self.allow_private):
                            if len(snap.blocked_targets) < 10:
                                snap.blocked_targets.append(req.url[:300])
                            return route.abort()
                        return route.continue_()

                    ctx.route("**/*", guard)
                    page.on("download", lambda d: (snap.downloads.append(d.suggested_filename[:120]),
                                                   d.cancel())[0])
                    chain: list[str] = [url]
                    page.on("framenavigated", lambda fr: (
                        chain.append(fr.url) if fr == page.main_frame and fr.url != chain[-1] else None))
                    try:
                        resp = page.goto(url, wait_until="load", timeout=self.timeout_ms)
                        snap.status = resp.status if resp else None
                    except Exception as exc:  # noqa: BLE001 - timeout/net error: jo mila wahi dekho
                        snap.error = f"navigation:{type(exc).__name__}"
                    if page.url and page.url != "about:blank":
                        snap.final_url = page.url
                        try:
                            page.wait_for_timeout(800)  # JS redirects ko moqa
                            snap.final_url = page.url
                            probe = page.evaluate(_JS_PROBE)
                            snap.title = str(probe["title"])[:300]
                            snap.text = str(probe["text"])[:MAX_TEXT_CHARS]
                            snap.forms = [FormInfo(f["action"][:500], f["method"],
                                                   "password" in f["types"], f["types"][:12])
                                          for f in probe["forms"][:10]]
                            if probe["loose_pw"] and not any(f.has_password for f in snap.forms):
                                snap.forms.append(FormInfo("", "post", True, ["password"]))
                            snap.hidden_iframes = int(probe["hidden"])
                            snap.meta_refresh = bool(probe["meta"])
                            if self.screenshot:
                                snap.screenshot_png = page.screenshot(type="png")
                            snap.error = None if snap.final_url else snap.error
                        except Exception as exc:  # noqa: BLE001
                            snap.error = snap.error or f"probe:{type(exc).__name__}"
                    snap.redirect_chain = chain[:15]
                finally:
                    browser.close()
        except Exception as exc:  # noqa: BLE001 - browser launch fail etc.
            log.warning("Sandbox browser error: %s", exc)
            snap.error = f"browser:{type(exc).__name__}"
        snap.elapsed_ms = int((time.monotonic() - t0) * 1000)
        return snap


# ----------------------------------------------------------------------------- public API
class LinkSandbox:
    """Engine ye object leta hai: inspect(url) -> SandboxResult. Kabhi raise nahi karta."""

    def __init__(self, fetcher: Fetcher | None = None) -> None:
        self.fetcher: Fetcher = fetcher or PlaywrightFetcher()

    def inspect(self, url: str) -> SandboxResult:
        try:
            snap = self.fetcher.fetch(url)
        except Exception as exc:  # noqa: BLE001
            log.exception("Sandbox fetch crash")
            snap = PageSnapshot(requested_url=url, error=f"crash:{type(exc).__name__}")
        points, signals = evaluate_snapshot(snap)
        return SandboxResult(url=url, points=points, signals=signals, snapshot=snap)


def pick_candidates(urls: list[str], limit: int) -> list[str]:
    """Pehle wo URLs jo shak wale lagte hain (IP, punycode, shortener, suspicious TLD), phir baqi."""
    def rank(u: str) -> int:
        p = parse_url(u)
        if not p:
            return 9
        return 0 if (p.is_ip or p.is_punycode or p.tld_suspicious or p.is_shortener
                     or p.has_userinfo) else 1
    seen: set[str] = set()
    out: list[str] = []
    for u in sorted(urls, key=rank):
        key = registrable_domain((parse_url(u) or parse_url("http://x.invalid")).host) + u
        if key in seen:
            continue
        seen.add(key)
        out.append(u)
    return out[:limit]
