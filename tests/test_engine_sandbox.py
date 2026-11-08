"""Sandbox tests. Asli browser wala test sirf tab chalta hai jab Chromium installed ho."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from engine.analyzer import Engine
from engine.models import EmailInput, Verdict
from engine.sandbox import (
    FormInfo,
    LinkSandbox,
    PageSnapshot,
    PlaywrightFetcher,
    evaluate_snapshot,
    is_allowed_target,
    is_public_host,
    pick_candidates,
)


# ------------------------------------------------------------------ SSRF guard
@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://localhost/admin", "http://169.254.169.254/latest/meta-data",
    "http://10.0.0.5/", "http://192.168.1.1/", "http://[::1]/", "file:///etc/passwd",
    "ftp://example.com/", "http://metadata.google.internal/", "https://example.com:8443/",
])
def test_ssrf_guard_blocks(url):
    assert not is_allowed_target(url)


def test_private_allowed_only_when_explicit():
    assert is_public_host("127.0.0.1", allow_private=True)
    assert not is_public_host("127.0.0.1")


# ------------------------------------------------------------------ scoring (pure)
def _pw_form(action=""):
    return FormInfo(action=action, method="post", has_password=True, input_types=["email", "password"])


def test_clean_page_scores_zero():
    snap = PageSnapshot(requested_url="https://example.org/a", final_url="https://example.org/a",
                        redirect_chain=["https://example.org/a"], title="Our blog", text="Hello")
    pts, sig = evaluate_snapshot(snap)
    assert pts == 0 and sig == []


def test_fake_paypal_login_page_is_phishing_grade():
    snap = PageSnapshot(
        requested_url="https://bit.ly/x1", final_url="https://secure-paypa1-login.xyz/signin",
        redirect_chain=["https://bit.ly/x1", "https://t.co/a", "https://r.example/b",
                        "https://secure-paypa1-login.xyz/signin"],
        title="PayPal - Log in", text="PayPal Log in to your account", forms=[_pw_form("https://collect.evil.top/p")])
    pts, sig = evaluate_snapshot(snap)
    codes = {s.code for s in sig}
    assert {"sbx_password_form", "sbx_form_other_domain", "sbx_brand_mismatch", "sbx_long_redirect"} <= codes
    assert pts >= 60


def test_real_paypal_login_not_flagged_as_brand_mismatch():
    snap = PageSnapshot(requested_url="https://www.paypal.com/signin", final_url="https://www.paypal.com/signin",
                        redirect_chain=["https://www.paypal.com/signin"], title="PayPal - Log in",
                        forms=[_pw_form("https://www.paypal.com/auth")])
    _, sig = evaluate_snapshot(snap)
    assert "sbx_brand_mismatch" not in {s.code for s in sig}
    assert "sbx_form_other_domain" not in {s.code for s in sig}


def test_blog_mentioning_brand_without_login_not_flagged():
    snap = PageSnapshot(requested_url="https://blog.example.org/", final_url="https://blog.example.org/",
                        redirect_chain=["https://blog.example.org/"], title="My weekly notes",
                        text="I read an article about Google and Amazon today")
    pts, _ = evaluate_snapshot(snap)
    assert pts == 0


def test_executable_download_flagged():
    snap = PageSnapshot(requested_url="https://a.example/", final_url="https://a.example/",
                        redirect_chain=["https://a.example/"], downloads=["invoice.exe"])
    pts, sig = evaluate_snapshot(snap)
    assert pts >= 45 and sig[0].code == "sbx_auto_download_exec"


def test_unreachable_page_gives_no_points():
    snap = PageSnapshot(requested_url="https://dead.example/", error="navigation:TimeoutError")
    assert evaluate_snapshot(snap) == (0.0, [])


def test_pick_candidates_prefers_suspicious_and_dedupes():
    urls = ["https://example.org/a", "https://bit.ly/zz", "https://bit.ly/zz", "https://x.top/p"]
    out = pick_candidates(urls, 2)
    assert out[0] in {"https://bit.ly/zz", "https://x.top/p"} and len(out) == 2 and len(set(out)) == 2


# ------------------------------------------------------------------ engine integration
class FakeFetcher:
    def __init__(self, snap: PageSnapshot | None = None, boom: bool = False):
        self.snap, self.boom, self.calls = snap, boom, []

    def fetch(self, url: str) -> PageSnapshot:
        self.calls.append(url)
        if self.boom:
            raise RuntimeError("browser died")
        return self.snap or PageSnapshot(requested_url=url, final_url=url, redirect_chain=[url])


PHISH = EmailInput(
    subject="Urgent: your PayPal account is limited",
    sender_name="PayPal Support", sender_email="service@paypa1-secure.top",
    text_body="Your account is suspended. Verify immediately: https://paypa1-secure.top/login",
)


def _bad_snap(url: str) -> PageSnapshot:
    return PageSnapshot(requested_url=url, final_url=url, redirect_chain=[url], title="PayPal - Log in",
                        text="PayPal", forms=[_pw_form("https://collect.evil.top/p")])


def test_engine_without_sandbox_never_opens_links():
    r = Engine(model=None).analyze(PHISH)
    assert r.sandbox_reports == [] and r.layer_scores["sandbox"] is None


def test_engine_with_sandbox_adds_signals_and_report():
    fetcher = FakeFetcher(_bad_snap("https://paypa1-secure.top/login"))
    r = Engine(model=None, sandbox=LinkSandbox(fetcher)).analyze(PHISH)
    assert fetcher.calls and r.verdict is Verdict.PHISHING
    assert r.layer_scores["sandbox"] and r.layer_scores["sandbox"] > 0
    assert r.sandbox_reports and r.sandbox_reports[0]["forms"][0]["has_password"] is True
    assert any(s.layer == "sandbox" for s in r.signals)


def test_clean_mail_links_are_not_opened():
    fetcher = FakeFetcher()
    mail = EmailInput(subject="Lunch?", sender_name="Sam", sender_email="sam@example.org",
                      text_body="See you at noon. Menu: https://example.org/menu")
    Engine(model=None, sandbox=LinkSandbox(fetcher)).analyze(mail)
    assert fetcher.calls == []  # score < sandbox_min_score


def test_sandbox_crash_does_not_break_analysis():
    r = Engine(model=None, sandbox=LinkSandbox(FakeFetcher(boom=True))).analyze(PHISH)
    assert r.verdict in (Verdict.SUSPICIOUS, Verdict.PHISHING)
    assert any(n.startswith("sandbox_error") for n in r.notes)


# ------------------------------------------------------------------ real browser (optional)
class _H(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/go":
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return
        body = (b"<html><head><title>PayPal - Log in</title></head><body><h1>PayPal</h1>"
                b"<form action='http://other.test/post' method='post'><input name=u>"
                b"<input type=password name=p></form></body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # noqa: D401
        pass


def _chromium_ok() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            p.chromium.launch().close()
        return True
    except Exception:  # noqa: BLE001
        return False


@pytest.mark.skipif(not _chromium_ok(), reason="Chromium installed nahi (playwright install chromium)")
def test_real_browser_inspects_local_phishing_page():
    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_port}/go"
        res = LinkSandbox(PlaywrightFetcher(allow_private=True)).inspect(url)
        codes = {s.code for s in res.signals}
        assert res.snapshot.final_url.endswith("/login") and len(res.snapshot.redirect_chain) >= 2
        assert {"sbx_password_form", "sbx_brand_mismatch"} <= codes
        # allow_private=False => localhost band, kuch khulta hi nahi
        blocked = PlaywrightFetcher().fetch(url)
        assert blocked.error == "target_not_allowed"
    finally:
        srv.shutdown()
