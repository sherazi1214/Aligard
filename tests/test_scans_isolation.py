"""Scans API: tenant isolation, pagination/filter/search, XSS-safety."""
import re
import uuid
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError

from backend.app.models import Scan

XSS = "<script>alert(1)</script>"
ROOT = Path(__file__).resolve().parents[1]


def _login(api, email):
    api.signup_verify(email, gmail=True)
    assert api.login(email).status_code == 200


def _two_users(api, api2, user_id, make_account):
    _login(api, "a@example.com")
    _login(api2, "b@example.com")
    acc_a = make_account(user_id("a@example.com"), "a@gmail.com")
    acc_b = make_account(user_id("b@example.com"), "b@gmail.com")
    return acc_a, acc_b


def test_scan_endpoints_require_login(api):
    for path in ("/api/scans", "/api/scans/stats", f"/api/scans/{uuid.uuid4()}", "/api/gmail/accounts"):
        assert api.get(path).status_code == 401, path


def test_user_cannot_read_other_users_scans(api, api2, user_id, make_account, make_scan):
    acc_a, acc_b = _two_users(api, api2, user_id, make_account)
    secret = make_scan(acc_a, subject="A ka secret", sender="boss@a.example")
    mine = make_scan(acc_b, subject="B ka scan")

    # B ki list mein sirf B ka scan
    items = api2.get("/api/scans").json()["items"]
    assert [i["id"] for i in items] == [str(mine.id)]
    assert "A ka secret" not in api2.get("/api/scans").text

    # A ka scan id jaan kar bhi B ko 404 (403 nahi: existence bhi leak na ho), ek jaisa jawab
    r = api2.get(f"/api/scans/{secret.id}")
    missing = api2.get(f"/api/scans/{uuid.uuid4()}")
    assert r.status_code == 404 and r.json() == missing.json()
    assert "A ka secret" not in r.text

    # A ka account_id filter lagane se bhi kuch nahi milta
    r = api2.get("/api/scans", params={"account_id": str(acc_a.id)})
    assert r.status_code == 200 and r.json()["items"] == [] and r.json()["total"] == 0

    # search se bhi A ka data nahi nikalta
    assert api2.get("/api/scans", params={"q": "secret"}).json()["total"] == 0

    # A ko apna scan milta hai
    assert api.get(f"/api/scans/{secret.id}").status_code == 200


def test_stats_are_per_user(api, api2, user_id, make_account, make_scan):
    acc_a, acc_b = _two_users(api, api2, user_id, make_account)
    make_scan(acc_a, verdict="PHISHING", action="quarantined")
    make_scan(acc_a, verdict="SUSPICIOUS")
    make_scan(acc_a, verdict="SAFE")
    make_scan(acc_b, verdict="SAFE")
    assert api.get("/api/scans/stats").json() == {
        "scanned": 3, "safe": 1, "suspicious": 1, "phishing": 1, "quarantined": 1,
    }
    assert api2.get("/api/scans/stats").json() == {
        "scanned": 1, "safe": 1, "suspicious": 0, "phishing": 0, "quarantined": 0,
    }


def test_pagination_filter_and_search(api, user_id, make_account, make_scan):
    _login(api, "a@example.com")
    acc = make_account(user_id("a@example.com"))
    for i in range(25):
        make_scan(acc, subject=f"mail {i}", verdict="PHISHING" if i % 5 == 0 else "SAFE")
    make_scan(acc, subject="100% off_deal", sender="Promo@Shop.example")

    first = api.get("/api/scans", params={"page_size": 10}).json()
    assert first["total"] == 26 and len(first["items"]) == 10
    assert first["items"][0]["subject"] == "100% off_deal"  # naya pehle
    third = api.get("/api/scans", params={"page_size": 10, "page": 3}).json()
    assert len(third["items"]) == 6
    ids = {i["id"] for p in (1, 2, 3) for i in api.get("/api/scans", params={"page_size": 10, "page": p}).json()["items"]}
    assert len(ids) == 26  # koi row dohrai ya gum nahi

    phish = api.get("/api/scans", params={"verdict": "PHISHING", "page_size": 50}).json()
    assert phish["total"] == 5 and all(i["verdict"] == "PHISHING" for i in phish["items"])

    # search case-insensitive, sender par bhi; % aur _ literal hain (wildcard nahi)
    assert api.get("/api/scans", params={"q": "PROMO@shop"}).json()["total"] == 1
    assert api.get("/api/scans", params={"q": "100%"}).json()["total"] == 1
    assert api.get("/api/scans", params={"q": "%"}).json()["total"] == 1
    assert api.get("/api/scans", params={"q": "off_d"}).json()["total"] == 1
    assert api.get("/api/scans", params={"q": "off.d"}).json()["total"] == 0


def test_query_params_validated(api):
    _login(api, "a@example.com")
    for params in ({"page_size": 1000}, {"page": 0}, {"verdict": "EVIL"}, {"q": "x" * 101}, {"account_id": "nope"}):
        r = api.get("/api/scans", params=params)
        assert r.status_code == 422, params
        assert "x" * 101 not in r.text  # input echo nahi hota
    assert api.get("/api/scans/not-a-uuid").status_code == 422


def test_scan_detail_fields(api, user_id, make_account, make_scan):
    _login(api, "a@example.com")
    acc = make_account(user_id("a@example.com"))
    s = make_scan(acc, verdict="PHISHING", score=91, reasons=["fake login"], urls=["hxxps://evil[.]com/x"],
                  layer_scores={"heuristics": 80.0, "ml": 70.0, "reputation": None})
    d = api.get(f"/api/scans/{s.id}").json()
    assert d["reasons"] == ["fake login"] and d["urls"] == ["hxxps://evil[.]com/x"]
    assert d["layer_scores"]["reputation"] is None and d["model_version"] == "test-1"
    assert "gmail_message_id" not in d and "user_id" not in d


def test_xss_subject_is_json_text_and_never_in_html(api, user_id, make_account, make_scan):
    _login(api, "a@example.com")
    acc = make_account(user_id("a@example.com"))
    s = make_scan(acc, subject=XSS, sender=f"{XSS}@evil.example", reasons=[XSS], verdict="PHISHING")
    for path in ("/api/scans", f"/api/scans/{s.id}"):
        r = api.get(path)
        assert r.headers["content-type"].startswith("application/json")
        assert r.headers["x-content-type-options"] == "nosniff"
        assert XSS in r.text  # API raw data deti hai (JSON), escape UI ka kaam hai
    # Dashboard HTML shell mein attacker ka text kabhi nahi aata, aur CSP strict hai
    page = api.get("/dashboard")
    assert page.status_code == 200 and XSS not in page.text
    csp = page.headers["content-security-policy"]
    assert "unsafe-inline" not in csp and "script-src 'self'" in csp and "default-src 'none'" in csp
    # UI code sirf textContent se render karta hai (browser mein asli run nahi hua, sirf static check)
    js = (ROOT / "web" / "static" / "dashboard.js").read_text()
    assert "textContent" in js
    assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function", js)


def test_same_gmail_message_id_dedupes_per_account(api, db, user_id, make_account, make_scan):
    _login(api, "a@example.com")
    acc = make_account(user_id("a@example.com"))
    make_scan(acc, mid="m1")
    with pytest.raises(IntegrityError):
        make_scan(acc, mid="m1")
    db.rollback()
    assert db.query(Scan).count() == 1
