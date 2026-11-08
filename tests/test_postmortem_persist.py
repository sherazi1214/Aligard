"""Postmortem DB mein save hota hai, sirf apne user ko dikhta hai, aur size-capped hai."""
from backend.app.worker.scanner import _MAX_POSTMORTEM_BYTES, _safe_postmortem

PM = {"version": 1, "sandbox": [{"url": "hxxps://evil[.]top/x", "final_url": "hxxps://evil[.]top/login",
                                 "redirect_chain": ["hxxps://bit[.]ly/x"], "forms": [{"has_password": True}],
                                 "findings": ["Page asks for a password"]}],
      "attachments": [], "domains": [{"domain": "evil.top", "age_days": 2}], "qr_links": []}


def _login(api, email):
    api.signup_verify(email, gmail=True)
    assert api.login(email).status_code == 200


def test_detail_returns_postmortem_and_other_user_gets_404(api, api2, user_id, make_account, make_scan, db):
    _login(api, "a@example.com")
    _login(api2, "b@example.com")
    acc = make_account(user_id("a@example.com"), "a@gmail.com")
    scan = make_scan(acc, verdict="PHISHING", score=95)
    scan.postmortem = PM
    db.commit()
    d = api.get(f"/api/scans/{scan.id}").json()
    assert d["postmortem"]["sandbox"][0]["forms"][0]["has_password"] is True
    assert "https://" not in str(d["postmortem"])  # defanged
    assert api2.get(f"/api/scans/{scan.id}").status_code == 404


def test_scan_without_postmortem_returns_null(api, user_id, make_account, make_scan):
    _login(api, "a@example.com")
    scan = make_scan(make_account(user_id("a@example.com"), "a@gmail.com"))
    assert api.get(f"/api/scans/{scan.id}").json()["postmortem"] is None


def test_safe_postmortem_caps_size_and_rejects_junk():
    assert _safe_postmortem(None) is None and _safe_postmortem("x") is None and _safe_postmortem({}) is None
    assert _safe_postmortem(PM) == PM
    huge = {"version": 1, "sandbox": [{"findings": ["x" * 500] * 100}] * 5, "attachments": [{"n": "y" * 500}] * 80}
    out = _safe_postmortem(huge)
    assert out["truncated"] is True and len(str(out)) < _MAX_POSTMORTEM_BYTES
