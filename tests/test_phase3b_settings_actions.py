"""Phase 3B API regressions: settings validation, whitelist isolation, feedback and restore ownership."""
from backend.app.models import Feedback
from backend.app.scans import actions as scan_actions


def _login(api, email):
    api.signup_verify(email, gmail=True)
    assert api.login(email).status_code == 200


def _csrf(api):
    return {"X-CSRF-Token": api.c.cookies.get("aliguard_csrf", "")}


def test_settings_defaults_and_threshold_validation(api):
    _login(api, "settings@example.com")
    data = api.get("/api/settings")
    assert data.status_code == 200
    body = data.json()
    assert body["suspicious_threshold"] < body["phishing_threshold"]
    assert body["whitelist"] == []

    bad = api.c.patch("/api/settings", json={"suspicious_threshold": 90, "phishing_threshold": 70}, headers=_csrf(api))
    assert bad.status_code == 422
    good = api.c.patch("/api/settings", json={"suspicious_threshold": 45, "phishing_threshold": 80}, headers=_csrf(api))
    assert good.status_code == 200
    assert good.json()["suspicious_threshold"] == 45
    assert good.json()["phishing_threshold"] == 80


def test_whitelist_is_validated_and_tenant_scoped(api, api2):
    _login(api, "owner@example.com")
    _login(api2, "other@example.com")
    added = api.post("/api/settings/whitelist", {"kind": "domain", "value": "example.com"})
    assert added.status_code == 200
    duplicate = api.post("/api/settings/whitelist", {"kind": "domain", "value": "example.com"})
    assert duplicate.status_code == 409
    invalid = api.post("/api/settings/whitelist", {"kind": "domain", "value": "https://example.com/path"})
    assert invalid.status_code == 422
    assert api2.get("/api/settings").json()["whitelist"] == []
    deleted = api2.c.delete("/api/settings/whitelist/" + added.json()["id"], headers=_csrf(api2))
    assert deleted.status_code == 404


def test_feedback_is_single_use_and_user_scoped(api, api2, user_id, make_account, make_scan, db):
    _login(api, "feedback-owner@example.com")
    _login(api2, "feedback-other@example.com")
    scan = make_scan(make_account(user_id("feedback-owner@example.com")), verdict="PHISHING", score=90)
    assert api2.post(f"/api/scans/{scan.id}/feedback", {"kind": "not_phishing"}).status_code == 404
    assert api.post(f"/api/scans/{scan.id}/feedback", {"kind": "not_phishing"}).status_code == 200
    assert api.post(f"/api/scans/{scan.id}/feedback", {"kind": "not_phishing"}).status_code == 409
    assert db.query(Feedback).filter(Feedback.scan_id == scan.id).count() == 1


def test_restore_only_own_quarantined_scan(api, api2, user_id, make_account, make_scan, monkeypatch):
    _login(api, "restore-owner@example.com")
    _login(api2, "restore-other@example.com")
    scan = make_scan(make_account(user_id("restore-owner@example.com")), verdict="PHISHING", score=99,
                     action="quarantined")
    assert api2.post(f"/api/scans/{scan.id}/restore", {}).status_code == 404

    restored = []
    class FakeGmail:
        def __init__(self, token): pass
        def restore(self, message_id): restored.append(message_id)
    monkeypatch.setattr(scan_actions, "access_token_for", lambda db, account: "fake-token")
    monkeypatch.setattr(scan_actions.gmail_api, "GmailClient", FakeGmail)
    response = api.post(f"/api/scans/{scan.id}/restore", {})
    assert response.status_code == 200, response.text
    assert restored == [scan.gmail_message_id]
    assert api.get(f"/api/scans/{scan.id}").json()["action_taken"] == "restored"


def test_feedback_rejects_unknown_kind(api, user_id, make_account, make_scan):
    _login(api, "feedback-kind@example.com")
    scan = make_scan(make_account(user_id("feedback-kind@example.com")))
    assert api.post(f"/api/scans/{scan.id}/feedback", {"kind": "train_model_now"}).status_code == 422
