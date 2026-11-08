import re


def _login(api, email="user@example.com"):
    api.signup_verify(email)
    assert api.login(email).status_code == 200


def test_dashboard_requires_login(api):
    r = api.get("/dashboard", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_dashboard_renders_for_logged_in_user_with_strict_csp(api):
    _login(api)
    r = api.get("/dashboard")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    assert "Gmail Scan" in r.text and "Link Check" in r.text and "Message Check" in r.text
    assert 'src="/static/dashboard.js"' in r.text
    assert not re.search(r"<script(?![^>]*\bsrc=)", r.text)
    csp = r.headers["content-security-policy"]
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp


def test_index_redirects_logged_in_user_to_dashboard(api):
    assert api.get("/", follow_redirects=False).headers["location"] == "/login"
    _login(api)
    assert api.get("/", follow_redirects=False).headers["location"] == "/dashboard"


def test_static_dashboard_js_served(api):
    assert api.get("/static/dashboard.js").status_code == 200
