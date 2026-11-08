"""Google OAuth / Gmail HTTP calls. Har call pe timeout + retry/backoff (sirf network error ya 5xx/429 par).
Token, code, client secret kabhi log nahi hote; sirf status code aur Google ka error code."""
import logging
import time

import httpx

from backend.app.config import get_settings

log = logging.getLogger("aliguard.google")

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105  (public URL, secret nahi)
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
PROFILE_URL = "https://gmail.googleapis.com/gmail/v1/users/me/profile"
GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.modify"


class GoogleError(Exception):
    """Google se baat nakam. `code` sirf short label hai (user ko tafseel nahi dikhti)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _request(method: str, url: str, **kwargs) -> httpx.Response:
    s = get_settings()
    attempts = max(1, s.google_http_retries)
    for attempt in range(attempts):
        try:
            with httpx.Client(timeout=s.google_http_timeout_seconds) as client:
                resp = client.request(method, url, **kwargs)
            if resp.status_code < 500 and resp.status_code != 429:
                return resp
            log.warning("Google %s ne status %s diya (try %s)", url.split("?")[0], resp.status_code, attempt + 1)
        except httpx.HTTPError as exc:
            log.warning("Google network error %s (try %s)", type(exc).__name__, attempt + 1)
        if attempt < attempts - 1:
            time.sleep(min(0.5 * 2**attempt, 4.0))  # exponential backoff
    raise GoogleError("google_unreachable")


def exchange_code(code: str, verifier: str) -> dict:
    """Authorization code + PKCE verifier -> tokens. Nakam ho to GoogleError."""
    s = get_settings()
    resp = _request(
        "POST",
        TOKEN_URL,
        data={
            "client_id": s.google_client_id,
            "client_secret": s.google_client_secret,
            "code": code,
            "code_verifier": verifier,
            "grant_type": "authorization_code",
            "redirect_uri": s.oauth_redirect_uri,
        },
    )
    if resp.status_code != 200:
        err = ""
        try:
            err = str(resp.json().get("error", ""))[:40]
        except ValueError:
            pass
        log.warning("Token exchange nakam: status=%s error=%s", resp.status_code, err)
        raise GoogleError("token_exchange_failed")
    try:
        data = resp.json()
    except ValueError as exc:
        raise GoogleError("token_bad_response") from exc
    if not isinstance(data, dict) or not isinstance(data.get("access_token"), str):
        raise GoogleError("token_bad_response")
    return data


def refresh_access_token(refresh_token: str) -> dict:
    """Refresh token -> naya access token. Token wapas lena Google ne mana kiya ho (invalid_grant: user ne
    access hata diya, password badla, ya Testing mode mein 7 din guzar gaye) to GoogleError("invalid_grant")."""
    s = get_settings()
    resp = _request(
        "POST",
        TOKEN_URL,
        data={
            "client_id": s.google_client_id,
            "client_secret": s.google_client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
    )
    if resp.status_code != 200:
        err = ""
        try:
            err = str(resp.json().get("error", ""))[:40]
        except ValueError:
            pass
        log.warning("Token refresh nakam: status=%s error=%s", resp.status_code, err)
        raise GoogleError("invalid_grant" if err == "invalid_grant" else "refresh_failed")
    try:
        data = resp.json()
    except ValueError as exc:
        raise GoogleError("token_bad_response") from exc
    if not isinstance(data, dict) or not isinstance(data.get("access_token"), str):
        raise GoogleError("token_bad_response")
    return data


def fetch_profile_email(access_token: str) -> str:
    """Gmail profile se mailbox ki email (sirf gmail.modify scope kafi hai)."""
    resp = _request("GET", PROFILE_URL, headers={"Authorization": f"Bearer {access_token}"})
    if resp.status_code != 200:
        log.warning("Gmail profile nakam: status=%s", resp.status_code)
        raise GoogleError("profile_failed")
    try:
        email = resp.json().get("emailAddress")
    except ValueError as exc:
        raise GoogleError("profile_bad_response") from exc
    if not isinstance(email, str) or "@" not in email or len(email) > 254:
        raise GoogleError("profile_bad_response")
    return email.strip().lower()


def revoke(token: str) -> bool:
    """Best-effort revoke: ek hi koshish, kabhi exception nahi uchalta. True = Google ne maan liya."""
    try:
        with httpx.Client(timeout=get_settings().google_http_timeout_seconds) as client:
            resp = client.post(REVOKE_URL, data={"token": token})
        return resp.status_code == 200
    except httpx.HTTPError as exc:
        log.warning("Google revoke network error %s", type(exc).__name__)
        return False
