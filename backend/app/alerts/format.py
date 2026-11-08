"""Alert ka text banana (pure). Sender/subject/reasons attacker-controlled hain: control characters saaf,
lambai capped, aur sirf plain text (Telegram parse_mode nahi, email HTML nahi) taake koi markup/injection na chale.
URLs hamesha defanged jate hain."""
import re

from backend.app.worker.decision import clean_text
from engine.urls import defang

_ACTION_TEXT = {
    "quarantined": "Email inbox se hata kar 'AliGuard/Quarantine' mein rakh di gayi (delete nahi hui).",
    "labeled": "Email par 'AliGuard/Suspicious' label laga diya gaya.",
    "pending": "Label lagana abhi baqi hai; worker dobara koshish karega.",
    "failed": "Gmail par action lagne mein masla aaya; dashboard mein dekh lein.",
}
_RAW_HTTP = re.compile(r"^https?://", re.IGNORECASE)


def safe_url(url: str) -> str:
    """Pehle se defanged URL ko dobara nahi chhedte; asal http(s) URL ho to defang karte hain."""
    text = clean_text(url, 120)
    return defang(text) if _RAW_HTTP.match(text) else text


def build_scan_alert(*, verdict: str, score: int, action_taken: str, sender: str, subject: str,
                     reasons: list, urls: list, dashboard_url: str) -> tuple[str, str]:
    quarantined = action_taken == "quarantined"
    title = "AliGuard: phishing email quarantine ki gayi" if quarantined else "AliGuard: shak wali email mili"
    lines = [
        f"Verdict: {clean_text(verdict, 12)} (score {int(score)}/100)",
        f"Sender: {clean_text(sender, 200)}",
        f"Subject: {clean_text(subject, 150)}",
    ]
    for reason in list(reasons or [])[:3]:
        lines.append(f"- {clean_text(reason, 200)}")
    shown = [safe_url(u) for u in list(urls or [])[:3]]
    if shown:
        lines.append("Links (defanged, na kholein): " + "  ".join(shown))
    lines.append(_ACTION_TEXT.get(action_taken, ""))
    lines.append(f"Dashboard: {dashboard_url}")
    body = "\n".join(line for line in lines if line)
    return title, body[:3500]


def build_throttle_notice(limit: int, dashboard_url: str) -> tuple[str, str]:
    return (
        "AliGuard: bohat zyada alerts",
        f"Ek ghante mein {int(limit)} se zyada shak wali emails aayin. Baqi alerts ruk gaye hain, "
        f"lekin sab scan dashboard mein dikhte hain: {dashboard_url}",
    )


def build_reauth_notice(account_email: str, dashboard_url: str) -> tuple[str, str]:
    return (
        "AliGuard: Gmail dobara connect karein",
        f"{clean_text(account_email, 200)} ki Gmail ijazat khatam ho gayi (access hata diya gaya ya Google ne token "
        f"expire kar diya). Jab tak dobara connect nahi karte, is account ki emails scan nahi hongi.\n"
        f"Dashboard: {dashboard_url}",
    )
