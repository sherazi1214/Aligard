"""Email bhejna: console (sirf dev) ya SMTP. Failure par retry, aakhir mein sirf log."""
import logging
import smtplib
import sys
import time
from email.message import EmailMessage

from backend.app.config import get_settings

log = logging.getLogger("aliguard.mailer")


def send_email_checked(to: str, subject: str, body: str) -> bool:
    """Email bhejo. True = SMTP ne qabool ki (ya dev console); False = 3 koshishon ke baad bhi nakam.
    Alerts isi se pata karte hain ke dobara koshish karni hai ya nahi."""
    s = get_settings()
    if s.email_backend == "console":
        # DEV ONLY: production mein config validator isay rokta hai.
        # FIX: pehle yahan log.info use hota tha, aur logging_config ka masker link ka token
        # "token=[REDACTED]" bana deta tha, isliye terminal wala link hamesha "expire/ghalat" aata tha.
        # Ab link seedha terminal par (bina masking ke) print hota hai. Ye sirf console/dev backend mein hai.
        print(f"\n===== [DEV EMAIL] =====\nTo: {to}\nSubject: {subject}\n\n{body}\n=======================\n",
              file=sys.stdout, flush=True)
        log.info("[DEV EMAIL] email console par print ho gayi (subject=%s)", subject)
        return True
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = s.smtp_from, to, subject
    msg.set_content(body)
    for attempt in range(3):
        try:
            with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=10) as smtp:
                smtp.starttls()
                if s.smtp_user:
                    smtp.login(s.smtp_user, s.smtp_password)
                smtp.send_message(msg)
            return True
        except (smtplib.SMTPException, OSError) as exc:
            log.warning("SMTP fail (attempt %d): %s", attempt + 1, type(exc).__name__)
            time.sleep(0.5 * 2**attempt)
    log.error("Email bhej nahi saka (subject=%s)", subject)  # address/token log nahi
    return False


def send_email(to: str, subject: str, body: str) -> None:
    send_email_checked(to, subject, body)


def safe_send(to: str, subject: str, body: str) -> None:
    """BackgroundTasks ke liye: koi exception kabhi bahar nahi jati."""
    try:
        send_email(to, subject, body)
    except Exception:
        log.exception("Email task crash")
