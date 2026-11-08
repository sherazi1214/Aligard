"""Haath se likhe hue evaluation emails (training templates se alag). Chhota set hai (18),
isliye is par accuracy sirf 'sanity check' hai, asli duniya ki accuracy nahi."""
from __future__ import annotations

from engine.models import EmailInput

_OK = [("Authentication-Results", "mx.google.com; dkim=pass header.i=@{d}; spf=pass; dmarc=pass")]
_BAD = [("Authentication-Results", "mx.google.com; dkim=fail; spf=softfail; dmarc=fail")]


def _ok(d: str) -> list[tuple[str, str]]:
    return [(k, v.format(d=d)) for k, v in _OK]


# (label 1=phishing, 0=legit, naam, EmailInput)
SAMPLES: list[tuple[int, str, EmailInput]] = [
    # ---------------- phishing
    (1, "paypal lookalike", EmailInput(
        subject="Your PayPal account has been limited", sender_name="PayPal Security",
        sender_email="service@paypal-secure-login.xyz", headers=_BAD,
        text_body="We noticed unusual activity. Verify your account immediately or it will be "
                  "suspended: http://paypal-secure-login.xyz/verify?id=88213")),
    (1, "microsoft anchor mismatch", EmailInput(
        subject="Password expires in 24 hours", sender_name="IT Support",
        sender_email="helpdesk@mail-office-support.top", headers=_BAD,
        html_body='<p>Your password expires today.</p><a href="http://bit.ly/3xYzAb">'
                  "https://office.com/password</a>")),
    (1, "easypaisa roman urdu", EmailInput(
        subject="Aapka Easypaisa account block", sender_name="Easypaisa",
        sender_email="easypaisa.support.pk@gmail.com",
        text_body="Aapka Easypaisa account block ho gaya hai. Turant verify karein warna 24 ghante "
                  "mein band ho jayega. Apna PIN dein: http://easypaisa-verify.top/login")),
    (1, "bisp 8171 ip link", EmailInput(
        subject="BISP Ehsaas inam", sender_email="info@bisp-ehsaas-claim.click",
        text_body="Mubarak ho! Aap ka Ehsaas 8171 mein Rs 25,000 ka inam nikla hai. CNIC aur PIN "
                  "bhejein: http://45.33.12.9/bisp/claim")),
    (1, "fbr refund", EmailInput(
        subject="FBR tax refund approved", sender_name="FBR Pakistan",
        sender_email="refund@fbr-gov-pk.click", headers=_BAD,
        text_body="You are eligible for a tax refund. Submit your CNIC and card number within 24 "
                  "hours: https://fbr-gov-pk.click/refund")),
    (1, "parcel shortener", EmailInput(
        subject="Parcel on hold", sender_email="noreply@track-parcel-pk.icu", headers=_BAD,
        text_body="Your parcel could not be delivered. Pay Rs 150 customs fee: "
                  "https://tinyurl.com/abc1234")),
    (1, "exe invoice", EmailInput(
        subject="Invoice 4471", sender_email="accounts@vendor-billing.xyz", headers=_BAD,
        text_body="Please see attached invoice and confirm payment today.",
        attachments=["Invoice_4471.pdf.exe"])),
    (1, "hbl urdu script", EmailInput(
        subject="اکاؤنٹ بلاک", sender_name="HBL", sender_email="alert@hbl-secure.icu",
        text_body="آپ کا ایچ بی ایل اکاؤنٹ بلاک ہو گیا ہے۔ فوری تصدیق کریں اور پاس ورڈ درج کریں: "
                  "http://hbl-secure.icu/login")),
    # ---------------- legit (kuch hard negatives)
    (0, "medium digest", EmailInput(
        subject="Your weekly Medium digest", sender_name="Medium Daily Digest",
        sender_email="noreply@medium.com", headers=_ok("medium.com"),
        html_body='<p>Top stories for you</p><a href="https://medium.com/@writer/story-1">Read</a>'
                  '<a href="https://medium.com/@writer/story-2">Read</a>')),
    (0, "amazon order", EmailInput(
        subject="Your Amazon.com order has shipped", sender_name="Amazon.com",
        sender_email="shipment-tracking@amazon.com", headers=_ok("amazon.com"),
        text_body="Your package will arrive Thursday. Track it: https://www.amazon.com/gp/css/"
                  "order-details?orderId=123")),
    (0, "colleague meeting", EmailInput(
        subject="Meeting kal 3 baje", sender_name="Hina", sender_email="hina.tariq@gmail.com",
        text_body="Assalam o alaikum, kal 3 baje project meeting hai conference room mein. "
                  "Apne updates le aana.")),
    (0, "hbl otp", EmailInput(
        subject="Your HBL one-time password", sender_name="HBL Alerts", sender_email="alerts@hbl.com",
        headers=_ok("hbl.com"),
        text_body="Your OTP is 482913 for your transaction. Do not share it with anyone. HBL will "
                  "never ask for your OTP.")),
    (0, "github notification", EmailInput(
        subject="[repo] Pull request merged", sender_name="GitHub", sender_email="noreply@github.com",
        headers=_ok("github.com"),
        text_body="Your pull request was merged. View it: https://github.com/org/repo/pull/12")),
    (0, "meezan e-statement", EmailInput(
        subject="Your e-statement is ready", sender_name="Meezan Bank",
        sender_email="statements@meezanbank.com", headers=_ok("meezanbank.com"),
        text_body="Your September e-statement is available. Log in to the Meezan mobile app to "
                  "view it. https://www.meezanbank.com/")),
    (0, "daraz promo (hard)", EmailInput(
        subject="Limited time offer: claim your voucher", sender_name="Daraz",
        sender_email="newsletter@daraz.pk", headers=_ok("daraz.pk"),
        text_body="Limited time offer! Claim your 20% discount voucher and shop now: "
                  "https://www.daraz.pk/sale")),
    (0, "google password reset (hard)", EmailInput(
        subject="Reset your password", sender_name="Google",
        sender_email="no-reply@accounts.google.com", headers=_ok("accounts.google.com"),
        text_body="Someone requested a password reset. If it was you, reset it here: "
                  "https://accounts.google.com/signin/recovery. If not, ignore this email.")),
    (0, "family roman urdu", EmailInput(
        subject="Kal ka plan", sender_email="bilal.khan@gmail.com",
        text_body="Yaar kal shaam cricket khelne chalte hain? Sab ko bata do.")),
    (0, "k-electric bill", EmailInput(
        subject="Electricity bill reminder", sender_name="K-Electric", sender_email="bills@ke.com.pk",
        headers=_ok("ke.com.pk"),
        text_body="Your bill of Rs 8,400 is due on 25 October. Pay online: https://www.ke.com.pk/pay")),
]
