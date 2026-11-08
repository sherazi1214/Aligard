"""Attachment content, QR, domain age, postmortem: engine ki nayi layers."""
from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import httpx
import pytest

from engine.analyzer import Engine
from engine.attachments import analyze_attachment, analyze_attachments, sniff
from engine.domainintel import RdapDomainIntel, evaluate_age
from engine.models import EmailInput, Verdict
from engine.parsing import from_raw_email
from engine.postmortem import build_postmortem
from engine.qr import available as qr_available
from engine.qr import decode_qr_urls


def _zip(members: dict[str, bytes], encrypted: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n, d in members.items():
            zf.writestr(zipfile.ZipInfo(n), d)
    raw = bytearray(buf.getvalue())
    if encrypted:  # zipfile flag_bits reset kar deta hai, is liye header bytes khud patch karte hain
        for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            i = raw.find(sig)
            while i != -1:
                raw[i + off] |= 0x1
                i = raw.find(sig, i + 4)
    return bytes(raw)


# ------------------------------------------------------------------ attachments
def test_disguised_exe_detected_by_magic_not_name():
    r = analyze_attachment("Invoice.pdf", b"MZ\x90\x00" + b"\x00" * 100)
    assert r.real_type == "exe" and any(s.code == "att_disguised_exe" for s in r.signals) and r.points >= 60


def test_pdf_with_js_and_link():
    pdf = b"%PDF-1.7\n1 0 obj<</JavaScript 2 0 R /OpenAction>>\n<</URI (https://evil.top/login)>>"
    r = analyze_attachment("doc.pdf", pdf)
    codes = {s.code for s in r.signals}
    assert {"att_pdf_js", "att_pdf_link"} <= codes and r.urls == ["https://evil.top/login"]


def test_plain_pdf_is_clean():
    assert analyze_attachment("a.pdf", b"%PDF-1.4\n%%EOF").points == 0


def test_office_macro_and_encrypted_zip_and_zip_exec():
    assert any(s.code == "att_macro" for s in analyze_attachment(
        "a.docm", _zip({"word/vbaProject.bin": b"x", "[Content_Types].xml": b"<x/>"})).signals)
    assert any(s.code == "att_encrypted_zip" for s in analyze_attachment("a.zip", _zip({"a.txt": b"x"}, True)).signals)
    assert any(s.code == "att_zip_exec" for s in analyze_attachment("a.zip", _zip({"run.exe": b"x"})).signals)


def test_remote_template_injection():
    rels = b'<Relationship Type="x/attachedTemplate" Target="http://evil.top/t.dotm" TargetMode="External"/>'
    r = analyze_attachment("a.docx", _zip({"word/_rels/settings.xml.rels": rels}))
    assert any(s.code == "att_remote_template" for s in r.signals) and r.urls


def test_html_attachment_login_form():
    html = b"<html><form action='https://evil.top/p'><input type='password' name=p></form></html>"
    r = analyze_attachment("Payment.html", html)
    assert r.real_type == "html" and any(s.code == "att_html_login" for s in r.signals) and r.urls


def test_garbage_and_oversize_never_crash():
    assert analyze_attachment("x.zip", b"PK\x03\x04garbage").points <= 80
    big = analyze_attachments([("big.bin", b"\0" * 5_000_001)])
    assert big[0].real_type == "too_large"
    assert sniff(b"") == "other"


# ------------------------------------------------------------------ QR
@pytest.mark.skipif(not qr_available(), reason="opencv/pillow nahi")
def test_qr_code_url_decoded():
    import qrcode
    img = qrcode.make("https://evil-login.top/verify")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    assert decode_qr_urls([("qr.png", buf.getvalue())]) == ["https://evil-login.top/verify"]


@pytest.mark.skipif(not qr_available(), reason="opencv/pillow nahi")
def test_non_url_qr_and_garbage_ignored():
    import qrcode
    buf = io.BytesIO()
    qrcode.make("hello").save(buf, format="PNG")
    assert decode_qr_urls([("a.png", buf.getvalue()), ("b.png", b"not an image")]) == []


# ------------------------------------------------------------------ domain age
def _rdap(days: int | None, status: int = 200):
    def handler(req: httpx.Request) -> httpx.Response:
        if days is None:
            return httpx.Response(status, json={})
        d = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
        return httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": d}]})
    return RdapDomainIntel(client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_domain_age_scoring():
    assert evaluate_age("a.top", 2).points == 30
    assert evaluate_age("a.top", 15).points == 20
    assert evaluate_age("a.top", 60).points == 8
    assert evaluate_age("a.com", 4000) is None and evaluate_age("a.com", None) is None


def test_rdap_lookup_validates_and_caches():
    intel = _rdap(3)
    assert intel.lookup("evil-login.top").age_days == 3
    assert intel.lookup("../etc/passwd").error == "invalid_domain"
    assert intel.lookup("1.2.3.4").error == "invalid_domain"
    assert _rdap(None, 404).lookup("x.example").error == "rdap_http_404"


# ------------------------------------------------------------------ postmortem + engine
def test_postmortem_is_defanged_and_has_no_raw_urls():
    pm = build_postmortem(
        [{"url": "https://bit.ly/x", "final_url": "https://evil.top/login", "redirect_chain": ["https://bit.ly/x"],
          "forms": [{"action": "https://c.evil.top/p", "has_password": True}], "signals": [{"text": "t"}]}],
        [{"name": "a.pdf", "urls": ["https://evil.top/a"]}], [{"domain": "evil.top", "age_days": 2}],
        ["https://qr.evil.top/x"])
    blob = json.dumps(pm)
    assert "https://" not in blob and "http://" not in blob and "hxxps://evil[.]top/login" in blob


def _mail_with(parts: list[tuple[str, str, bytes]], body: str, sender="PayPal <a@paypa1-secure.top>") -> bytes:
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = sender, "me@gmail.com", "Urgent: verify your account now"
    m.set_content(body)
    for name, mime, data in parts:
        main, sub = mime.split("/")
        m.add_attachment(data, maintype=main, subtype=sub, filename=name)
    return m.as_bytes()


def test_raw_email_attachment_bytes_reach_engine_and_flag():
    raw = _mail_with([("Invoice.pdf", "application/pdf", b"MZ\x90" + b"\0" * 64)], "See attached invoice.")
    email = from_raw_email(raw)
    assert email.attachment_files and email.attachment_files[0][0] == "Invoice.pdf"
    r = Engine(model=None).analyze(email)
    assert r.verdict is Verdict.PHISHING and r.layer_scores["attachments"] >= 60
    assert r.postmortem["attachments"][0]["real_type"] == "exe"


@pytest.mark.skipif(not qr_available(), reason="opencv/pillow nahi")
def test_qr_only_mail_gets_flagged_and_link_enters_url_list():
    import qrcode
    buf = io.BytesIO()
    qrcode.make("https://secure-paypa1-login.top/verify").save(buf, format="PNG")
    raw = _mail_with([("scan-me.png", "image/png", buf.getvalue())], "Scan the code to restore access immediately.")
    r = Engine(model=None).analyze(from_raw_email(raw))
    assert r.postmortem["qr_links"] and any("secure-paypa1-login" in u for u in r.urls)
    assert any(s.code == "qr_link" for s in r.signals)


def test_domain_intel_adds_signal_only_when_suspicious_mail():
    mail = EmailInput(subject="Urgent: verify your PayPal account", sender_name="PayPal",
                      sender_email="a@paypa1-secure.top",
                      text_body="Verify now: https://paypa1-secure.top/login")
    r = Engine(model=None, domain_intel=_rdap(2)).analyze(mail)
    assert r.layer_scores["domain"] == 30 and r.postmortem["domains"][0]["age_days"] == 2
    clean = EmailInput(subject="Lunch", sender_email="s@example.org", text_body="menu https://example.org/m")
    assert Engine(model=None, domain_intel=_rdap(2)).analyze(clean).postmortem["domains"] == []


def test_result_to_dict_is_json_safe_with_new_layers():
    raw = _mail_with([("a.pdf", "application/pdf", b"%PDF-1.4 /JavaScript")], "hi")
    json.dumps(Engine(model=None).analyze(from_raw_email(raw)).to_dict())
