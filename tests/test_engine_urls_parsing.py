import email.message

from engine.brands import display_name_brand, lookalike_brand
from engine.heuristics import parse_auth_results
from engine.parsing import build_content, from_raw_email, parse_html
from engine.urls import defang, extract_urls, parse_url, registrable_domain

TRUSTED = frozenset({"mx.google.com"})


def test_extract_urls_strips_punctuation_and_dedupes():
    urls = extract_urls("see www.example.com/a, https://x.y/z). and https://x.y/z again")
    assert urls == ["www.example.com/a", "https://x.y/z"]


def test_parse_url_tricks():
    assert parse_url("http://3232235777/x").is_ip
    assert parse_url("http://0xC0A80001/x").is_ip
    assert parse_url("http://192.168.1.1/x").is_ip
    assert parse_url("http://paypal.com@evil.com/x").has_userinfo
    assert parse_url("http://paypal.com@evil.com/x").host == "evil.com"
    assert parse_url("http://xn--pypal-4ve.com/").is_punycode
    assert parse_url("http://bit.ly/abc").is_shortener


def test_parse_url_rejects_garbage_without_crashing():
    for bad in ["ftp://x.com", "javascript:alert(1)", "http://", "http://[::1", "", "mailto:a@b.c"]:
        assert parse_url(bad) is None


def test_registrable_domain():
    assert registrable_domain("a.b.fbr.gov.pk") == "fbr.gov.pk"
    assert registrable_domain("login.evil.co.uk") == "evil.co.uk"
    assert registrable_domain("www.example.com") == "example.com"


def test_defang():
    assert defang("https://evil.com/a") == "hxxps://evil[.]com/a"


def test_lookalike_brand():
    assert lookalike_brand("paypal-secure-login.xyz", "paypal-secure-login.xyz") == "paypal"
    assert lookalike_brand("paypa1.com", "paypa1.com") == "paypal"  # leet
    assert lookalike_brand("support.paypal.com", "paypal.com") is None
    assert lookalike_brand("hbl.com", "hbl.com") is None
    assert lookalike_brand("publish.com", "publish.com") is None  # chhota token substring nahi
    assert lookalike_brand("easypaisa-verify.top", "easypaisa-verify.top") == "easypaisa"


def test_display_name_brand():
    assert display_name_brand("PayPal Security", "evil.xyz") == "paypal"
    assert display_name_brand("PayPal", "paypal.com") is None


def test_auth_results_only_from_trusted_server():
    forged = [("Authentication-Results", "evil.example; spf=pass; dkim=pass; dmarc=pass")]
    assert parse_auth_results(forged, TRUSTED) == {}
    real = [("Authentication-Results", "mx.google.com; dkim=pass; spf=softfail; dmarc=fail")]
    assert parse_auth_results(real, TRUSTED) == {"dkim": "pass", "spf": "softfail", "dmarc": "fail"}


def test_auth_results_topmost_trusted_wins():
    hdrs = [("Authentication-Results", "mx.google.com; dmarc=fail"),
            ("Authentication-Results", "mx.google.com; dmarc=pass")]
    assert parse_auth_results(hdrs, TRUSTED)["dmarc"] == "fail"


def _raw_email() -> bytes:
    m = email.message.EmailMessage()
    m["From"] = "PayPal Security <Service@Evil.xyz>"
    m["Reply-To"] = "other@else.com"
    m["Subject"] = "Verify now"
    m["Authentication-Results"] = "mx.google.com; dmarc=fail"
    m.set_content("plain body http://evil.xyz/a")
    m.add_alternative('<p>hi</p><script>var x="http://hidden.xyz"</script>'
                      '<a href="http://evil.xyz/b">https://paypal.com/login</a>', subtype="html")
    m.add_attachment(b"MZ", maintype="application", subtype="octet-stream",
                     filename="Invoice.pdf.exe")
    return m.as_bytes()


def test_from_raw_email_extracts_everything():
    e = from_raw_email(_raw_email())
    assert e.sender_email == "service@evil.xyz" and e.sender_name == "PayPal Security"
    assert e.reply_to == "other@else.com"
    assert "plain body" in e.text_body and "<a href" in e.html_body
    assert e.attachments == ["Invoice.pdf.exe"]
    assert e.headers[0][0] == "From"


def test_from_raw_email_survives_garbage():
    for raw in [b"", b"\x00\xff\xfe garbage", b"From: \xff\xfe\nSubject: \x80\n\nbody", b"A" * 100_000]:
        from_raw_email(raw)  # exception nahi aani chahiye


def test_html_parsing_ignores_scripts_and_finds_anchors():
    text, links = parse_html('<p>hi</p><script>evil()</script><a href="http://a.com/x">click a.com</a>')
    assert "evil" not in text and links == [("http://a.com/x", "click a.com")]


def test_html_parser_survives_broken_html():
    parse_html("<a href=<<<>>>><<div<<<//>>" * 1000)


def test_build_content_collects_href_and_text_urls():
    e = from_raw_email(_raw_email())
    c = build_content(e)
    assert "http://evil.xyz/b" in c.urls and "http://evil.xyz/a" in c.urls
    assert "hidden.xyz" not in " ".join(c.urls)  # script ke andar wala URL nahi
