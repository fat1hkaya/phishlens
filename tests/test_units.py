"""Unit tests for the individual heuristics."""

from __future__ import annotations

from email.message import EmailMessage

import pytest

from phishlens import analyze_bytes
from phishlens.attachments import detect_type
from phishlens.headers import org_domain
from phishlens.models import Finding, Severity, defang
from phishlens.scoring import score_findings
from phishlens.urls import extract_urls, levenshtein, lookalike_brand


@pytest.mark.parametrize(
    ("host", "brand"),
    [
        ("paypa1.com", "paypal"),
        ("micros0ft-login.com", "microsoft"),
        ("rnicrosoft.com", "microsoft"),
        ("secure-vakifbank-giris.xyz", "vakifbank"),
        ("www.paypal.com", None),
        ("login.microsoftonline.microsoft.com", None),
        ("github.com", None),
        ("example.org", None),
        # Brand-owned infrastructure must not be flagged (regression: false positives).
        ("login.microsoftonline.com", None),
        ("s3.amazonaws.com", None),
        ("lh3.googleusercontent.com", None),
        ("www.paypalobjects.com", None),
        ("outlook.office365.com", None),
        ("www.amazon.com.tr", None),
        ("www.garanti.com.tr", None),
        ("na3.docusign.net", None),
    ],
)
def test_lookalike_brand(host, brand):
    assert lookalike_brand(host) == brand


def test_levenshtein():
    assert levenshtein("paypal", "paypa1") == 1
    assert levenshtein("kitten", "sitting") == 3


def test_org_domain():
    assert org_domain("mail.vakifbank.com.tr") == "vakifbank.com.tr"
    assert org_domain("a.b.example.com") == "example.com"


def test_defang():
    assert defang("https://evil.com/x") == "hxxps[://]evil[.]com/x"


def test_extract_urls_html_and_text():
    urls, forms = extract_urls(
        "see https://a.example/x.",
        '<a href="https://b.example/">Click</a><form action="https://c.example/p"></form>',
    )
    found = {u.url for u in urls}
    assert {"https://a.example/x", "https://b.example/"} <= found
    assert forms == ["https://c.example/p"]


def test_detect_type():
    assert detect_type(b"%PDF-1.7") == "pdf"
    assert detect_type(b"MZ\x90\x00") == "pe-executable"
    assert detect_type(b"<html><body>") == "html/script"
    assert detect_type(b"hello") is None


def test_scoring_dedupes_and_caps():
    f = [Finding("urls", "URL shortener hides destination", Severity.MEDIUM)] * 10
    score, verdict = score_findings(f)
    assert score == 12 and verdict == "LIKELY SAFE"
    many = [Finding("m", str(i), Severity.CRITICAL) for i in range(5)]
    assert score_findings(many) == (100, "MALICIOUS")


def test_single_critical_is_at_least_suspicious():
    _, verdict = score_findings([Finding("attachments", "Executable attachment (.exe)", Severity.CRITICAL)])
    assert verdict == "SUSPICIOUS"


def _msg(**headers) -> EmailMessage:
    m = EmailMessage()
    m["From"] = headers.pop("From", "Alice <alice@example.com>")
    m["To"] = "bob@example.com"
    m["Subject"] = headers.pop("Subject", "hello")
    m["Message-ID"] = "<1@example.com>"
    for k, v in headers.items():
        m[k.replace("_", "-")] = v
    m.set_content(headers.get("body", "Hi Bob, see you tomorrow."))
    return m


def test_rtlo_filename():
    m = _msg()
    m.add_attachment(b"data", maintype="application", subtype="octet-stream",
                     filename="invoice‮fdp.exe")
    titles = {f.title for f in analyze_bytes(bytes(m)).findings}
    assert "Right-to-left override character in filename" in titles


def test_html_attachment():
    m = _msg()
    m.add_attachment(b"<html><script>location='x'</script></html>", maintype="text",
                     subtype="html", filename="Statement.html")
    titles = {f.title for f in analyze_bytes(bytes(m)).findings}
    assert any(t.startswith("HTML/SVG attachment") for t in titles)


def test_free_mail_authority_display():
    m = _msg(From='"IT Helpdesk" <it.helpdesk.team@gmail.com>')
    titles = {f.title for f in analyze_bytes(bytes(m)).findings}
    assert "Authority display name from free mail provider" in titles


def test_plain_mail_is_clean():
    r = analyze_bytes(bytes(_msg(Authentication_Results="mx; spf=pass; dkim=pass; dmarc=pass")))
    assert r.verdict == "LIKELY SAFE"
    assert r.score == 0


def test_malformed_input_does_not_crash():
    r = analyze_bytes(b"\x00\xff garbage without headers <a href=")
    assert r.verdict in {"LIKELY SAFE", "SUSPICIOUS", "MALICIOUS"}
