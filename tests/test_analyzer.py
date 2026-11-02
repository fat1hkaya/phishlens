"""End-to-end tests against the bundled synthetic samples."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from phishlens import analyze_file
from phishlens.cli import main
from phishlens.report import to_html, to_json, to_markdown

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def titles(result) -> set[str]:
    return {f.title for f in result.findings}


@pytest.mark.parametrize(
    ("sample", "verdict"),
    [
        ("01_legit_newsletter.eml", "LIKELY SAFE"),
        ("02_credential_harvest.eml", "MALICIOUS"),
        ("03_malicious_attachment.eml", "MALICIOUS"),
        ("04_bec_ceo_fraud.eml", "SUSPICIOUS"),
        ("05_tr_edevlet_lure.eml", "MALICIOUS"),
    ],
)
def test_sample_verdicts(sample, verdict):
    assert analyze_file(SAMPLES / sample).verdict == verdict


def test_legit_has_no_findings():
    r = analyze_file(SAMPLES / "01_legit_newsletter.eml")
    assert r.score == 0
    assert (r.headers.spf, r.headers.dkim, r.headers.dmarc) == ("pass", "pass", "pass")
    assert r.headers.originating_ip == "192.30.252.201"


def test_credential_harvest_indicators():
    r = analyze_file(SAMPLES / "02_credential_harvest.eml")
    t = titles(r)
    assert "DMARC fail" in t
    assert "Link text/destination mismatch" in t
    assert "Lookalike domain impersonating 'paypal'" in t
    assert "Sender domain impersonates 'paypal'" in t
    assert "HTML form embedded in e-mail" in t
    assert "Reply-To domain differs from From" in t
    assert r.headers.originating_ip == "203.0.113.45"
    assert "T1566.002" in r.mitre_techniques


def test_attachment_indicators_and_hashes():
    r = analyze_file(SAMPLES / "03_malicious_attachment.eml")
    t = titles(r)
    assert "Executable attachment (.exe)" in t
    assert "Double extension disguises file type" in t
    assert "Archive contains executable/script files" in t
    assert "Macro-enabled Office document (.xlsm)" in t
    exe = next(a for a in r.attachments if a.filename.endswith(".exe"))
    assert exe.detected_type == "pe-executable"
    assert len(exe.sha256) == 64 and len(exe.md5) == 32


def test_bec_display_name_spoof():
    r = analyze_file(SAMPLES / "04_bec_ceo_fraud.eml")
    assert "Display name spoofing" in titles(r)
    assert "Business e-mail compromise phrasing" in titles(r)


def test_turkish_lure():
    r = analyze_file(SAMPLES / "05_tr_edevlet_lure.eml")
    t = titles(r)
    assert "Punycode (IDN homograph) domain" in t
    assert "URL shortener hides destination" in t
    assert "Sender domain impersonates 'edevlet'" in t
    assert "Credential request" in t


@pytest.mark.parametrize("renderer", [to_json, to_markdown, to_html])
def test_renderers(renderer):
    r = analyze_file(SAMPLES / "02_credential_harvest.eml")
    out = renderer(r)
    assert "MALICIOUS" in out
    # IOCs must always be defanged in reports.
    assert "hxxp[://]paypa1-security[.]com" in out or renderer is to_html


def test_json_is_valid():
    data = json.loads(to_json(analyze_file(SAMPLES / "03_malicious_attachment.eml")))
    assert data["verdict"] == "MALICIOUS"
    assert len(data["attachments"]) == 3


def test_cli_exit_codes(tmp_path, capsys):
    assert main(["analyze", str(SAMPLES / "01_legit_newsletter.eml"), "--no-color"]) == 0
    assert main(["analyze", str(SAMPLES / "04_bec_ceo_fraud.eml"), "--no-color"]) == 1
    assert main(["analyze", str(SAMPLES / "02_credential_harvest.eml"), "--no-color"]) == 2
    out = tmp_path / "reports"
    assert main(["analyze", *map(str, sorted(SAMPLES.glob("*.eml"))), "-f", "html", "-o", str(out)]) == 2
    assert len(list(out.glob("*.html"))) == 5
