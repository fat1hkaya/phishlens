"""Flask app and threat-intel client (network fully mocked)."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from phishlens import analyze_file
from phishlens.intel import IntelClient
from phishlens.web.app import create_app

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


@pytest.fixture()
def client(monkeypatch):
    for k in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "URLHAUS_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_index(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"Analyze a suspicious e-mail" in r.data


def test_upload_and_report(client):
    data = (SAMPLES / "02_credential_harvest.eml").read_bytes()
    r = client.post("/analyze", data={"eml": (io.BytesIO(data), "x.eml")},
                    content_type="multipart/form-data")
    assert r.status_code == 302
    page = client.get(r.headers["Location"])
    assert page.status_code == 200 and b"MALICIOUS" in page.data
    j = client.get(r.headers["Location"] + ".json")
    assert json.loads(j.data)["verdict"] == "MALICIOUS"


def test_api(client):
    data = (SAMPLES / "04_bec_ceo_fraud.eml").read_bytes()
    r = client.post("/api/analyze", data=data)
    assert r.status_code == 200
    assert r.get_json()["verdict"] == "SUSPICIOUS"
    # curl --data-binary sends application/x-www-form-urlencoded by default
    r = client.post("/api/analyze", data=data, content_type="application/x-www-form-urlencoded")
    assert r.get_json()["verdict"] == "SUSPICIOUS"
    r = client.post("/api/analyze", data={"eml": (io.BytesIO(data), "m.eml")},
                    content_type="multipart/form-data")
    assert r.get_json()["verdict"] == "SUSPICIOUS"


def test_sample_route(client):
    r = client.get("/sample/03_malicious_attachment.eml")
    assert r.status_code == 302
    assert client.get("/sample/../../etc/passwd").status_code == 404


def test_empty_upload(client):
    r = client.post("/analyze", data={"eml": (io.BytesIO(b""), "e.eml")},
                    content_type="multipart/form-data")
    assert b"empty" in r.data


class FakeResponse:
    def __init__(self, status: int, payload: dict):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)


class FakeSession:
    def __init__(self):
        self.headers = {}

    def get(self, url, **kw):
        if "virustotal" in url:
            stats = {"malicious": 41, "suspicious": 2, "undetected": 20, "harmless": 0}
            return FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": stats}}})
        if "abuseipdb" in url:
            return FakeResponse(200, {"data": {"abuseConfidenceScore": 97, "totalReports": 311,
                                               "countryCode": "XX", "isp": "Bad VPS"}})
        return FakeResponse(404, {})

    def post(self, url, **kw):
        return FakeResponse(200, {"query_status": "no_results"})


def test_intel_enrichment(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "x")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "y")
    intel = IntelClient(session=FakeSession())
    r = analyze_file(SAMPLES / "03_malicious_attachment.eml", intel)
    assert r.intel_enabled
    assert all(a.reputation.get("malicious") for a in r.attachments)
    titles = {f.title for f in r.findings}
    assert "Threat intel: attachment hash known malicious" in titles
    assert "Originating IP has bad reputation" in titles


def test_intel_disabled_without_keys(monkeypatch):
    for k in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "URLHAUS_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    assert not IntelClient().enabled
