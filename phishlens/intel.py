"""Optional threat-intelligence enrichment.

Every provider is opt-in: it only runs when its API key is present in the
environment. Network errors never break the analysis - they are recorded in
the reputation dict instead.

    VT_API_KEY         VirusTotal v3   (files, URLs)
    ABUSEIPDB_API_KEY  AbuseIPDB v2    (originating IP)
    URLHAUS_API_KEY    abuse.ch URLhaus (URLs)
"""

from __future__ import annotations

import base64
import os
from typing import Any

import requests

from phishlens.models import AttachmentInfo, UrlInfo

TIMEOUT = 10
MAX_URL_LOOKUPS = 10  # protect free-tier API quotas


class IntelClient:
    def __init__(self, session: requests.Session | None = None) -> None:
        self.vt_key = os.getenv("VT_API_KEY")
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY")
        self.urlhaus_key = os.getenv("URLHAUS_API_KEY")
        self.http = session or requests.Session()
        self.http.headers["User-Agent"] = "PhishLens/1.0"

    @property
    def enabled(self) -> bool:
        return any((self.vt_key, self.abuse_key, self.urlhaus_key))

    # ------------------------------------------------------------------ files
    def check_hash(self, sha256: str) -> dict[str, Any]:
        if not self.vt_key:
            return {}
        try:
            r = self.http.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                              headers={"x-apikey": self.vt_key}, timeout=TIMEOUT)
            if r.status_code == 404:
                return {"source": "virustotal", "malicious": False, "summary": "not found in VirusTotal"}
            r.raise_for_status()
            return _vt_verdict(r.json())
        except requests.RequestException as exc:
            return {"source": "virustotal", "error": str(exc)}

    # ------------------------------------------------------------------- URLs
    def check_url(self, url: str) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if self.vt_key:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            try:
                r = self.http.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                                  headers={"x-apikey": self.vt_key}, timeout=TIMEOUT)
                if r.status_code == 200:
                    result = _vt_verdict(r.json())
                elif r.status_code == 404:
                    result = {"source": "virustotal", "malicious": False, "summary": "not found in VirusTotal"}
            except requests.RequestException as exc:
                result = {"source": "virustotal", "error": str(exc)}
        if self.urlhaus_key and not result.get("malicious"):
            try:
                r = self.http.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url},
                                   headers={"Auth-Key": self.urlhaus_key}, timeout=TIMEOUT)
                data = r.json()
                if data.get("query_status") == "ok":
                    result = {"source": "urlhaus", "malicious": True,
                              "summary": f"URLhaus: {data.get('threat', 'listed')} ({data.get('url_status')})"}
            except (requests.RequestException, ValueError) as exc:
                result.setdefault("error", str(exc))
        return result

    # --------------------------------------------------------------------- IP
    def check_ip(self, ip: str) -> dict[str, Any]:
        if not self.abuse_key:
            return {}
        try:
            r = self.http.get("https://api.abuseipdb.com/api/v2/check",
                              params={"ipAddress": ip, "maxAgeInDays": 90},
                              headers={"Key": self.abuse_key, "Accept": "application/json"},
                              timeout=TIMEOUT)
            r.raise_for_status()
            d = r.json().get("data", {})
            score = int(d.get("abuseConfidenceScore", 0))
            return {"source": "abuseipdb", "malicious": score >= 50, "abuse_score": score,
                    "country": d.get("countryCode"), "isp": d.get("isp"),
                    "summary": f"AbuseIPDB confidence {score}% ({d.get('totalReports', 0)} reports)"}
        except requests.RequestException as exc:
            return {"source": "abuseipdb", "error": str(exc)}

    # ---------------------------------------------------------------- enrich
    def enrich(self, urls: list[UrlInfo], attachments: list[AttachmentInfo],
               origin_ip: str | None) -> dict[str, Any]:
        for att in attachments:
            att.reputation = self.check_hash(att.sha256)
        for u in urls[:MAX_URL_LOOKUPS]:
            u.reputation = self.check_url(u.url)
        return self.check_ip(origin_ip) if origin_ip else {}


def _vt_verdict(payload: dict[str, Any]) -> dict[str, Any]:
    stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    mal = int(stats.get("malicious", 0))
    sus = int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) or 0
    return {"source": "virustotal", "malicious": mal >= 2, "detections": mal, "suspicious": sus,
            "engines": total, "summary": f"VirusTotal {mal}/{total} engines malicious"}
