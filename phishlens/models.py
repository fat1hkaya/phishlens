"""Data models shared by every analysis module."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Points each severity adds to the risk score.
SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 12,
    Severity.HIGH: 25,
    Severity.CRITICAL: 40,
}


@dataclass
class Finding:
    """A single observation produced by an analysis module."""

    module: str
    title: str
    severity: Severity
    detail: str = ""
    mitre: str | None = None

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHT[self.severity]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["weight"] = self.weight
        return data


@dataclass
class UrlInfo:
    url: str
    domain: str
    source: str  # "text", "html", "html-anchor"
    display_text: str | None = None
    reputation: dict[str, Any] = field(default_factory=dict)

    @property
    def defanged(self) -> str:
        return defang(self.url)


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size: int
    md5: str
    sha1: str
    sha256: str
    detected_type: str | None = None
    reputation: dict[str, Any] = field(default_factory=dict)


@dataclass
class HeaderInfo:
    subject: str = ""
    from_address: str = ""
    from_display: str = ""
    from_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    date: str = ""
    message_id: str = ""
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    received_hops: list[dict[str, str]] = field(default_factory=list)
    originating_ip: str | None = None
    x_mailer: str = ""


@dataclass
class AnalysisResult:
    filename: str
    headers: HeaderInfo
    urls: list[UrlInfo]
    attachments: list[AttachmentInfo]
    findings: list[Finding]
    score: int
    verdict: str
    body_preview: str = ""
    intel_enabled: bool = False

    @property
    def mitre_techniques(self) -> list[str]:
        return sorted({f.mitre for f in self.findings if f.mitre})

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "verdict": self.verdict,
            "score": self.score,
            "intel_enabled": self.intel_enabled,
            "mitre_techniques": self.mitre_techniques,
            "headers": asdict(self.headers),
            "urls": [
                {**asdict(u), "defanged": u.defanged} for u in self.urls
            ],
            "attachments": [asdict(a) for a in self.attachments],
            "findings": [f.to_dict() for f in self.findings],
            "body_preview": self.body_preview,
        }


def defang(value: str) -> str:
    """Make an IOC non-clickable: https://evil.com -> hxxps[://]evil[.]com"""
    return (
        value.replace("http://", "hxxp[://]")
        .replace("https://", "hxxps[://]")
        .replace(".", "[.]")
    )
