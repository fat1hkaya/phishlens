"""Report renderers: JSON, Markdown and standalone HTML."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from phishlens import __version__
from phishlens.models import AnalysisResult

TEMPLATE_DIR = Path(__file__).parent / "web" / "templates"

_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)

MITRE_NAMES = {
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1656": "Impersonation",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1204.001": "User Execution: Malicious Link",
    "T1204.002": "User Execution: Malicious File",
    "T1036.002": "Masquerading: Right-to-Left Override",
    "T1036.007": "Masquerading: Double File Extension",
    "T1036.008": "Masquerading: Masquerade File Type",
    "T1027": "Obfuscated Files or Information",
}

RECOMMENDATIONS = {
    "MALICIOUS": [
        "Block sender address/domain and listed IOCs on the mail gateway, proxy and EDR.",
        "Search the mailbox estate for the same Message-ID, subject or sender and purge copies.",
        "Identify recipients who clicked links or opened attachments; reset credentials and isolate hosts if needed.",
        "Open an incident ticket and attach this report as evidence.",
    ],
    "SUSPICIOUS": [
        "Escalate to L2 for manual review before releasing the message.",
        "Detonate attachments / URLs in a sandbox (e.g. ANY.RUN, Joe Sandbox, urlscan.io).",
        "Contact the purported sender through a known-good channel to verify.",
    ],
    "LIKELY SAFE": [
        "No strong phishing indicators found - close as false positive if the user report has no additional context.",
        "Keep the report for the audit trail.",
    ],
}


def to_json(result: AnalysisResult) -> str:
    data = result.to_dict()
    data["generated_at"] = _now()
    data["tool"] = f"PhishLens {__version__}"
    return json.dumps(data, indent=2, ensure_ascii=False)


def _context(result: AnalysisResult) -> dict:
    return {
        "r": result,
        "generated_at": _now(),
        "version": __version__,
        "mitre_names": MITRE_NAMES,
        "recommendations": RECOMMENDATIONS[result.verdict],
    }


def to_markdown(result: AnalysisResult) -> str:
    return _env.get_template("report.md.j2").render(**_context(result))


def to_html(result: AnalysisResult) -> str:
    return _env.get_template("report.html").render(**_context(result), standalone=True)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


RENDERERS = {"json": to_json, "md": to_markdown, "markdown": to_markdown, "html": to_html}
