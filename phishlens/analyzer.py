"""Orchestrates every analysis module into a single AnalysisResult."""

from __future__ import annotations

from pathlib import Path

from phishlens.attachments import analyze_attachments, build_info
from phishlens.content import analyze_content
from phishlens.headers import analyze_headers
from phishlens.intel import IntelClient
from phishlens.models import AnalysisResult, Finding, Severity
from phishlens.parser import parse_eml
from phishlens.scoring import score_findings
from phishlens.urls import analyze_sender_domain, analyze_urls, extract_urls


def analyze_bytes(data: bytes, filename: str = "message.eml",
                  intel: IntelClient | None = None) -> AnalysisResult:
    """Run the full pipeline: parse -> extract IOCs -> enrich -> heuristics -> score."""
    parsed = parse_eml(data)
    header_info, findings = analyze_headers(parsed.message)

    urls, forms = extract_urls(parsed.text_body, parsed.html_body)
    attachment_infos = [build_info(a) for a in parsed.attachments]

    # Enrich first so reputation hits are turned into findings by the heuristics.
    ip_rep: dict = {}
    intel_enabled = bool(intel and intel.enabled)
    if intel_enabled:
        ip_rep = intel.enrich(urls, attachment_infos, header_info.originating_ip)

    attachments, att_findings = analyze_attachments(parsed.attachments, attachment_infos)
    findings += att_findings
    findings += analyze_sender_domain(header_info.from_domain, header_info.from_display)
    findings += analyze_urls(urls, forms, header_info.from_domain)
    preview, content_findings = analyze_content(parsed.text_body, parsed.html_body)
    findings += content_findings

    if ip_rep.get("malicious"):
        findings.append(Finding("intel", "Originating IP has bad reputation", Severity.HIGH,
                                f"{header_info.originating_ip} - {ip_rep.get('summary')}"))

    score, verdict = score_findings(findings)
    findings.sort(key=lambda f: f.weight, reverse=True)

    return AnalysisResult(
        filename=filename,
        headers=header_info,
        urls=urls,
        attachments=attachments,
        findings=findings,
        score=score,
        verdict=verdict,
        body_preview=preview,
        intel_enabled=intel_enabled,
    )


def analyze_file(path: str | Path, intel: IntelClient | None = None) -> AnalysisResult:
    p = Path(path)
    return analyze_bytes(p.read_bytes(), p.name, intel)
