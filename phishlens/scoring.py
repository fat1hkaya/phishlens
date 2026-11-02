"""Turn findings into a 0-100 risk score and a triage verdict."""

from __future__ import annotations

from phishlens.models import Finding, Severity

VERDICT_MALICIOUS = "MALICIOUS"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_LIKELY_SAFE = "LIKELY SAFE"

THRESHOLD_MALICIOUS = 60
THRESHOLD_SUSPICIOUS = 25


def score_findings(findings: list[Finding]) -> tuple[int, str]:
    """Weighted sum, capped at 100.

    Each distinct (module, title) only counts once so a mail with twenty
    shortened links does not get twenty times the points. A single CRITICAL
    finding is always enough for at least a SUSPICIOUS verdict, and an
    authentication failure combined with a lookalike domain or a dangerous
    attachment is escalated to MALICIOUS.
    """
    unique: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.module, f.title)
        if key not in unique or f.weight > unique[key].weight:
            unique[key] = f

    score = min(100, sum(f.weight for f in unique.values()))
    severities = {f.severity for f in unique.values()}

    if score >= THRESHOLD_MALICIOUS:
        verdict = VERDICT_MALICIOUS
    elif score >= THRESHOLD_SUSPICIOUS or Severity.CRITICAL in severities:
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_LIKELY_SAFE

    auth_fail = any(f.module == "headers" and f.title in {"DMARC fail", "SPF fail"} for f in unique.values())
    if auth_fail and Severity.CRITICAL in severities:
        verdict = VERDICT_MALICIOUS
        score = max(score, THRESHOLD_MALICIOUS)

    return score, verdict
