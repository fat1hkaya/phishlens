"""Body content heuristics: social-engineering language (EN + TR)."""

from __future__ import annotations

import re
from html import unescape

from phishlens.models import Finding, Severity

MODULE = "content"

PATTERNS: list[tuple[str, Severity, re.Pattern[str]]] = [
    ("Credential request", Severity.HIGH, re.compile(
        r"(verify|confirm|update|validate|re-?enter)\s+(your\s+)?(account|password|credentials|login|identity|payment)"
        r"|(hesab[ıi]n[ıi]z[ıi]?|şifreniz[ie]?|kimli[ğg]inizi)\s+(doğrula|güncelle|onayla)", re.I)),
    ("Urgency / threat language", Severity.MEDIUM, re.compile(
        r"(within\s+\d+\s+(hours?|days?)|immediately|account\s+(will\s+be\s+)?(suspended|locked|closed|terminated)"
        r"|final\s+(notice|warning)|unusual\s+(sign-?in|activity)|24\s+saat\s+içinde|hesabınız\s+askıya"
        r"|derhal|son\s+uyarı|kapatılacaktır)", re.I)),
    ("Financial lure", Severity.MEDIUM, re.compile(
        r"(wire\s+transfer|gift\s+cards?|bank\s+details|outstanding\s+invoice|refund|payment\s+(failed|declined)"
        r"|iade|havale|ödenmemiş\s+fatura|ödemeniz\s+(başarısız|reddedildi))", re.I)),
    ("Business e-mail compromise phrasing", Severity.MEDIUM, re.compile(
        r"(are\s+you\s+(available|at\s+your\s+desk)|i\s+need\s+(a\s+)?(quick\s+)?favou?r|keep\s+this\s+confidential"
        r"|müsait\s+misiniz|gizli\s+tutun)", re.I)),
    ("Generic greeting", Severity.LOW, re.compile(
        r"^\s*(dear\s+(customer|user|client|member|valued\s+customer|account\s+holder)|sayın\s+(müşterimiz|kullanıcı))",
        re.I | re.M)),
]

_TAG_RE = re.compile(r"<[^>]+>")
_STYLE_RE = re.compile(r"<(style|script)[^>]*>.*?</\1>", re.I | re.S)


def html_to_text(html: str) -> str:
    return " ".join(unescape(_TAG_RE.sub(" ", _STYLE_RE.sub(" ", html))).split())


def analyze_content(text_body: str, html_body: str) -> tuple[str, list[Finding]]:
    plain = text_body.strip() or html_to_text(html_body)
    findings: list[Finding] = []
    for title, sev, rx in PATTERNS:
        m = rx.search(plain) or (rx.search(html_to_text(html_body)) if html_body else None)
        if m:
            findings.append(Finding(MODULE, title, sev, f"...{m.group(0).strip()}...", "T1566"))

    if html_body and re.search(r"(display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*#?fff(fff)?\b)", html_body, re.I):
        findings.append(Finding(MODULE, "Hidden text in HTML body", Severity.LOW,
                                "Invisible text is often used to evade content filters.", "T1027"))

    preview = plain[:400] + ("..." if len(plain) > 400 else "")
    return preview, findings
