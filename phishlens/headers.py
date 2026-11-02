"""Header analysis: authentication results, sender spoofing, relay path."""

from __future__ import annotations

import ipaddress
import re
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr

from phishlens.models import Finding, HeaderInfo, Severity

MODULE = "headers"

_AUTH_RE = {
    "spf": re.compile(r"\bspf=(\w+)", re.I),
    "dkim": re.compile(r"\bdkim=(\w+)", re.I),
    "dmarc": re.compile(r"\bdmarc=(\w+)", re.I),
}
_RECEIVED_SPF_RE = re.compile(r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)", re.I)
_IP_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")
_FROM_RE = re.compile(r"from\s+(\S+)", re.I)
_BY_RE = re.compile(r"by\s+(\S+)", re.I)

# Words commonly abused in display names to impersonate trusted senders.
_TRUSTED_DISPLAY_WORDS = (
    "support", "security", "admin", "it department", "helpdesk", "help desk",
    "billing", "payroll", "hr", "bank", "account", "service", "team", "no-reply",
)

_URGENCY_SUBJECT = re.compile(
    r"\b(urgent|immediate|action required|verify|suspend|suspended|locked|"
    r"unusual|password|expire|expires|invoice|payment|refund|acil|doğrula|"
    r"askıya|şifre|fatura|ödeme)\b",
    re.I,
)


def domain_of(address: str) -> str:
    _, addr = parseaddr(address or "")
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


def org_domain(domain: str) -> str:
    """Naive registrable domain (last two labels, or three for e.g. co.uk / com.tr)."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "edu", "ac"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _auth_results(msg: EmailMessage) -> dict[str, str]:
    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    for header in msg.get_all("Authentication-Results", []) or []:
        for key, rx in _AUTH_RE.items():
            match = rx.search(str(header))
            if match and results[key] == "none":
                results[key] = match.group(1).lower()
    if results["spf"] == "none":
        rspf = msg.get("Received-SPF")
        if rspf:
            m = _RECEIVED_SPF_RE.match(str(rspf))
            if m:
                results["spf"] = m.group(1).lower()
    return results


def _parse_received(msg: EmailMessage) -> tuple[list[dict[str, str]], str | None]:
    hops: list[dict[str, str]] = []
    # Received headers are prepended; reverse so hop 1 is the origin.
    received = list(reversed(msg.get_all("Received", []) or []))
    origin_ip: str | None = None
    for idx, raw in enumerate(received, start=1):
        text = " ".join(str(raw).split())
        frm = _FROM_RE.search(text)
        by = _BY_RE.search(text)
        ips = [ip for ip in _IP_RE.findall(text) if _valid_ip(ip)]
        public = [ip for ip in ips if not _is_internal(ip)]
        if origin_ip is None and public:
            origin_ip = public[0]
        hops.append(
            {
                "hop": str(idx),
                "from": frm.group(1) if frm else "",
                "by": by.group(1) if by else "",
                "ip": ips[0] if ips else "",
                "date": text.rsplit(";", 1)[-1].strip() if ";" in text else "",
            }
        )
    return hops, origin_ip


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10")]


def _is_internal(ip: str) -> bool:
    """RFC1918 / loopback / link-local / CGNAT - hops that never identify the true sender."""
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in _INTERNAL_NETS)


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def analyze_headers(msg: EmailMessage) -> tuple[HeaderInfo, list[Finding]]:
    findings: list[Finding] = []

    display, from_addr = parseaddr(str(msg.get("From", "")))
    from_domain = domain_of(from_addr)
    reply_to = str(msg.get("Reply-To", "") or "")
    return_path = str(msg.get("Return-Path", "") or "")
    auth = _auth_results(msg)
    hops, origin_ip = _parse_received(msg)

    info = HeaderInfo(
        subject=str(msg.get("Subject", "") or ""),
        from_address=from_addr,
        from_display=display,
        from_domain=from_domain,
        reply_to=reply_to,
        return_path=return_path,
        to=", ".join(a for _, a in getaddresses(msg.get_all("To", []) or [])),
        date=str(msg.get("Date", "") or ""),
        message_id=str(msg.get("Message-ID", "") or ""),
        spf=auth["spf"],
        dkim=auth["dkim"],
        dmarc=auth["dmarc"],
        received_hops=hops,
        originating_ip=origin_ip,
        x_mailer=str(msg.get("X-Mailer", "") or ""),
    )

    # --- Authentication -------------------------------------------------
    if auth["spf"] in {"fail", "softfail"}:
        findings.append(Finding(MODULE, f"SPF {auth['spf']}",
                                Severity.HIGH if auth["spf"] == "fail" else Severity.MEDIUM,
                                "Sending server is not authorized by the sender domain's SPF record.",
                                "T1566"))
    if auth["dkim"] == "fail":
        findings.append(Finding(MODULE, "DKIM signature failed", Severity.MEDIUM,
                                "Message body or headers were altered, or the signature is forged.",
                                "T1566"))
    if auth["dmarc"] == "fail":
        findings.append(Finding(MODULE, "DMARC fail", Severity.HIGH,
                                "Sender domain alignment failed - a strong spoofing indicator.",
                                "T1566"))
    if auth == {"spf": "none", "dkim": "none", "dmarc": "none"}:
        findings.append(Finding(MODULE, "No authentication results", Severity.LOW,
                                "No SPF/DKIM/DMARC verdicts present; cannot confirm sender legitimacy."))

    # --- Sender consistency ---------------------------------------------
    if reply_to:
        rt_domain = domain_of(reply_to)
        if rt_domain and from_domain and org_domain(rt_domain) != org_domain(from_domain):
            findings.append(Finding(MODULE, "Reply-To domain differs from From", Severity.MEDIUM,
                                    f"From: {from_domain} / Reply-To: {rt_domain} - replies go to another org.",
                                    "T1566"))
    if return_path:
        rp_domain = domain_of(return_path)
        if rp_domain and from_domain and org_domain(rp_domain) != org_domain(from_domain):
            findings.append(Finding(MODULE, "Return-Path domain differs from From", Severity.LOW,
                                    f"From: {from_domain} / Return-Path: {rp_domain}."))

    # Display name contains an e-mail address of a different domain.
    embedded = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", display or "")
    if embedded and from_domain and org_domain(embedded.group(1).lower()) != org_domain(from_domain):
        findings.append(Finding(MODULE, "Display name spoofing", Severity.HIGH,
                                f"Display name shows '{embedded.group(0)}' but real sender is {from_addr}.",
                                "T1656"))
    elif display and any(w in display.lower() for w in _TRUSTED_DISPLAY_WORDS) and \
            from_domain.endswith(("gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "yandex.com")):
        findings.append(Finding(MODULE, "Authority display name from free mail provider", Severity.MEDIUM,
                                f"'{display}' sent from a free webmail account ({from_domain}).",
                                "T1656"))

    if info.subject and _URGENCY_SUBJECT.search(info.subject):
        findings.append(Finding(MODULE, "Urgency / lure keywords in subject", Severity.LOW,
                                f"Subject: {info.subject}", "T1566"))

    if not info.message_id:
        findings.append(Finding(MODULE, "Missing Message-ID", Severity.LOW,
                                "Legitimate MTAs almost always add a Message-ID."))

    return info, findings
