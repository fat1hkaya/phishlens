"""URL extraction and heuristic analysis."""

from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import unquote, urlparse

from phishlens.headers import org_domain
from phishlens.models import Finding, Severity, UrlInfo

MODULE = "urls"

URL_RE = re.compile(r"""(?i)\bhttps?://[^\s<>"'()\[\]{}]+""")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf",
    "ga", "work", "support", "rest", "cam", "icu", "monster", "live", "sbs",
}
# Brands most frequently impersonated in credential-phishing campaigns.
BRANDS = {
    "microsoft": "microsoft.com", "office365": "office.com", "outlook": "outlook.com",
    "paypal": "paypal.com", "apple": "apple.com", "icloud": "icloud.com",
    "google": "google.com", "amazon": "amazon.com", "netflix": "netflix.com",
    "dhl": "dhl.com", "fedex": "fedex.com", "linkedin": "linkedin.com",
    "docusign": "docusign.com", "dropbox": "dropbox.com", "instagram": "instagram.com",
    "facebook": "facebook.com", "adobe": "adobe.com", "binance": "binance.com",
    "vakifbank": "vakifbank.com.tr", "ziraat": "ziraatbank.com.tr",
    "garanti": "garantibbva.com.tr", "akbank": "akbank.com", "edevlet": "turkiye.gov.tr",
    "ptt": "ptt.gov.tr", "yapikredi": "yapikredi.com.tr", "isbank": "isbank.com.tr",
}
CREDENTIAL_WORDS = re.compile(
    r"(login|log-in|signin|sign-in|verify|verification|account|secure|update|"
    r"password|wallet|unlock|confirm|webscr|auth|session|billing)",
    re.I,
)
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []
        self.forms: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self._href = attrs["href"]
            self._text = []
        elif tag == "form":
            self.forms.append(attrs.get("action") or "")
        elif tag in {"img", "iframe", "script"} and attrs.get("src", "").startswith("http"):
            self.links.append((attrs["src"], ""))

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._text).split())))
            self._href = None


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def extract_urls(text_body: str, html_body: str) -> tuple[list[UrlInfo], list[str]]:
    seen: dict[str, UrlInfo] = {}
    forms: list[str] = []

    if html_body:
        parser = _LinkExtractor()
        try:
            parser.feed(html_body)
        except Exception:  # noqa: S110 - malformed HTML must never crash the analysis
            pass
        forms = parser.forms
        for href, text in parser.links:
            href = href.strip()
            if not href.lower().startswith(("http://", "https://")):
                continue
            seen.setdefault(href, UrlInfo(href, _host(href), "html-anchor" if text else "html", text or None))

        for action in forms:
            if action.lower().startswith(("http://", "https://")):
                seen.setdefault(action, UrlInfo(action, _host(action), "html-form"))

    # Plain-text body only: URLs that appear as *visible text* inside HTML anchors are
    # display text, not destinations, and are evaluated by the mismatch check instead.
    for match in URL_RE.findall(text_body or ""):
        url = match.rstrip(".,;:!?")
        seen.setdefault(url, UrlInfo(url, _host(url), "text"))

    return list(seen.values()), forms


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def lookalike_brand(host: str) -> str | None:
    """Return the impersonated brand if the host looks like (but is not) a brand domain."""
    if not host:
        return None
    reg = org_domain(host)
    for legit in BRANDS.values():
        if reg == org_domain(legit) or host.endswith("." + legit) or host == legit:
            return None
    label = reg.split(".")[0]
    normalized = label.translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    for brand in BRANDS:
        if brand in normalized or brand in host.replace(".", "").replace("-", ""):
            return brand
        if len(brand) >= 5 and levenshtein(normalized, brand) <= 2:
            return brand
    return None


def decode_idn(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna")
    except UnicodeError:
        return host


SENDER_MODULE = "sender"


def analyze_sender_domain(from_domain: str, display_name: str = "") -> list[Finding]:
    """Brand impersonation / risky TLD checks on the From: domain itself."""
    findings: list[Finding] = []
    if not from_domain:
        return findings
    brand = lookalike_brand(from_domain)
    if not brand and display_name:
        # Display name claims a brand the sending domain does not belong to.
        squashed = re.sub(r"[^a-z0-9]", "", display_name.lower())
        for b, legit in BRANDS.items():
            if b in squashed and org_domain(from_domain) != org_domain(legit):
                findings.append(Finding(SENDER_MODULE, f"Display name claims '{b}' from unrelated domain",
                                        Severity.HIGH, f"'{display_name}' <...@{from_domain}>", "T1656"))
                break
    if brand:
        findings.append(Finding(SENDER_MODULE, f"Sender domain impersonates '{brand}'", Severity.CRITICAL,
                                f"{from_domain} is not an official {brand} domain", "T1656"))
    if from_domain.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        findings.append(Finding(SENDER_MODULE, "Sender uses suspicious top-level domain", Severity.MEDIUM,
                                from_domain, "T1583.001"))
    if from_domain.startswith("xn--") or ".xn--" in from_domain:
        findings.append(Finding(SENDER_MODULE, "Sender domain is punycode (IDN homograph)", Severity.HIGH,
                                f"{from_domain} renders as {decode_idn(from_domain)}", "T1656"))
    return findings


def analyze_urls(urls: list[UrlInfo], forms: list[str], sender_domain: str) -> list[Finding]:
    findings: list[Finding] = []
    flagged: set[tuple[str, str]] = set()

    def add(title: str, sev: Severity, detail: str, mitre: str | None = "T1566.002") -> None:
        key = (title, detail)
        if key not in flagged:
            flagged.add(key)
            findings.append(Finding(MODULE, title, sev, detail, mitre))

    for u in urls:
        host = u.domain
        parsed = urlparse(u.url)
        d = u.defanged

        if _is_ip(host):
            add("URL uses raw IP address", Severity.HIGH, d)
        if host.startswith("xn--") or ".xn--" in host:
            add("Punycode (IDN homograph) domain", Severity.HIGH, f"{d} (renders as: {decode_idn(host)})")
        if host in SHORTENERS:
            add("URL shortener hides destination", Severity.MEDIUM, d)
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            add("Suspicious top-level domain", Severity.MEDIUM, d)
        if "@" in (parsed.netloc or ""):
            add("Credentials-style '@' in URL authority", Severity.HIGH, d)
        if host.count(".") >= 4:
            add("Excessive subdomains", Severity.LOW, d)
        if parsed.scheme == "http" and CREDENTIAL_WORDS.search(u.url):
            add("Credential keywords over plain HTTP", Severity.MEDIUM, d)

        brand = lookalike_brand(host)
        if brand:
            add(f"Lookalike domain impersonating '{brand}'", Severity.CRITICAL,
                f"{host.replace('.', '[.]')} is not an official {brand} domain", "T1583.001")

        # Anchor text shows one domain but links to another.
        if u.display_text:
            shown = URL_RE.search(u.display_text) or re.search(
                r"\b([a-z0-9-]+\.)+[a-z]{2,}\b", u.display_text, re.I)
            if shown:
                shown_host = _host(shown.group(0) if shown.group(0).startswith("http")
                                   else "http://" + shown.group(0))
                if shown_host and org_domain(shown_host) != org_domain(host):
                    add("Link text/destination mismatch", Severity.HIGH,
                        f"Shows '{u.display_text}' but points to {d}")

        if re.search(r"\.(exe|scr|js|vbs|hta|iso|img|zip|rar|7z|msi|lnk)(\?|$)", unquote(parsed.path), re.I):
            add("URL downloads executable / archive", Severity.HIGH, d, "T1204.001")

        if u.reputation.get("malicious"):
            add("Threat intel: URL/domain reported malicious", Severity.CRITICAL,
                f"{d} - {u.reputation.get('summary', '')}")

    for action in forms:
        sev = Severity.HIGH if action.lower().startswith("http") else Severity.MEDIUM
        add("HTML form embedded in e-mail", sev,
            f"Form action: {action or '(none)'} - may harvest credentials inside the mail client.")

    external = {org_domain(u.domain) for u in urls if u.domain}
    if sender_domain and external and org_domain(sender_domain) not in external and len(urls) <= 3:
        add("All links point outside sender's domain", Severity.LOW,
            f"Sender: {sender_domain}; link domains: {', '.join(sorted(external))}", None)

    return findings
