"""Low-level .eml parsing: bodies and attachments."""

from __future__ import annotations

from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser


@dataclass
class RawAttachment:
    filename: str
    content_type: str
    payload: bytes


@dataclass
class ParsedEmail:
    message: EmailMessage
    text_body: str = ""
    html_body: str = ""
    attachments: list[RawAttachment] = field(default_factory=list)


def parse_eml(data: bytes) -> ParsedEmail:
    """Parse raw RFC 5322 bytes into bodies and attachments."""
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(data)
    parsed = ParsedEmail(message=msg)

    for part in msg.walk():
        if part.is_multipart():
            continue

        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        ctype = part.get_content_type()

        if disposition == "attachment" or filename:
            payload = part.get_payload(decode=True) or b""
            parsed.attachments.append(
                RawAttachment(
                    filename=filename or "unnamed",
                    content_type=ctype,
                    payload=payload,
                )
            )
            continue

        if ctype == "text/plain":
            parsed.text_body += _safe_text(part)
        elif ctype == "text/html":
            parsed.html_body += _safe_text(part)

    return parsed


def _safe_text(part: EmailMessage) -> str:
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError, KeyError):
        raw = part.get_payload(decode=True) or b""
        return raw.decode("utf-8", errors="replace")
