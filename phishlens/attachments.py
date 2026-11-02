"""Attachment hashing, true-type detection and risk heuristics."""

from __future__ import annotations

import hashlib
import io
import zipfile

from phishlens.models import AttachmentInfo, Finding, Severity
from phishlens.parser import RawAttachment

MODULE = "attachments"

EXECUTABLE_EXT = {
    "exe", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse",
    "wsf", "hta", "msi", "jar", "lnk", "dll", "cpl", "reg", "chm",
}
CONTAINER_EXT = {"iso", "img", "vhd", "vhdx", "zip", "rar", "7z", "gz", "cab", "ace"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam"}
LEGACY_OFFICE_EXT = {"doc", "xls", "ppt"}
HTML_EXT = {"html", "htm", "shtml", "svg", "xhtml"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "png", "jpeg"}

MAGIC = [
    (b"MZ", "pe-executable"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip/ooxml"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2 (legacy office)"),
    (b"Rar!", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"),
    (b"\x7fELF", "elf-executable"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "windows-shortcut (lnk)"),
]


def detect_type(data: bytes) -> str | None:
    if len(data) >= 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso9660"
    for magic, name in MAGIC:
        if data.startswith(magic):
            return name
    head = data[:512].lstrip().lower()
    if head.startswith((b"<html", b"<!doctype html", b"<svg", b"<?xml")) or b"<script" in head:
        return "html/script"
    return None


def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def build_info(att: RawAttachment) -> AttachmentInfo:
    data = att.payload
    return AttachmentInfo(
        filename=att.filename,
        content_type=att.content_type,
        size=len(data),
        md5=hashlib.md5(data).hexdigest(),  # noqa: S324 - IOC hash, not a security control
        sha1=hashlib.sha1(data).hexdigest(),  # noqa: S324
        sha256=hashlib.sha256(data).hexdigest(),
        detected_type=detect_type(data),
    )


def analyze_attachments(raw: list[RawAttachment],
                        infos: list[AttachmentInfo] | None = None) -> tuple[list[AttachmentInfo], list[Finding]]:
    """Hash and assess attachments. Pass pre-built (e.g. intel-enriched) infos to reuse them."""
    infos = infos if infos is not None else [build_info(a) for a in raw]
    findings: list[Finding] = []
    for info, att in zip(infos, raw, strict=True):
        findings.extend(assess(info, att.payload))
    return infos, findings


def assess(info: AttachmentInfo, data: bytes) -> list[Finding]:
    out: list[Finding] = []
    name = info.filename
    lower = name.lower()
    ext = _ext(name)
    parts = lower.split(".")

    def add(title: str, sev: Severity, mitre: str = "T1566.001") -> None:
        out.append(Finding(MODULE, title, sev, f"{name} (sha256: {info.sha256})", mitre))

    if ext in EXECUTABLE_EXT:
        add(f"Executable attachment (.{ext})", Severity.CRITICAL)
    elif ext in CONTAINER_EXT:
        add(f"Archive / disk image attachment (.{ext})", Severity.MEDIUM)
    elif ext in MACRO_EXT:
        add(f"Macro-enabled Office document (.{ext})", Severity.HIGH)
    elif ext in LEGACY_OFFICE_EXT:
        add(f"Legacy Office format can carry macros (.{ext})", Severity.MEDIUM)
    elif ext in HTML_EXT:
        add(f"HTML/SVG attachment (.{ext}) - common credential-phishing vector", Severity.HIGH)

    if len(parts) >= 3 and parts[-2] in DOC_EXT and ext in EXECUTABLE_EXT | HTML_EXT | CONTAINER_EXT:
        add("Double extension disguises file type", Severity.HIGH, "T1036.007")

    if "‮" in name:
        add("Right-to-left override character in filename", Severity.CRITICAL, "T1036.002")

    dt = info.detected_type
    if dt in {"pe-executable", "elf-executable", "windows-shortcut (lnk)"} and ext not in EXECUTABLE_EXT:
        add(f"File content is {dt} but extension is .{ext or 'none'}", Severity.CRITICAL, "T1036.008")
    if dt == "html/script" and ext not in HTML_EXT:
        add("Attachment contains HTML/script content", Severity.HIGH)

    if dt == "zip/ooxml" and ext in {"zip"} | {"docx", "xlsx", "pptx"}:
        out.extend(_inspect_zip(info, data))

    if info.reputation.get("malicious"):
        out.append(Finding(MODULE, "Threat intel: attachment hash known malicious", Severity.CRITICAL,
                           f"{name} - {info.reputation.get('summary', '')}", "T1566.001"))
    return out


def _inspect_zip(info: AttachmentInfo, data: bytes) -> list[Finding]:
    out: list[Finding] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            encrypted = any(i.flag_bits & 0x1 for i in zf.infolist())
    except zipfile.BadZipFile:
        return out

    if any(n.lower().endswith("vbaproject.bin") for n in names):
        out.append(Finding(MODULE, "Office document contains VBA macros", Severity.HIGH,
                           info.filename, "T1204.002"))
    inner_exec = [n for n in names if _ext(n) in EXECUTABLE_EXT | HTML_EXT | {"iso", "img"}]
    if inner_exec and _ext(info.filename) == "zip":
        out.append(Finding(MODULE, "Archive contains executable/script files", Severity.CRITICAL,
                           f"{info.filename}: {', '.join(inner_exec[:5])}", "T1204.002"))
    if encrypted:
        out.append(Finding(MODULE, "Password-protected archive (evades scanning)", Severity.HIGH,
                           info.filename, "T1027"))
    return out
