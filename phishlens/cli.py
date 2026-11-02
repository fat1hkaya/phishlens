"""Command-line interface.

    phishlens analyze suspicious.eml
    phishlens analyze mails/*.eml --format html --output reports/
    phishlens analyze mail.eml --format json | jq .verdict
    phishlens web
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from phishlens import __version__
from phishlens.analyzer import analyze_file
from phishlens.intel import IntelClient
from phishlens.models import AnalysisResult, Severity
from phishlens.report import RENDERERS

EXIT_CODES = {"LIKELY SAFE": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}

_COLORS = {
    "MALICIOUS": "\033[1;31m", "SUSPICIOUS": "\033[1;33m", "LIKELY SAFE": "\033[1;32m",
    Severity.CRITICAL: "\033[31m", Severity.HIGH: "\033[91m", Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[32m", Severity.INFO: "\033[90m",
}
RESET = "\033[0m"


def _c(text: str, key, enabled: bool) -> str:
    return f"{_COLORS[key]}{text}{RESET}" if enabled else text


def print_summary(r: AnalysisResult, color: bool) -> None:
    h = r.headers
    print(f"\n{'=' * 70}\n  {r.filename}\n{'=' * 70}")
    print(f"  Verdict : {_c(r.verdict, r.verdict, color)}   (risk score {r.score}/100)")
    print(f"  Subject : {h.subject}")
    print(f"  From    : {h.from_display} <{h.from_address}>")
    print(f"  Auth    : SPF={h.spf}  DKIM={h.dkim}  DMARC={h.dmarc}   origin IP={h.originating_ip or '-'}")
    print(f"  IOCs    : {len(r.urls)} URL(s), {len(r.attachments)} attachment(s)")
    if r.findings:
        print("\n  Findings:")
        for f in r.findings:
            sev = _c(f"[{f.severity.value.upper():8}]", f.severity, color)
            mitre = f" ({f.mitre})" if f.mitre else ""
            print(f"    {sev} {f.title}{mitre}")
            if f.detail:
                print(f"               {f.detail[:110]}")
    if r.mitre_techniques:
        print(f"\n  MITRE ATT&CK: {', '.join(r.mitre_techniques)}")
    print()


def cmd_analyze(args: argparse.Namespace) -> int:
    intel = IntelClient() if args.online else None
    if args.online and not intel.enabled:
        print("[!] --online given but no VT_API_KEY / ABUSEIPDB_API_KEY / URLHAUS_API_KEY set; "
              "running heuristics only.", file=sys.stderr)

    files = [Path(p) for p in args.files]
    out_dir = Path(args.output) if args.output else None
    if out_dir and (len(files) > 1 or out_dir.suffix == ""):
        out_dir.mkdir(parents=True, exist_ok=True)

    worst = 0
    color = sys.stdout.isatty() and not args.no_color
    for path in files:
        if not path.is_file():
            print(f"[!] not found: {path}", file=sys.stderr)
            worst = max(worst, 3)
            continue
        result = analyze_file(path, intel)
        worst = max(worst, EXIT_CODES[result.verdict])

        if args.format == "text":
            print_summary(result, color)
            continue

        rendered = RENDERERS[args.format](result)
        ext = {"markdown": "md"}.get(args.format, args.format)
        if out_dir is None:
            print(rendered)
        else:
            target = out_dir / f"{path.stem}.{ext}" if out_dir.is_dir() else out_dir
            target.write_text(rendered, encoding="utf-8")
            print(f"[+] {path.name}: {result.verdict} ({result.score}/100) -> {target}")
    return worst


def cmd_web(args: argparse.Namespace) -> int:
    from phishlens.web.app import create_app

    create_app().run(host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="phishlens", description="Phishing e-mail analyzer for SOC triage.")
    p.add_argument("--version", action="version", version=f"PhishLens {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyze one or more .eml files")
    a.add_argument("files", nargs="+", help=".eml file(s)")
    a.add_argument("-f", "--format", choices=["text", "json", "md", "markdown", "html"], default="text")
    a.add_argument("-o", "--output", help="output file or directory")
    a.add_argument("--online", action="store_true", help="enable threat-intel lookups (needs API keys)")
    a.add_argument("--no-color", action="store_true")
    a.set_defaults(func=cmd_analyze)

    w = sub.add_parser("web", help="start the web interface")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=5000)
    w.set_defaults(func=cmd_web)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
