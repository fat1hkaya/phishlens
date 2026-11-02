# PhishLens Analysis Report

| | |
|---|---|
| **File** | `04_bec_ceo_fraud.eml` |
| **Verdict** | **SUSPICIOUS** |
| **Risk score** | 49/100 |
| **Threat intel** | offline (heuristics only) |
| **Generated** | 2026-11-02 12:19 UTC - PhishLens 1.0.0 |

## Message headers

| Field | Value |
|---|---|
| Subject | Quick request |
| From | CEO - ceo@example.com &lt;ceo.office.private@gmail.com&gt; |
| Reply-To | - |
| Return-Path | - |
| To | assistant@example.com |
| Date | Mon, 02 Nov 2026 13:31:00 +0000 |
| Message-ID | `<CAF=123@mail.gmail.com>` |
| SPF / DKIM / DMARC | `pass` / `pass` / `pass` |
| Originating IP | `209.85.220.41` |

### Relay path (origin first)

| # | From | By | IP |
|---|---|---|---|
| 1 | mail-sor-f41.google.com | mx.example.com | 209.85.220.41 |

## Findings (3)

| Severity | Module | Finding | Detail | MITRE |
|---|---|---|---|---|
| HIGH | headers | Display name spoofing | Display name shows 'ceo@example.com' but real sender is ceo.office.private@gmail.com. | T1656 |
| MEDIUM | content | Financial lure | ...gift cards... | T1566 |
| MEDIUM | content | Business e-mail compromise phrasing | ...Are you available... | T1566 |

## Indicators of compromise

### URLs (0)
- none

### Attachments (0)
- none

## MITRE ATT&CK mapping

- [T1566](https://attack.mitre.org/techniques/T1566/) - Phishing
- [T1656](https://attack.mitre.org/techniques/T1656/) - Impersonation

## Recommended actions

1. Escalate to L2 for manual review before releasing the message.
2. Detonate attachments / URLs in a sandbox (e.g. ANY.RUN, Joe Sandbox, urlscan.io).
3. Contact the purported sender through a known-good channel to verify.
