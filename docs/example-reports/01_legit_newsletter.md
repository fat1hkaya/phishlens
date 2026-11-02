# PhishLens Analysis Report

| | |
|---|---|
| **File** | `01_legit_newsletter.eml` |
| **Verdict** | **LIKELY SAFE** |
| **Risk score** | 0/100 |
| **Threat intel** | offline (heuristics only) |
| **Generated** | 2026-11-02 12:19 UTC - PhishLens 1.0.0 |

## Message headers

| Field | Value |
|---|---|
| Subject | Your weekly repository digest |
| From | GitHub &lt;noreply@github.com&gt; |
| Reply-To | - |
| Return-Path | <noreply@github.com> |
| To | analyst@example.com |
| Date | Mon, 02 Nov 2026 09:00:00 +0000 |
| Message-ID | `<digest-123@github.com>` |
| SPF / DKIM / DMARC | `pass` / `pass` / `pass` |
| Originating IP | `192.30.252.201` |

### Relay path (origin first)

| # | From | By | IP |
|---|---|---|---|
| 1 | mail-out.github.com | mx.example.com | 192.30.252.201 |

## Findings (0)

No suspicious indicators detected.

## Indicators of compromise

### URLs (1)
- `hxxps[://]github[.]com/notifications` - shown as "View activity"

### Attachments (0)
- none


## Recommended actions

1. No strong phishing indicators found - close as false positive if the user report has no additional context.
2. Keep the report for the audit trail.
