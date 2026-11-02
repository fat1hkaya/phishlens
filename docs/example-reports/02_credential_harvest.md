# PhishLens Analysis Report

| | |
|---|---|
| **File** | `02_credential_harvest.eml` |
| **Verdict** | **MALICIOUS** |
| **Risk score** | 100/100 |
| **Threat intel** | offline (heuristics only) |
| **Generated** | 2026-11-02 12:19 UTC - PhishLens 1.0.0 |

## Message headers

| Field | Value |
|---|---|
| Subject | URGENT: Unusual sign-in activity - your account will be suspended |
| From | PayPal Security &lt;service@paypa1-security.com&gt; |
| Reply-To | resolution-center@protonmail.com |
| Return-Path | <bounce@mailer-x91.top> |
| To | victim@example.com |
| Date | Mon, 02 Nov 2026 07:14:00 +0000 |
| Message-ID | `<9f2c1@paypa1-security.com>` |
| SPF / DKIM / DMARC | `fail` / `none` / `fail` |
| Originating IP | `203.0.113.45` |

### Relay path (origin first)

| # | From | By | IP |
|---|---|---|---|
| 1 | vps-4471.badhost.example | mx.example.com | 203.0.113.45 |
| 2 | mx.example.com | mail.example.com |  |

## Findings (15)

| Severity | Module | Finding | Detail | MITRE |
|---|---|---|---|---|
| CRITICAL | sender | Sender domain impersonates 'paypal' | paypa1-security.com is not an official paypal domain | T1656 |
| CRITICAL | urls | Lookalike domain impersonating 'paypal' | paypa1-security[.]com is not an official paypal domain | T1583.001 |
| HIGH | headers | SPF fail | Sending server is not authorized by the sender domain's SPF record. | T1566 |
| HIGH | headers | DMARC fail | Sender domain alignment failed - a strong spoofing indicator. | T1566 |
| HIGH | urls | Link text/destination mismatch | Shows 'https://www.paypal.com/signin' but points to hxxp[://]paypa1-security[.]com/webscr/login?session=8812 | T1566.002 |
| HIGH | urls | URL uses raw IP address | hxxp[://]203[.]0[.]113[.]45/collect[.]php | T1566.002 |
| HIGH | urls | HTML form embedded in e-mail | Form action: http://203.0.113.45/collect.php - may harvest credentials inside the mail client. | T1566.002 |
| HIGH | content | Credential request | ...verify your account... | T1566 |
| MEDIUM | headers | Reply-To domain differs from From | From: paypa1-security.com / Reply-To: protonmail.com - replies go to another org. | T1566 |
| MEDIUM | urls | Credential keywords over plain HTTP | hxxp[://]paypa1-security[.]com/webscr/login?session=8812 | T1566.002 |
| MEDIUM | content | Urgency / threat language | ...unusual sign-in... | T1566 |
| LOW | headers | Return-Path domain differs from From | From: paypa1-security.com / Return-Path: mailer-x91.top. |  |
| LOW | headers | Urgency / lure keywords in subject | Subject: URGENT: Unusual sign-in activity - your account will be suspended | T1566 |
| LOW | content | Generic greeting | ...Dear Customer... | T1566 |
| LOW | content | Hidden text in HTML body | Invisible text is often used to evade content filters. | T1027 |

## Indicators of compromise

### URLs (3)
- `hxxp[://]paypa1-security[.]com/webscr/login?session=8812` - shown as "https://www.paypal.com/signin"
- `hxxp[://]203[.]0[.]113[.]45/collect[.]php`
- `hxxps[://]paypa1-security[.]com/webscr/login?session=8812`

### Attachments (0)
- none

## MITRE ATT&CK mapping

- [T1027](https://attack.mitre.org/techniques/T1027/) - Obfuscated Files or Information
- [T1566](https://attack.mitre.org/techniques/T1566/) - Phishing
- [T1566.002](https://attack.mitre.org/techniques/T1566/002/) - Spearphishing Link
- [T1583.001](https://attack.mitre.org/techniques/T1583/001/) - Acquire Infrastructure: Domains
- [T1656](https://attack.mitre.org/techniques/T1656/) - Impersonation

## Recommended actions

1. Block sender address/domain and listed IOCs on the mail gateway, proxy and EDR.
2. Search the mailbox estate for the same Message-ID, subject or sender and purge copies.
3. Identify recipients who clicked links or opened attachments; reset credentials and isolate hosts if needed.
4. Open an incident ticket and attach this report as evidence.
