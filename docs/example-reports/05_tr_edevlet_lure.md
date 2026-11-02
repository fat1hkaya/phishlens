# PhishLens Analysis Report

| | |
|---|---|
| **File** | `05_tr_edevlet_lure.eml` |
| **Verdict** | **MALICIOUS** |
| **Risk score** | 100/100 |
| **Threat intel** | offline (heuristics only) |
| **Generated** | 2026-11-02 12:19 UTC - PhishLens 1.0.0 |

## Message headers

| Field | Value |
|---|---|
| Subject | Acil: Ödenmemiş fatura - hesabınız askıya alınacak |
| From | e-Devlet Kapısı &lt;bildirim@edevlet-bildirim.xyz&gt; |
| Reply-To | - |
| Return-Path | - |
| To | kullanici@example.com.tr |
| Date | Mon, 02 Nov 2026 15:45:00 +0300 |
| Message-ID | `-` |
| SPF / DKIM / DMARC | `softfail` / `none` / `fail` |
| Originating IP | `192.0.2.77` |

### Relay path (origin first)

| # | From | By | IP |
|---|---|---|---|
| 1 | smtp.bulkmail.example | mx.example.com.tr | 192.0.2.77 |

## Findings (13)

| Severity | Module | Finding | Detail | MITRE |
|---|---|---|---|---|
| CRITICAL | sender | Sender domain impersonates 'edevlet' | edevlet-bildirim.xyz is not an official edevlet domain | T1656 |
| HIGH | headers | DMARC fail | Sender domain alignment failed - a strong spoofing indicator. | T1566 |
| HIGH | urls | Punycode (IDN homograph) domain | hxxp[://]xn--turkye-gov-0ub[.]com/giris (renders as: turkıye-gov.com) | T1566.002 |
| HIGH | content | Credential request | ...kimliğinizi doğrula... | T1566 |
| MEDIUM | headers | SPF softfail | Sending server is not authorized by the sender domain's SPF record. | T1566 |
| MEDIUM | sender | Sender uses suspicious top-level domain | edevlet-bildirim.xyz | T1583.001 |
| MEDIUM | urls | URL shortener hides destination | hxxps[://]bit[.]ly/3xYz-edevlet | T1566.002 |
| MEDIUM | content | Urgency / threat language | ...24 saat içinde... | T1566 |
| MEDIUM | content | Financial lure | ...ödenmemiş fatura... | T1566 |
| LOW | headers | Urgency / lure keywords in subject | Subject: Acil: Ödenmemiş fatura - hesabınız askıya alınacak | T1566 |
| LOW | headers | Missing Message-ID | Legitimate MTAs almost always add a Message-ID. |  |
| LOW | urls | All links point outside sender's domain | Sender: edevlet-bildirim.xyz; link domains: bit.ly, xn--turkye-gov-0ub.com |  |
| LOW | content | Generic greeting | ...Sayın Kullanıcı... | T1566 |

## Indicators of compromise

### URLs (2)
- `hxxps[://]bit[.]ly/3xYz-edevlet`
- `hxxp[://]xn--turkye-gov-0ub[.]com/giris`

### Attachments (0)
- none

## MITRE ATT&CK mapping

- [T1566](https://attack.mitre.org/techniques/T1566/) - Phishing
- [T1566.002](https://attack.mitre.org/techniques/T1566/002/) - Spearphishing Link
- [T1583.001](https://attack.mitre.org/techniques/T1583/001/) - Acquire Infrastructure: Domains
- [T1656](https://attack.mitre.org/techniques/T1656/) - Impersonation

## Recommended actions

1. Block sender address/domain and listed IOCs on the mail gateway, proxy and EDR.
2. Search the mailbox estate for the same Message-ID, subject or sender and purge copies.
3. Identify recipients who clicked links or opened attachments; reset credentials and isolate hosts if needed.
4. Open an incident ticket and attach this report as evidence.
