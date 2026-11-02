# PhishLens Analysis Report

| | |
|---|---|
| **File** | `03_malicious_attachment.eml` |
| **Verdict** | **MALICIOUS** |
| **Risk score** | 100/100 |
| **Threat intel** | offline (heuristics only) |
| **Generated** | 2026-11-02 12:19 UTC - PhishLens 1.0.0 |

## Message headers

| Field | Value |
|---|---|
| Subject | Outstanding invoice #INV-20931 - payment failed |
| From | Accounts Payable &lt;billing@acme-logistics.example&gt; |
| Reply-To | - |
| Return-Path | - |
| To | finance@example.com |
| Date | Mon, 02 Nov 2026 11:02:40 +0000 |
| Message-ID | `-` |
| SPF / DKIM / DMARC | `softfail` / `none` / `none` |
| Originating IP | `198.51.100.23` |

### Relay path (origin first)

| # | From | By | IP |
|---|---|---|---|
| 1 | [198.51.100.23] | mx.example.com | 198.51.100.23 |

## Findings (9)

| Severity | Module | Finding | Detail | MITRE |
|---|---|---|---|---|
| CRITICAL | attachments | Executable attachment (.exe) | Invoice_20931.pdf.exe (sha256: 6527e7980bba971c7bf53dd5c93e41dafd2d44a9b346f600e3063e2b44467925) | T1566.001 |
| CRITICAL | attachments | Archive contains executable/script files | Invoice_scan.zip: Invoice_20931.js | T1204.002 |
| HIGH | attachments | Double extension disguises file type | Invoice_20931.pdf.exe (sha256: 6527e7980bba971c7bf53dd5c93e41dafd2d44a9b346f600e3063e2b44467925) | T1036.007 |
| HIGH | attachments | Macro-enabled Office document (.xlsm) | Remittance.xlsm (sha256: 9df4c7281b7a9a32c192faa5d91373bb6f043aa1610293667564baed466eb324) | T1566.001 |
| MEDIUM | headers | SPF softfail | Sending server is not authorized by the sender domain's SPF record. | T1566 |
| MEDIUM | attachments | Archive / disk image attachment (.zip) | Invoice_scan.zip (sha256: acbc5a83ea20571ca850c837c7069bbabb1dc0d7242b8fad94bcde9a42930447) | T1566.001 |
| MEDIUM | content | Financial lure | ...payment failed... | T1566 |
| LOW | headers | Urgency / lure keywords in subject | Subject: Outstanding invoice #INV-20931 - payment failed | T1566 |
| LOW | headers | Missing Message-ID | Legitimate MTAs almost always add a Message-ID. |  |

## Indicators of compromise

### URLs (0)
- none

### Attachments (3)
- **Invoice_20931.pdf.exe** (application/octet-stream, 116 bytes, detected: pe-executable)
  - MD5 `f15f47eac66b5c305c4b5c965a107973`
  - SHA1 `6ec34b25cda05cf0ac54e48c28fe875d38c57054`
  - SHA256 `6527e7980bba971c7bf53dd5c93e41dafd2d44a9b346f600e3063e2b44467925`
- **Invoice_scan.zip** (application/zip, 169 bytes, detected: zip/ooxml)
  - MD5 `67974a2d7239afb067c7cc89eedbd402`
  - SHA1 `af57cc309c629f627d4dfc5b502ea16e2a603f3c`
  - SHA256 `acbc5a83ea20571ca850c837c7069bbabb1dc0d7242b8fad94bcde9a42930447`
- **Remittance.xlsm** (application/vnd.ms-excel.sheet.macroenabled.12, 26 bytes, detected: unknown)
  - MD5 `a5f444874e0c6aa3890cb69364acf031`
  - SHA1 `50d7992cdd9a8eae56585afa940469c9c1deafea`
  - SHA256 `9df4c7281b7a9a32c192faa5d91373bb6f043aa1610293667564baed466eb324`

## MITRE ATT&CK mapping

- [T1036.007](https://attack.mitre.org/techniques/T1036/007/) - Masquerading: Double File Extension
- [T1204.002](https://attack.mitre.org/techniques/T1204/002/) - User Execution: Malicious File
- [T1566](https://attack.mitre.org/techniques/T1566/) - Phishing
- [T1566.001](https://attack.mitre.org/techniques/T1566/001/) - Spearphishing Attachment

## Recommended actions

1. Block sender address/domain and listed IOCs on the mail gateway, proxy and EDR.
2. Search the mailbox estate for the same Message-ID, subject or sender and purge copies.
3. Identify recipients who clicked links or opened attachments; reset credentials and isolate hosts if needed.
4. Open an incident ticket and attach this report as evidence.
