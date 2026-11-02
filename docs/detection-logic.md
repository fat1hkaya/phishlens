# Detection logic

Every rule produces a `Finding` with a severity. Severities carry fixed weights:

| Severity | Points |
|---|---|
| CRITICAL | 40 |
| HIGH | 25 |
| MEDIUM | 12 |
| LOW | 5 |
| INFO | 0 |

**Scoring** (`phishlens/scoring.py`)

- Findings are de-duplicated by `(module, title)` (twenty shortened links count once).
- Score = sum of weights, capped at 100.
- `score ≥ 60` → **MALICIOUS**; `score ≥ 25` *or* any CRITICAL finding → **SUSPICIOUS**; otherwise **LIKELY SAFE**.
- Escalation: `SPF fail` or `DMARC fail` together with any CRITICAL finding → **MALICIOUS** (min. score 60).

## headers

| Rule | Severity | ATT&CK |
|---|---|---|
| SPF fail / softfail | HIGH / MEDIUM | T1566 |
| DKIM signature failed | MEDIUM | T1566 |
| DMARC fail | HIGH | T1566 |
| No authentication results at all | LOW | - |
| Reply-To organization ≠ From organization | MEDIUM | T1566 |
| Return-Path organization ≠ From organization | LOW | - |
| Display name contains an address of another domain (`"ceo@corp.com" <x@gmail.com>`) | HIGH | T1656 |
| Authority display name (support, IT, bank, HR…) from free webmail | MEDIUM | T1656 |
| Urgency / lure keywords in subject (EN + TR) | LOW | T1566 |
| Missing Message-ID | LOW | - |

The originating IP is the first non-internal address (RFC1918, loopback, link-local and CGNAT are skipped) in the `Received` chain, read bottom-up.

## sender

| Rule | Severity | ATT&CK |
|---|---|---|
| From domain is a lookalike of a known brand | CRITICAL | T1656 |
| Display name claims a brand, domain unrelated | HIGH | T1656 |
| From domain is punycode | HIGH | T1656 |
| From domain uses a high-abuse TLD | MEDIUM | T1583.001 |

**Lookalike algorithm.** The registrable label is normalized (`0→o 1→l 3→e 4→a 5→s 7→t`, `rn→m`, `vv→w`). It matches a brand when the brand name is contained in it or the Levenshtein distance is ≤ 2 (brands with ≥ 5 chars). Official brand domains and their subdomains are always whitelisted. The brand list includes global targets and Turkish banks / e-Devlet / PTT.

## urls

| Rule | Severity | ATT&CK |
|---|---|---|
| Lookalike domain impersonating a brand | CRITICAL | T1583.001 |
| Link text shows one domain, `href` points to another | HIGH | T1566.002 |
| Raw IP address host | HIGH | T1566.002 |
| Punycode (IDN homograph) host, decoded form shown | HIGH | T1566.002 |
| `user@host` trick in authority | HIGH | T1566.002 |
| Direct download of exe/script/archive/disk image | HIGH | T1204.001 |
| HTML `<form>` inside the mail (external action = HIGH) | HIGH / MEDIUM | T1566.002 |
| URL shortener | MEDIUM | T1566.002 |
| High-abuse TLD | MEDIUM | T1566.002 |
| Credential keywords over plain HTTP | MEDIUM | T1566.002 |
| ≥ 4 dots in host | LOW | T1566.002 |
| All (≤ 3) links point outside the sender's organization | LOW | - |
| Threat intel: URL known malicious | CRITICAL | T1566.002 |

URLs visible only as anchor *text* are not treated as destinations; they feed the mismatch rule instead.

## attachments

| Rule | Severity | ATT&CK |
|---|---|---|
| Executable / script extension | CRITICAL | T1566.001 |
| Content is PE/ELF/LNK but extension is not executable | CRITICAL | T1036.008 |
| Right-to-left override (U+202E) in filename | CRITICAL | T1036.002 |
| ZIP contains exe / script / HTML / disk image | CRITICAL | T1204.002 |
| Double extension (`.pdf.exe`, `.doc.html`) | HIGH | T1036.007 |
| Macro-enabled Office (`.docm`, `.xlsm`…) | HIGH | T1566.001 |
| `vbaProject.bin` inside OOXML | HIGH | T1204.002 |
| HTML / SVG attachment (HTML smuggling, fake login) | HIGH | T1566.001 |
| HTML/script content under a non-HTML extension | HIGH | T1566.001 |
| Password-protected archive | HIGH | T1027 |
| Archive / disk image | MEDIUM | T1566.001 |
| Legacy Office (`.doc`, `.xls`, `.ppt`) | MEDIUM | T1566.001 |
| Threat intel: hash known malicious | CRITICAL | T1566.001 |

## content (EN + TR)

| Rule | Severity | ATT&CK |
|---|---|---|
| Credential request ("verify your account", "şifrenizi güncelleyin") | HIGH | T1566 |
| Urgency / threats ("within 24 hours", "hesabınız askıya") | MEDIUM | T1566 |
| Financial lure (invoice, refund, wire, "ödenmemiş fatura") | MEDIUM | T1566 |
| BEC phrasing ("are you available", "gizli tutun") | MEDIUM | T1566 |
| Generic greeting ("Dear Customer", "Sayın Müşterimiz") | LOW | T1566 |
| Hidden HTML text (`display:none`, `font-size:0`) | LOW | T1027 |

## intel

| Rule | Severity |
|---|---|
| Originating IP AbuseIPDB confidence ≥ 50 % | HIGH |
| VirusTotal: ≥ 2 engines malicious (file or URL) | CRITICAL |
| URLhaus listing | CRITICAL |
