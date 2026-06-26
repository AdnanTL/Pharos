"""
PHAROS — EML Parser
Lit un fichier .eml et extrait toutes les informations structurées
"""

import email
import email.policy
import email.header
import hashlib
import re
from email import message_from_bytes
from dataclasses import dataclass, field


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    md5: str
    sha256: str
    preview_kind: str
    data: bytes = field(repr=False)

    def to_dict(self):
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size": self.size,
            "md5": self.md5,
            "sha256": self.sha256,
            "preview_kind": self.preview_kind,
        }


@dataclass
class ParsedEmail:
    subject: str = ""
    from_addr: str = ""
    to_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    date: str = ""
    message_id: str = ""
    x_mailer: str = ""
    received_ips: list = field(default_factory=list)
    originating_ip: str = ""
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    body_text: str = ""
    body_html: str = ""
    attachments: list = field(default_factory=list)
    raw_headers: dict = field(default_factory=dict)


def parse_eml(data: bytes) -> ParsedEmail:
    msg = message_from_bytes(data, policy=email.policy.compat32)
    parsed = ParsedEmail()

    parsed.subject = _decode_header(msg.get("Subject", ""))
    parsed.from_addr = _decode_header(msg.get("From", ""))
    parsed.to_addr = _decode_header(msg.get("To", ""))
    parsed.reply_to = _decode_header(msg.get("Reply-To", ""))
    parsed.return_path = _decode_header(msg.get("Return-Path", ""))
    parsed.date = msg.get("Date", "")
    parsed.message_id = msg.get("Message-ID", "")
    parsed.x_mailer = msg.get("X-Mailer", msg.get("X-Originating-Client", ""))

    for key in set(msg.keys()):
        parsed.raw_headers[key] = msg.get_all(key, [])

    auth = msg.get("Authentication-Results", "")
    if auth:
        parsed.spf = _extract_auth(auth, "spf")
        parsed.dkim = _extract_auth(auth, "dkim")
        parsed.dmarc = _extract_auth(auth, "dmarc")

    spf_header = msg.get("Received-SPF", "")
    if spf_header and parsed.spf == "none":
        for result in ("pass", "fail", "softfail", "neutral"):
            if result in spf_header.lower():
                parsed.spf = result
                break

    ip_pattern = re.compile(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]')
    received_headers = msg.get_all("Received", [])
    seen = set()
    for r in received_headers:
        for ip in ip_pattern.findall(r):
            if ip not in seen and not _is_private_ip(ip):
                seen.add(ip)
                parsed.received_ips.append(ip)

    if parsed.received_ips:
        parsed.originating_ip = parsed.received_ips[-1]

    x_orig = msg.get("X-Originating-IP", "")
    if x_orig:
        parsed.originating_ip = x_orig.strip("[]").strip()

    if msg.is_multipart():
        for part in msg.walk():
            _process_part(part, parsed)
    else:
        _process_part(msg, parsed)

    return parsed


def _process_part(part, parsed: ParsedEmail):
    content_type = (part.get_content_type() or "").lower()
    disposition = str(part.get("Content-Disposition", "")).lower()
    filename = part.get_filename()

    is_attachment = "attachment" in disposition or bool(filename)
    is_inline_file = "inline" in disposition and bool(filename)

    if is_attachment or is_inline_file:
        safe_filename = filename or "unnamed"
        try:
            data = part.get_payload(decode=True) or b""
            preview_kind = _detect_preview_kind(safe_filename, content_type)

            parsed.attachments.append(Attachment(
                filename=safe_filename,
                content_type=content_type or "application/octet-stream",
                size=len(data),
                md5=hashlib.md5(data).hexdigest(),
                sha256=hashlib.sha256(data).hexdigest(),
                preview_kind=preview_kind,
                data=data,
            ))
        except Exception:
            pass
        return

    try:
        payload = part.get_payload(decode=True)
        if not payload:
            return
        charset = part.get_content_charset() or "utf-8"
        text = payload.decode(charset, errors="replace")
    except Exception:
        return

    if content_type == "text/plain" and not parsed.body_text:
        parsed.body_text = text
    elif content_type == "text/html" and not parsed.body_html:
        parsed.body_html = text


def _detect_preview_kind(filename: str, content_type: str) -> str:
    name = (filename or "").lower()
    ctype = (content_type or "").lower()

    if ctype == "application/pdf" or name.endswith(".pdf"):
        return "pdf"

    if ctype.startswith("image/") or name.endswith((
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"
    )):
        return "image"

    if ctype.startswith("text/") or name.endswith((
        ".txt", ".log", ".csv", ".json", ".xml", ".html", ".htm"
    )):
        return "text"

    return "blocked"


def _decode_header(value: str) -> str:
    try:
        parts = email.header.decode_header(value)
        result = []
        for part, enc in parts:
            if isinstance(part, bytes):
                result.append(part.decode(enc or "utf-8", errors="replace"))
            else:
                result.append(str(part))
        return " ".join(result)
    except Exception:
        return value


def _extract_auth(auth_str: str, protocol: str) -> str:
    m = re.search(rf"{protocol}=(\w+)", auth_str, re.IGNORECASE)
    return m.group(1).lower() if m else "none"


def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        a, b = int(parts[0]), int(parts[1])
        return (
            a == 10 or
            a == 127 or
            (a == 172 and 16 <= b <= 31) or
            (a == 192 and b == 168)
        )
    except ValueError:
        return True
