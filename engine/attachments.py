"""Attachment content analysis (static, kabhi file chalati nahi). Heuristics sirf filename dekhti hai (double
extension, .exe...); ye module ANDAR dekhta hai: asli file type, PDF JavaScript/links, Office macros, archive tricks,
HTML attachment mein nakli login form.

Hadd (DoS/zip-bomb se bachao): har file <= MAX_FILE_BYTES, <= MAX_FILES, archive ke sirf naam/flags padhte hain
(extract nahi), OOXML ke sirf chhote XML members (<= 512 KB) padhte hain.
"""
from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field

from engine.models import Signal

MAX_FILES = 10
MAX_FILE_BYTES = 5_000_000
_SMALL_MEMBER = 512_000
EXEC_EXT = (".exe", ".msi", ".scr", ".bat", ".cmd", ".com", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".jar",
            ".lnk", ".hta", ".iso", ".img", ".dll", ".apk", ".wsf")
_URL_RE = re.compile(rb"https?://[^\s\"'<>()\\\x00-\x1f]{4,300}", re.IGNORECASE)
_PDF_URI = re.compile(rb"/URI\s*\(([^)]{4,300})\)")


def sniff(data: bytes) -> str:
    """Asli type magic bytes se (naam par bharosa nahi)."""
    h = data[:8]
    if h[:2] == b"MZ":
        return "exe"
    if h[:4] == b"\x7fELF":
        return "elf"
    if h[:5] == b"%PDF-":
        return "pdf"
    if h[:4] == b"PK\x03\x04":
        return "zip"
    if h[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if h[:4] == b"Rar!" or h[:6] == b"7z\xbc\xaf\x27\x1c":
        return "archive"
    if h[:5] == b"{\\rtf":
        return "rtf"
    low = data[:2000].lstrip().lower()
    if low.startswith((b"<!doctype html", b"<html", b"<svg", b"<?xml")) or b"<script" in low:
        return "html"
    if h[:8] == b"\x89PNG\r\n\x1a\n" or h[:3] == b"\xff\xd8\xff" or h[:4] == b"GIF8":
        return "image"
    return "other"


@dataclass
class AttachmentReport:
    name: str
    size: int
    real_type: str
    points: float = 0.0
    signals: list[Signal] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)

    def report(self) -> dict:
        return {"name": self.name[:120], "size": self.size, "real_type": self.real_type,
                "points": self.points, "findings": [s.text for s in self.signals],
                "urls": self.urls[:10]}


def _ext(name: str) -> str:
    return ("." + name.lower().rsplit(".", 1)[-1]) if "." in name else ""


def analyze_attachment(name: str, data: bytes) -> AttachmentReport:  # noqa: C901
    rep = AttachmentReport(name=name, size=len(data), real_type=sniff(data))
    ext, real = _ext(name), rep.real_type

    def add(code: str, pts: float, text: str) -> None:
        rep.signals.append(Signal(code, "attachment", pts, text))
        rep.points += pts

    if real in {"exe", "elf"} and ext not in EXEC_EXT:
        add("att_disguised_exe", 60,
            f"'{name[:60]}' claims to be {ext or 'a document'} but is really an executable program")
    elif real in {"exe", "elf"}:
        add("att_real_exe", 30, "Attachment is a real executable program")

    if real == "pdf":
        low = data[: MAX_FILE_BYTES]
        if re.search(rb"/(JavaScript|JS)\b", low):
            add("att_pdf_js", 25, "PDF contains embedded JavaScript")
        if re.search(rb"/(Launch|EmbeddedFile)\b", low):
            add("att_pdf_launch", 30, "PDF can launch a program or carries an embedded file")
        uris = [m.group(1).decode("latin-1", "replace") for m in _PDF_URI.finditer(low)]
        if uris:
            rep.urls = list(dict.fromkeys(uris))[:10]
            add("att_pdf_link", 10, f"PDF contains {len(rep.urls)} clickable link(s)")

    elif real == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                infos = zf.infolist()[:300]
                names = [i.filename for i in infos]
                lname = [n.lower() for n in names]
                if any(i.flag_bits & 0x1 for i in infos):
                    add("att_encrypted_zip", 25,
                        "Password-protected archive (a common way to hide malware from scanners)")
                if any(n.endswith(EXEC_EXT) for n in lname):
                    add("att_zip_exec", 45, "Archive contains an executable or script file")
                if any(n.endswith("vbaproject.bin") for n in lname):
                    add("att_macro", 40, "Office file contains VBA macros")
                for i in infos:
                    n = i.filename.lower()
                    if n.endswith(".rels") and i.file_size <= _SMALL_MEMBER:
                        body = zf.read(i)
                        if b"attachedTemplate" in body and b"TargetMode=\"External\"" in body:
                            add("att_remote_template", 30, "Document loads a remote template (template injection)")
                            rep.urls += [m.group(0).decode("latin-1") for m in _URL_RE.finditer(body)][:5]
                            break
        except (zipfile.BadZipFile, RuntimeError, OSError, NotImplementedError):
            add("att_bad_zip", 5, "Archive is corrupted or unreadable")

    elif real == "ole":
        if b"_VBA_PROJECT" in data or b"Macros" in data[:MAX_FILE_BYTES] or b"VBA" in data[:200_000]:
            add("att_macro", 35, "Legacy Office file contains macros")

    elif real == "html":
        text = data[:MAX_FILE_BYTES].lower()
        if re.search(rb"<input[^>]+type\s*=\s*[\"']?password", text):
            add("att_html_login", 45, "HTML attachment contains a login form (offline phishing page)")
        if re.search(rb"(atob\(|unescape\(|eval\(|document\.write\()", text):
            add("att_html_obfuscated", 20, "HTML attachment uses obfuscated script")
        acts = re.findall(rb"<form[^>]+action\s*=\s*[\"']?(https?://[^\"' >]{4,300})", text)
        if acts:
            rep.urls = [a.decode("latin-1") for a in dict.fromkeys(acts)][:5]

    elif real == "rtf" and re.search(rb"\\objdata|\\objautlink", data[:MAX_FILE_BYTES]):
        add("att_rtf_object", 30, "RTF document embeds an object (known exploit vector)")

    rep.points = min(rep.points, 80.0)
    return rep


def analyze_attachments(files: list[tuple[str, bytes]]) -> list[AttachmentReport]:
    out = []
    for name, data in files[:MAX_FILES]:
        if len(data) > MAX_FILE_BYTES:
            r = AttachmentReport(name=name, size=len(data), real_type="too_large")
            r.signals.append(Signal("att_too_large", "attachment", 0, "Attachment too large to inspect"))
            out.append(r)
            continue
        try:
            out.append(analyze_attachment(name, data))
        except Exception:  # noqa: BLE001 - kharab file engine ko crash na kare
            out.append(AttachmentReport(name=name, size=len(data), real_type="unreadable"))
    return out
