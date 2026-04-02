"""
modules/file_analysis.py — File Analysis core logic for Obsidian Circuit
Extracts metadata, computes hashes, checks permissions, flags suspicious indicators
"""
import os
import hashlib
import stat
import mimetypes
import platform
from datetime import datetime
from pathlib import Path
import tempfile


# --- Known dangerous MIME types ---
DANGEROUS_MIME = {
    "application/x-dosexec", "application/x-executable",
    "application/x-sharedlib", "application/x-msdownload",
    "application/x-sh", "application/x-shellscript",
    "application/x-bat", "application/x-msdos-program",
}

# --- Extension → expected MIME mappings for mismatch detection ---
EXTENSION_MIME_MAP = {
    ".pdf":  ["application/pdf"],
    ".jpg":  ["image/jpeg"],
    ".jpeg": ["image/jpeg"],
    ".png":  ["image/png"],
    ".gif":  ["image/gif"],
    ".zip":  ["application/zip"],
    ".docx": ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
    ".xlsx": ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
    ".mp4":  ["video/mp4"],
    ".mp3":  ["audio/mpeg"],
    ".txt":  ["text/plain"],
    ".html": ["text/html"],
    ".xml":  ["application/xml", "text/xml"],
}



def compute_entropy(data: bytes) -> float:
    """Compute Shannon entropy of bytes (0–8 bits per byte)."""
    import math
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def interpret_entropy(entropy: float) -> tuple:
    """Return (label, color) based on entropy value."""
    if entropy >= 7.5:
        return "High — Likely Encrypted/Packed/Compressed", "#ff3333"
    elif entropy >= 6.0:
        return "Elevated — May contain binary or obfuscated data", "#ff9900"
    elif entropy >= 4.0:
        return "Normal — Typical file content", "#00ff9f"
    else:
        return "Low — Mostly plain text or sparse data", "#00d4ff"


def compute_hashes(file_bytes: bytes) -> dict:
    """Compute MD5, SHA1, SHA256 hashes of raw bytes."""
    return {
        "md5":    hashlib.md5(file_bytes).hexdigest(),
        "sha1":   hashlib.sha1(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
    }


def detect_mime(filename: str, file_bytes: bytes) -> str:
    """Detect MIME type using python-magic if available, else fallback to mimetypes."""
    try:
        import magic
        mime_type = magic.from_buffer(file_bytes, mime=True)
        return mime_type
    except Exception:
        pass
    mime, _ = mimetypes.guess_type(filename)
    return mime or "application/octet-stream"


def analyze_file(uploaded_file) -> dict:
    """
    Full analysis of an uploaded Streamlit file object.
    Returns structured findings dict.
    """
    import re as _re
    filename   = uploaded_file.name
    file_bytes = uploaded_file.read()
    file_size  = len(file_bytes)
    ext        = Path(filename).suffix.lower()

    # Hashes
    hashes = compute_hashes(file_bytes)

    # Entropy & printable ratio
    entropy = compute_entropy(file_bytes)
    printable_count = sum(1 for b in file_bytes if 32 <= b <= 126)
    printable_ratio = round(printable_count / max(file_size, 1) * 100, 1)

    # MIME detection
    detected_mime = detect_mime(filename, file_bytes)

    # Embedded URLs and IPs (scan first 50KB of text representation)
    try:
        text_repr = file_bytes[:50000].decode("utf-8", errors="replace")
        embedded_urls = list(set(_re.findall(r'https?://[^\s\'"<>]{4,100}', text_repr, _re.I)))[:20]
        embedded_ips  = list(set(_re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text_repr)))[:20]
    except Exception:
        embedded_urls = []
        embedded_ips  = []

    # Hex dump — first 64 bytes
    hex_lines = []
    for i in range(0, min(64, file_size), 16):
        row = file_bytes[i:i+16]
        hex_p   = " ".join(f"{b:02x}" for b in row)
        ascii_p = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        hex_lines.append(f"{i:04x}  {hex_p:<47}  {ascii_p}")
    hex_dump = "\n".join(hex_lines)

    # Write to temp for stat() calls
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        file_stat = os.stat(tmp_path)
        permissions = oct(stat.S_IMODE(file_stat.st_mode))
        size_on_disk = file_stat.st_size
        is_world_writable = bool(file_stat.st_mode & stat.S_IWOTH)
        is_executable = bool(file_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    except Exception:
        permissions = "N/A"
        size_on_disk = file_size
        is_world_writable = False
        is_executable = False
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    # --- Suspicious flag analysis ---
    flags = []

    # 1. MIME mismatch
    expected_mimes = EXTENSION_MIME_MAP.get(ext, [])
    mime_mismatch = bool(expected_mimes) and detected_mime not in expected_mimes
    if mime_mismatch:
        flags.append({
            "severity": "CRITICAL",
            "title": "MIME Type Mismatch",
            "description": f"File extension '{ext}' suggests {expected_mimes[0] if expected_mimes else 'unknown'}, "
                         f"but detected MIME is '{detected_mime}'. This is a common malware masquerading technique.",
            "recommendation": "Do not open or execute this file. Investigate further with a sandbox.",
        })

    # 2. Dangerous MIME type
    if detected_mime in DANGEROUS_MIME:
        flags.append({
            "severity": "WARNING",
            "title": "Executable/Script Content Detected",
            "description": f"MIME type '{detected_mime}' indicates this file is executable or a script.",
            "recommendation": "Verify the source and whether execution is expected. Scan with antivirus.",
        })

    # 3. World-writable permissions (unix)
    if is_world_writable:
        flags.append({
            "severity": "WARNING",
            "title": "World-Writable Permissions",
            "description": f"File has permissions {permissions} — any user can modify it.",
            "recommendation": "Restrict permissions to owner only: chmod 600 or 644.",
        })

    # 4. Executable flag
    if is_executable and ext not in [".exe", ".dll", ".so", ".bat", ".sh", ".bin"]:
        flags.append({
            "severity": "WARNING",
            "title": "Unexpected Executable Bit",
            "description": f"File '{filename}' has executable permissions but its extension is '{ext}'.",
            "recommendation": "Confirm if execution is intentional for this file type.",
        })

    # 5. Large file size
    if file_size > 50 * 1024 * 1024:
        flags.append({
            "severity": "INFO",
            "title": "Large File Size",
            "description": f"File is {file_size / (1024*1024):.1f} MB, which is unusually large for a {ext} file.",
            "recommendation": "Review file contents; large files can conceal data or be bloated malware.",
        })

    # 6. Zero-byte file
    if file_size == 0:
        flags.append({
            "severity": "INFO",
            "title": "Empty File",
            "description": "This file is zero bytes. It may be a placeholder, error, or decoy.",
            "recommendation": "Verify why this file exists in the investigation scope.",
        })

    # 7. Magic bytes check for common formats
    magic_mismatch = _check_magic_bytes(file_bytes, ext)
    if magic_mismatch:
        flags.append({
            "severity": "CRITICAL",
            "title": "Magic Bytes Mismatch",
            "description": magic_mismatch,
            "recommendation": "This file's internal signature doesn't match its extension — strong indicator of disguised malware.",
        })

    if not flags:
        flags.append({
            "severity": "SAFE",
            "title": "No Suspicious Indicators Found",
            "description": "File metadata, MIME type, and permissions appear normal.",
            "recommendation": "Always verify the file source regardless of automated scan results.",
        })

    overall_severity = "SAFE"
    if any(f["severity"] == "CRITICAL" for f in flags):
        overall_severity = "CRITICAL"
    elif any(f["severity"] == "WARNING" for f in flags):
        overall_severity = "WARNING"
    elif any(f["severity"] == "INFO" for f in flags):
        overall_severity = "INFO"

    return {
        "filename":         filename,
        "extension":        ext,
        "file_size":        file_size,
        "detected_mime":    detected_mime,
        "permissions":      permissions,
        "is_world_writable": is_world_writable,
        "is_executable":    is_executable,
        "hashes":           hashes,
        "entropy":          entropy,
        "printable_ratio":  printable_ratio,
        "embedded_urls":    embedded_urls,
        "embedded_ips":     embedded_ips,
        "hex_dump":         hex_dump,
        "flags":            flags,
        "overall_severity": overall_severity,
        "flag_count":       len([f for f in flags if f["severity"] != "SAFE"]),
    }


MAGIC_BYTES = {
    ".pdf":  (b"%PDF", "PDF"),
    ".png":  (b"\x89PNG", "PNG"),
    ".jpg":  (b"\xff\xd8\xff", "JPEG"),
    ".gif":  (b"GIF8", "GIF"),
    ".zip":  (b"PK\x03\x04", "ZIP"),
    ".exe":  (b"MZ", "PE Executable"),
    ".elf":  (b"\x7fELF", "ELF Executable"),
}


def _check_magic_bytes(file_bytes: bytes, ext: str) -> str | None:
    """Return mismatch description if magic bytes don't match extension."""
    if not file_bytes:
        return None
    expected = MAGIC_BYTES.get(ext)
    if expected is None:
        return None
    magic_sig, fmt_name = expected
    if not file_bytes[:len(magic_sig)] == magic_sig:
        # Check if it matches a DIFFERENT known format
        for other_ext, (other_sig, other_name) in MAGIC_BYTES.items():
            if other_ext != ext and file_bytes[:len(other_sig)] == other_sig:
                return (f"File starts with {other_name} signature (magic bytes) "
                        f"but has extension '{ext}'. It appears to be a {other_name} "
                        f"disguised as {fmt_name}.")
    return None
