"""Encode/decode helpers for XSS parameter obfuscation detection and payload delivery.

Both the parser (detection) and payload generator (auto-encoding) import from here
so the same chains are used on both sides.
"""
from __future__ import annotations

import base64
import codecs
import gzip
import json
from html import unescape as html_unescape
from urllib.parse import quote as url_quote, unquote as url_unquote


# All supported chain identifiers
SUPPORTED_CHAINS: frozenset[str] = frozenset({
    "base64",
    "base64+uuencode",
    "base32",
    "html_entity",
    "url_percent",
    "double_url_percent",
    "gzip+base64",
    "json_string",
    "rot13",
})


def uuencode_line(data: bytes) -> str:
    """UU-encode bytes as a single data line (no begin/end header)."""
    result = chr(32 + len(data))
    i = 0
    while i < len(data):
        chunk = data[i : i + 3]
        padded = chunk + b"\x00" * (3 - len(chunk))
        a, b, c = padded[0], padded[1], padded[2]
        result += chr(((a >> 2) & 0x3F) + 32)
        result += chr((((a & 0x3) << 4) | ((b >> 4) & 0xF)) + 32)
        result += chr((((b & 0xF) << 2) | ((c >> 6) & 0x3)) + 32)
        result += chr((c & 0x3F) + 32)
        i += 3
    return result


def uudecode_line(data: bytes) -> str | None:
    """UU-decode bytes. Returns decoded text or None on failure."""
    try:
        text = data.decode("ascii", errors="replace")
        result = bytearray()
        for line in text.splitlines():
            if not line:
                continue
            expected_len = ord(line[0]) - 32
            if expected_len <= 0:
                break
            decoded = bytearray()
            i = 1
            while i + 3 < len(line):
                a = (ord(line[i])     - 32) & 0x3F
                b = (ord(line[i + 1]) - 32) & 0x3F
                c = (ord(line[i + 2]) - 32) & 0x3F
                d = (ord(line[i + 3]) - 32) & 0x3F
                decoded.append((a << 2) | (b >> 4))
                decoded.append(((b & 0xF) << 4) | (c >> 2))
                decoded.append(((c & 0x3) << 6) | d)
                i += 4
            result += bytes(decoded[:expected_len])
        return result.decode("utf-8", errors="replace") if result else None
    except Exception:
        return None


def encode(raw: str, chain: str) -> str | None:
    """Encode *raw* through *chain*. Returns the encoded string or None on failure.

    The returned value is the raw encoded form (e.g. base64 with ``==`` padding).
    Use :func:`url_safe` to get a version safe for embedding in a query string.
    """
    try:
        if chain == "base64":
            return base64.b64encode(raw.encode()).decode()
        if chain == "base64+uuencode":
            uu_line = uuencode_line(raw.encode()) + "\n" + chr(32) + "\n"
            return base64.b64encode(uu_line.encode()).decode()
        if chain == "base32":
            return base64.b32encode(raw.encode()).decode()
        if chain == "html_entity":
            return "".join(f"&#{ord(c)};" for c in raw)
        if chain == "url_percent":
            return url_quote(raw, safe="")
        if chain == "double_url_percent":
            return url_quote(url_quote(raw, safe=""), safe="")
        if chain == "gzip+base64":
            return base64.b64encode(gzip.compress(raw.encode())).decode()
        if chain == "json_string":
            return json.dumps(raw)
        if chain == "rot13":
            return codecs.encode(raw, "rot_13")
        return None
    except Exception:
        return None


def url_safe(encoded: str) -> str:
    """Percent-encode an already-encoded value so it is safe in a URL query string."""
    return url_quote(encoded, safe="")


def decode(encoded: str, chain: str) -> str | None:
    """Decode *encoded* through *chain*. Returns decoded string or None on failure."""
    try:
        if chain == "base64":
            padding = "=" * ((-len(encoded)) % 4)
            return base64.b64decode(encoded + padding).decode("utf-8", errors="replace")
        if chain == "base64+uuencode":
            padding = "=" * ((-len(encoded)) % 4)
            b64_bytes = base64.b64decode(encoded + padding)
            return uudecode_line(b64_bytes)
        if chain == "base32":
            padding = "=" * ((-len(encoded)) % 8)
            return base64.b32decode(encoded.upper() + padding).decode("utf-8", errors="replace")
        if chain == "html_entity":
            return html_unescape(encoded)
        if chain == "url_percent":
            return url_unquote(encoded)
        if chain == "double_url_percent":
            return url_unquote(url_unquote(encoded))
        if chain == "gzip+base64":
            padding = "=" * ((-len(encoded)) % 4)
            return gzip.decompress(base64.b64decode(encoded + padding)).decode("utf-8", errors="replace")
        if chain == "json_string":
            parsed = json.loads(encoded)
            return str(parsed) if isinstance(parsed, str) else None
        if chain == "rot13":
            return codecs.decode(encoded, "rot_13")
        return None
    except Exception:
        return None


def decode_candidates(raw_value: str) -> list[tuple[str, str]]:
    """Try all chains against *raw_value*. Returns (decoded_text, chain) pairs.

    Only returns results where:
    - The decoded text is printable, non-empty, and >= 4 chars.
    - For identity-like transforms (url_percent, html_entity, rot13) the decoded
      value must actually differ from the input — otherwise it's just plain text
      with no real encoding applied.
    """
    results: list[tuple[str, str]] = []

    def _add(text: str | None, chain: str, *, must_differ: bool = False) -> None:
        if not text:
            return
        stripped = text.strip()
        if len(stripped) < 4 or not stripped.isprintable():
            return
        if must_differ and stripped == raw_value.strip():
            return
        results.append((stripped, chain))

    # Structural encoding chains — decoded value is always different from input
    _add(decode(raw_value, "base64"), "base64")
    _add(decode(raw_value, "base64+uuencode"), "base64+uuencode")
    _add(decode(raw_value, "base32"), "base32")
    _add(decode(raw_value, "gzip+base64"), "gzip+base64")
    _add(decode(raw_value, "json_string"), "json_string")

    # Identity-like chains — only meaningful when decoding actually changes the value
    _add(decode(raw_value, "html_entity"), "html_entity", must_differ=True)
    _add(decode(raw_value, "url_percent"), "url_percent", must_differ=True)
    _add(decode(raw_value, "double_url_percent"), "double_url_percent", must_differ=True)
    _add(decode(raw_value, "rot13"), "rot13", must_differ=True)

    return results
