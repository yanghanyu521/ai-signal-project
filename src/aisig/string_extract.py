from __future__ import annotations

import re
from typing import Any

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16LE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
UTF16BE_RE = re.compile(rb"(?:\x00[\x20-\x7e]){4,}")
UTF8_RE = re.compile(rb"(?:[\x20-\x7e]|[\xc2-\xf4][\x80-\xbf]{1,3}){4,}")


def _clean(value: str, max_chars: int) -> str:
    return value[:max_chars]


def extract_strings(data: bytes, max_strings: int, max_chars: int) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for encoding, pattern in (("ascii", ASCII_RE), ("utf8", UTF8_RE),
                              ("utf16le", UTF16LE_RE), ("utf16be", UTF16BE_RE)):
        for match in pattern.finditer(data):
            if len(found) >= max_strings:
                return found
            codec = {"ascii": "ascii", "utf8": "utf-8", "utf16le": "utf-16le", "utf16be": "utf-16be"}[encoding]
            value = match.group().decode(codec, errors="replace")
            key = (match.start(), value)
            if key in seen:
                continue
            seen.add(key)
            found.append({"encoding": encoding, "offset": match.start(), "value": _clean(value, max_chars)})
    return sorted(found, key=lambda item: item["offset"])


def source_text(data: bytes, language: str | None) -> tuple[str | None, str | None]:
    if language is None:
        return None, None
    for encoding in ("utf-8", "utf-8-sig", "utf-16le"):
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        printable = sum(char.isprintable() or char in "\r\n\t" for char in text)
        if text and printable / len(text) >= 0.90:
            return text, encoding
    return None, None
