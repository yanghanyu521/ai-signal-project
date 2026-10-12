from __future__ import annotations

import re
from heapq import merge
from typing import Any

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16LE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
UTF16BE_RE = re.compile(rb"(?:\x00[\x20-\x7e]){4,}")
UTF16_CJK_LE_RE = re.compile(rb"(?:[\x00-\xff][\x4e-\x9f]){4,}")
UTF16_CJK_BE_RE = re.compile(rb"(?:[\x4e-\x9f][\x00-\xff]){4,}")
UTF8_RE = re.compile(rb"(?:[\x20-\x7e]|[\xc2-\xf4][\x80-\xbf]{1,3}){4,}")


def _clean(value: str, max_chars: int) -> str:
    return value[:max_chars]


def extract_strings(data: bytes, max_strings: int, max_chars: int) -> list[dict[str, Any]]:
    return scan_strings(data, max_strings, max_chars)[0]


def scan_strings(data: bytes, max_strings: int, max_chars: int, *,
                 include_cjk: bool = False) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Scan every supported encoding; select by byte offset, not encoding order.

    The cap limits material retained, never how much of the input is scanned.
    Consequently callers can distinguish extraction coverage from retention.
    """
    found: list[dict[str, Any]] = []
    seen_at_offset: set[str] = set()
    current_offset = -1
    patterns = (("ascii", ASCII_RE), ("utf8", UTF8_RE),
                ("utf16le", UTF16LE_RE), ("utf16be", UTF16BE_RE))
    if include_cjk:
        patterns += (("utf16le_cjk", UTF16_CJK_LE_RE), ("utf16be_cjk", UTF16_CJK_BE_RE))
    def matches(priority: int, encoding: str, pattern: re.Pattern[bytes]):
        for match in pattern.finditer(data):
            yield (match.start(), priority, encoding, match)

    streams = (matches(priority, encoding, pattern)
               for priority, (encoding, pattern) in enumerate(patterns))
    # heapq.merge never materializes every regex match at once.
    total = 0
    by_encoding = {name: 0 for name, _ in patterns}
    retained_by_encoding = {name: 0 for name, _ in patterns}
    for offset, _, encoding, match in merge(*streams):
        codec = {"ascii": "ascii", "utf8": "utf-8", "utf16le": "utf-16le", "utf16be": "utf-16be",
                 "utf16le_cjk": "utf-16le", "utf16be_cjk": "utf-16be"}[encoding]
        value = match.group().decode(codec, errors="replace")
        if offset != current_offset:
            current_offset = offset
            seen_at_offset.clear()
        if value in seen_at_offset:
            continue
        seen_at_offset.add(value)
        total += 1
        by_encoding[encoding] += 1
        if len(found) < max_strings:
            found.append({"encoding": encoding, "offset": offset, "value": _clean(value, max_chars)})
            retained_by_encoding[encoding] += 1
    return found, {"bytes_scanned": len(data), "strings_discovered": total,
                   "strings_retained": len(found), "strings_rejected_by_limit": total - len(found),
                   "strings_by_encoding": by_encoding,
                   "strings_retained_by_encoding": retained_by_encoding,
                   "retention_rate": round(len(found) / total, 6) if total else None}


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
