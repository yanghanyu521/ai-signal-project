from __future__ import annotations

import hashlib
import io
import math
import zipfile
from pathlib import Path
from typing import Any

try:
    import magic  # type: ignore
except ImportError:  # pragma: no cover - optional for local unit tests
    magic = None


def _digest(data: bytes, algorithm: str) -> str:
    return hashlib.new(algorithm, data).hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return round(-sum((count / length) * math.log2(count / length) for count in counts if count), 4)


def detect_format(data: bytes) -> str:
    """Recognize containers from bytes, independent of host libmagic or filename."""
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data[:4] in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}:
        return "mach_o"
    if data.startswith(b"dex\n"):
        return "dex"
    if data.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = set(archive.namelist())
            if "AndroidManifest.xml" in names or "classes.dex" in names:
                return "apk"
        except (zipfile.BadZipFile, OSError, RuntimeError):
            pass
        return "zip"
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data[:4] in {b"\x42\x0d\x0d\x0a", b"\x6f\x0d\x0d\x0a"}:
        return "python_bytecode"
    return "text" if data and b"\x00" not in data[:4096] else "unknown_binary"


def detect_language(data: bytes, file_type: str, file_name: str = "") -> tuple[str | None, str]:
    head = data[:262144]
    lowered = head.lower()
    # A binary header/file magic is authoritative. Embedded strings must never
    # turn an executable into a source-language classification.
    if detect_format(data) in {"pe", "elf", "mach_o", "apk", "dex", "zip", "pdf", "python_bytecode", "unknown_binary"} or any(marker in file_type for marker in ("PE32", "ELF", "Mach-O", "MS-DOS")):
        return None, "strings_only"
    if not head:
        return None, "unknown"
    printable = sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in head)
    if printable / len(head) < 0.85:
        return None, "strings_only"
    # An extension is a source hint only after the byte-level binary guard.
    suffix = Path(file_name).suffix.casefold()
    if suffix == ".py":
        return "python", "original_source"
    if suffix in {".js", ".mjs", ".cjs", ".jsx"}:
        return "javascript", "original_source"
    if suffix in {".ps1", ".psm1"}:
        return "powershell", "original_source"
    if (b"#!/" in head[:128] and b"python" in head[:256]) or b"def " in head or b"import " in head:
        return "python", "original_source"
    if b"node" in lowered[:256] or b"require(" in lowered or b"module.exports" in lowered:
        return "javascript", "original_source"
    if b"powershell" in lowered[:512] or b"param(" in lowered or (b"$" in head and b"function" in lowered):
        return "powershell", "original_source"
    if b"createobject(" in lowered or b"wscript." in lowered or b"dim " in lowered:
        return "vbscript", "original_source"
    if "PE32" in file_type or "MS-DOS" in file_type:
        return None, "strings_only"
    if "ELF" in file_type:
        return None, "strings_only"
    return None, "unknown"


def collect_metadata_from_data(data: bytes, file_name: str, max_file_bytes: int) -> dict[str, Any]:
    """Build metadata from already-read bytes without interpreting their content."""
    size = len(data)
    if size > max_file_bytes:
        raise ValueError(f"sample exceeds configured size limit ({size} > {max_file_bytes})")
    file_type = magic.from_buffer(data, mime=False) if magic else "unknown (python-magic unavailable)"
    language, recoverability = detect_language(data, file_type, file_name)
    return {
        "sha256": _digest(data, "sha256"),
        "sha1": _digest(data, "sha1"),
        "md5": _digest(data, "md5"),
        "size": size,
        "file_name": file_name,
        "file_type": file_type,
        "format": detect_format(data),
        "entropy": shannon_entropy(data),
        "language": language,
        "recoverability": recoverability,
    }


def collect_metadata(sample: Path, max_file_bytes: int) -> tuple[dict[str, Any], bytes]:
    data = sample.read_bytes()
    return collect_metadata_from_data(data, sample.name, max_file_bytes), data
