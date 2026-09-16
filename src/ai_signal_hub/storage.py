from __future__ import annotations

import hashlib
import re
import uuid
from pathlib import Path
from typing import BinaryIO


REPORT_EXTENSIONS = {".pdf", ".html", ".htm", ".docx", ".md", ".txt"}


class UploadTooLarge(ValueError):
    pass


def safe_report_suffix(filename: str | None) -> str:
    suffix = Path(filename or "").suffix.lower()
    if suffix not in REPORT_EXTENSIONS:
        raise ValueError(f"不支持的报告类型: {suffix or '无扩展名'}")
    return suffix


def sanitize_display_name(filename: str | None, fallback: str) -> str:
    name = Path(filename or "").name.strip() or fallback
    return re.sub(r"[\x00-\x1f]", "_", name)[:255]


def stream_to_temporary(source: BinaryIO, temp_dir: Path, max_bytes: int) -> tuple[Path, str, int]:
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_path = temp_dir / f"upload-{uuid.uuid4().hex}.part"
    digest = hashlib.sha256()
    total = 0
    try:
        with temp_path.open("xb") as handle:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise UploadTooLarge(f"上传文件超过 {max_bytes} 字节限制")
                digest.update(chunk)
                handle.write(chunk)
        return temp_path, digest.hexdigest(), total
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def move_without_overwrite(source: Path, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        source.unlink(missing_ok=True)
        return destination
    source.replace(destination)
    return destination
