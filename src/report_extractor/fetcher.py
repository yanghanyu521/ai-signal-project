from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin

import requests

from .utils import ensure_public_http_url, sha256_bytes, utc_now, write_json


ALLOWED_CONTENT_TYPES = {
    "text/html": ".html",
    "application/pdf": ".pdf",
    "text/plain": ".txt",
    "application/xhtml+xml": ".html",
}


@dataclass(frozen=True)
class FetchLimits:
    max_bytes: int = 20 * 1024 * 1024
    max_redirects: int = 5
    timeout_seconds: int = 30


def fetch_public_report(url: str, output_dir: str | Path, limits: FetchLimits | None = None) -> dict:
    limits = limits or FetchLimits()
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    session = requests.Session()
    session.headers["User-Agent"] = "ZTW-Report-Extractor/0.1 (+public-report-research)"
    current = ensure_public_http_url(url)
    response = None
    history: list[str] = []
    for _ in range(limits.max_redirects + 1):
        response = session.get(current, timeout=limits.timeout_seconds, stream=True, allow_redirects=False)
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            if not location:
                raise ValueError("重定向响应缺少 Location")
            history.append(current)
            current = ensure_public_http_url(urljoin(current, location))
            continue
        break
    else:
        raise ValueError("重定向次数超过限制")
    assert response is not None
    response.raise_for_status()
    content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if content_type not in ALLOWED_CONTENT_TYPES:
        raise ValueError(f"不支持的报告 MIME 类型: {content_type or 'unknown'}")
    declared = response.headers.get("Content-Length")
    if declared and int(declared) > limits.max_bytes:
        raise ValueError("报告超过大小限制")
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        size += len(chunk)
        if size > limits.max_bytes:
            raise ValueError("报告流超过大小限制")
        chunks.append(chunk)
    data = b"".join(chunks)
    digest = sha256_bytes(data)
    source_path = out / f"source{ALLOWED_CONTENT_TYPES[content_type]}"
    source_path.write_bytes(data)
    metadata = {
        "requested_url": url,
        "canonical_url": current,
        "redirect_history": history,
        "retrieved_at": utc_now(),
        "status_code": response.status_code,
        "content_type": content_type,
        "content_length": len(data),
        "content_sha256": digest,
        "source_path": str(source_path.resolve()),
    }
    write_json(out / "fetch.json", metadata)
    return metadata
