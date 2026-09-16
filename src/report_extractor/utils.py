from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def stable_id(prefix: str, *parts: object, length: int = 20) -> str:
    raw = "\x1f".join(str(part) for part in parts)
    return f"{prefix}:{sha256_text(raw)[:length]}"


def normalize_space(value: str | None) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def normalize_url(value: str | None) -> str | None:
    value = normalize_space(value)
    if not value:
        return None
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    port = parts.port
    netloc = host
    if port and not ((parts.scheme.lower() == "http" and port == 80) or (parts.scheme.lower() == "https" and port == 443)):
        netloc = f"{host}:{port}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def virus_total_sha256(url: str | None) -> str | None:
    if not url:
        return None
    parts = urlsplit(url)
    if (parts.hostname or "").lower() not in {"virustotal.com", "www.virustotal.com"}:
        return None
    match = re.search(r"/file/([a-fA-F0-9]{64})(?:/|$)", parts.path)
    return match.group(1).lower() if match else None


def ensure_public_http_url(url: str) -> str:
    normalized = normalize_url(url)
    if not normalized:
        raise ValueError("只允许有效的 HTTP(S) URL")
    host = urlsplit(normalized).hostname
    assert host
    if host.lower() == "localhost" or host.lower().endswith(".local"):
        raise ValueError("禁止访问本机或本地域名")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
    except socket.gaierror as exc:
        raise ValueError(f"域名解析失败: {host}") from exc
    if not addresses:
        raise ValueError(f"域名没有可用地址: {host}")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError(f"禁止访问非公网地址: {address}")
    return normalized


def write_json(path: str | Path, value: object) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def read_json(path: str | Path) -> object:
    return json.loads(Path(path).read_text(encoding="utf-8"))
