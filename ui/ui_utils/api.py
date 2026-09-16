from __future__ import annotations

from typing import Any

import httpx
import streamlit as st


class ApiError(RuntimeError):
    pass


def _raise(response: httpx.Response) -> None:
    try:
        detail = response.json().get("detail")
    except Exception:
        detail = response.text
    raise ApiError(f"API {response.status_code}: {detail or '请求失败'}")


@st.cache_data(ttl="10s", max_entries=100, show_spinner=False)
def get_json(base_url: str, path: str, params: tuple[tuple[str, Any], ...] = ()) -> Any:
    try:
        response = httpx.get(f"{base_url.rstrip('/')}{path}", params=dict(params), timeout=30)
    except httpx.HTTPError as exc:
        raise ApiError(f"无法连接 API: {exc}") from exc
    if not response.is_success:
        _raise(response)
    return response.json()


def post_json(base_url: str, path: str, payload: dict[str, Any]) -> Any:
    try:
        response = httpx.post(f"{base_url.rstrip('/')}{path}", json=payload, timeout=120)
    except httpx.HTTPError as exc:
        raise ApiError(f"无法连接 API: {exc}") from exc
    if not response.is_success:
        _raise(response)
    get_json.clear()
    return response.json()


def patch_json(base_url: str, path: str, payload: dict[str, Any]) -> Any:
    try:
        response = httpx.patch(f"{base_url.rstrip('/')}{path}", json=payload, timeout=30)
    except httpx.HTTPError as exc:
        raise ApiError(f"无法连接 API: {exc}") from exc
    if not response.is_success:
        _raise(response)
    get_json.clear()
    return response.json()


def post_file(
    base_url: str,
    path: str,
    *,
    filename: str,
    content: bytes,
    data: dict[str, Any],
) -> Any:
    try:
        response = httpx.post(
            f"{base_url.rstrip('/')}{path}",
            files={"file": (filename, content, "application/octet-stream")},
            data={key: str(value).lower() if isinstance(value, bool) else value for key, value in data.items() if value not in (None, "")},
            timeout=600,
        )
    except httpx.HTTPError as exc:
        raise ApiError(f"无法连接 API: {exc}") from exc
    if not response.is_success:
        _raise(response)
    get_json.clear()
    return response.json()


def post_files(
    base_url: str,
    path: str,
    *,
    files: dict[str, tuple[str, bytes, str]],
    data: dict[str, Any],
) -> Any:
    try:
        response = httpx.post(
            f"{base_url.rstrip('/')}{path}",
            files=files or None,
            data={key: str(value).lower() if isinstance(value, bool) else value for key, value in data.items() if value not in (None, "")},
            timeout=900,
        )
    except httpx.HTTPError as exc:
        raise ApiError(f"无法连接 API: {exc}") from exc
    if not response.is_success:
        _raise(response)
    get_json.clear()
    return response.json()


def api_base_url() -> str:
    return st.session_state["api_base_url"].rstrip("/")
