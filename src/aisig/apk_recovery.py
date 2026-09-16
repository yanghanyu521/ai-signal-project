from __future__ import annotations

"""Static-only APK member scanning.

APK files are ZIP containers. This module reads bounded archive members with
``zipfile`` and extracts strings/features from their bytes; it never installs,
loads, executes, imports, or decompiles Android code. Recovered bytes exist
only in memory and are never written to analysis artifacts.
"""

import copy
import hashlib
import zipfile
from pathlib import Path
from typing import Any

from .prompt import extract_prompt_features
from .string_extract import extract_strings
from .toolchain import extract_toolchain


def is_apk(sample: Path, metadata: dict[str, Any]) -> bool:
    """Identify an Android APK through file type and archive metadata only."""
    if "Android package (APK)" in str(metadata.get("file_type", "")):
        return True
    try:
        with zipfile.ZipFile(sample) as archive:
            return "AndroidManifest.xml" in archive.namelist()
    except (OSError, zipfile.BadZipFile):
        return False


def _member_kind(name: str) -> str:
    suffix = Path(name).suffix.lower().lstrip(".")
    return suffix if suffix and suffix.isalnum() else "member"


def _mark(item: dict[str, Any], member_name: str, member_data: bytes) -> dict[str, Any]:
    """Keep only a member kind and hash in evidence provenance, never its path."""
    marked = copy.deepcopy(item)
    original_source = marked.get("source", "recovered")
    member_hash = hashlib.sha256(member_data).hexdigest()
    marked["source"] = f"recovered_apk:{_member_kind(member_name)}:{original_source}"
    marked["recovery_origin"] = {
        "layer": "apk_member_scan",
        "member_sha256": member_hash,
        "member_kind": _member_kind(member_name),
    }
    return marked


def recover_and_analyze_apk(sample: Path, config: dict[str, Any], rules: dict[str, Any]) -> dict[str, Any]:
    """Statically scan bounded APK members and return structured evidence only."""
    max_members = int(config.get("apk_max_members", 5000))
    max_member_bytes = int(config.get("apk_max_member_bytes", 32 * 1024 * 1024))
    max_total_bytes = int(config.get("apk_max_total_bytes", 120 * 1024 * 1024))
    max_ratio = int(config.get("apk_max_compression_ratio", 200))
    evidence: list[dict[str, Any]] = []
    prompts: list[dict[str, Any]] = []
    prompt_hashes: set[str] = set()
    special_tokens: list[dict[str, Any]] = []
    structural_artifacts: list[dict[str, Any]] = []
    structural = {name: False for name in rules.get("prompt_patterns", {})}
    scanned = skipped = scanned_bytes = 0

    try:
        with zipfile.ZipFile(sample) as archive:
            members = [entry for entry in archive.infolist() if not entry.is_dir()]
            for entry in members:
                ratio = entry.file_size / max(entry.compress_size, 1)
                if (
                    scanned >= max_members
                    or entry.file_size > max_member_bytes
                    or scanned_bytes + entry.file_size > max_total_bytes
                    or ratio > max_ratio
                ):
                    skipped += 1
                    continue
                data = archive.read(entry)
                scanned += 1
                scanned_bytes += len(data)
                strings = extract_strings(data, config["max_strings"], config["max_string_chars"])
                current_toolchain = extract_toolchain(strings, rules, {"file_type": "apk_member", "language": None}, data)
                existing_evidence = {(item.get("type"), item.get("rule_id"), item.get("value")) for item in evidence}
                for item in current_toolchain.get("evidence", []):
                    marked = _mark(item, entry.filename, data)
                    key = (marked.get("type"), marked.get("rule_id"), marked.get("value"))
                    if key not in existing_evidence:
                        evidence.append(marked)
                        existing_evidence.add(key)

                current_prompt = extract_prompt_features(strings, rules, config["max_prompt_candidates"], data)
                for item in current_prompt.get("embedded_prompts", []):
                    if len(prompts) >= config["max_prompt_candidates"]:
                        break
                    marked = _mark(item, entry.filename, data)
                    text_hash = marked.get("text_hash")
                    if text_hash and text_hash not in prompt_hashes:
                        prompts.append(marked)
                        prompt_hashes.add(text_hash)
                        for name in marked.get("features", {}):
                            structural[name] = True
                special_tokens.extend(_mark(item, entry.filename, data) for item in current_prompt.get("special_tokens", []))
                structural_artifacts.extend(
                    _mark(item, entry.filename, data)
                    for item in current_prompt.get("structural_artifacts", [])
                )
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        return {"status": "scan_failed", "message": f"{type(exc).__name__}: {exc}"}

    return {
        "status": "scanned",
        "member_count": len(members),
        "members_scanned": scanned,
        "members_skipped": skipped,
        "bytes_scanned": scanned_bytes,
        "limits": {
            "max_members": max_members,
            "max_member_bytes": max_member_bytes,
            "max_total_bytes": max_total_bytes,
            "max_compression_ratio": max_ratio,
        },
        "features": {
            "toolchain": {"evidence": evidence},
            "prompt": {
                "embedded_prompts": prompts,
                "structural_features": structural,
                "structural_artifacts": structural_artifacts,
                "special_tokens": special_tokens,
            },
        },
    }


def merge_apk_features(
    parent_toolchain: dict[str, Any],
    parent_prompt: dict[str, Any],
    recovery: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Merge APK-member evidence into the parent sample without source content."""
    if recovery.get("status") != "scanned":
        return parent_toolchain, parent_prompt
    toolchain = copy.deepcopy(parent_toolchain)
    prompt = copy.deepcopy(parent_prompt)
    existing_evidence = {
        (item.get("type"), item.get("rule_id"), item.get("value"))
        for item in toolchain.get("evidence", [])
    }
    for item in recovery["features"]["toolchain"].get("evidence", []):
        key = (item.get("type"), item.get("rule_id"), item.get("value"))
        if key not in existing_evidence:
            toolchain.setdefault("evidence", []).append(item)
            existing_evidence.add(key)

    prompt.setdefault("embedded_prompts", [])
    existing_prompts = {item.get("text_hash") for item in prompt["embedded_prompts"]}
    for item in recovery["features"]["prompt"].get("embedded_prompts", []):
        if item.get("text_hash") not in existing_prompts:
            prompt["embedded_prompts"].append(item)
            existing_prompts.add(item.get("text_hash"))
    structural = prompt.setdefault("structural_features", {})
    for name, value in recovery["features"]["prompt"].get("structural_features", {}).items():
        structural[name] = bool(structural.get(name) or value)
    prompt.setdefault("structural_artifacts", [])
    known_artifacts = {
        (item.get("type"), item.get("value"), item.get("offset"), item.get("source"))
        for item in prompt["structural_artifacts"]
    }
    for item in recovery["features"]["prompt"].get("structural_artifacts", []):
        key = (item.get("type"), item.get("value"), item.get("offset"), item.get("source"))
        if key not in known_artifacts:
            prompt["structural_artifacts"].append(item)
            known_artifacts.add(key)
    prompt["special_tokens"] = list(dict.fromkeys(prompt.get("special_tokens", []) + recovery["features"]["prompt"].get("special_tokens", [])))
    return toolchain, prompt
