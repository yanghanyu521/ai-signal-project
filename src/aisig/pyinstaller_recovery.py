from __future__ import annotations

"""Static-only PyInstaller recovery.

This module stages a copy of an already supplied PE in a temporary directory,
uses extraction/decompilation tools with argument lists (never a shell), and
returns only structured features. It never executes, imports, or evaluates the
input payload or recovered Python code.
"""

import copy
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

from .code_style import analyze_code_style
from .ingest import collect_metadata_from_data
from .prompt import extract_prompt_features
from .string_extract import extract_strings, source_text
from .toolchain import extract_toolchain

PYINSTALLER_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"


def is_pyinstaller(strings: list[dict[str, Any]], raw_data: bytes, toolchain: dict[str, Any]) -> bool:
    """Identify PyInstaller through static markers only."""
    if "PyInstaller" in toolchain.get("packaging_candidates", []):
        return True
    if PYINSTALLER_MAGIC in raw_data:
        return True
    return any("pyinstaller" in item.get("value", "").lower() for item in strings)


def _entrypoint_from_info(text: str) -> str | None:
    match = re.search(r"(?im)^\s*(?:\[\+\]\s*)?entry\s*points?\s*:\s*([^\r\n]+)", text)
    if not match:
        return None
    # pyinstxtractor-ng commonly emits several boot modules followed by the
    # application entry point. The final comma-separated value is the target.
    value = Path(match.group(1).split(",")[-1].strip().replace("\\", "/")).name
    if not value:
        return None
    return value if value.lower().endswith(".pyc") else f"{value}.pyc"


def _run(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        shell=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def _analysis_from_recovered_text(
    recovered: bytes,
    source_name: str,
    config: dict[str, Any],
    rules: dict[str, Any],
) -> dict[str, Any]:
    metadata = collect_metadata_from_data(recovered, source_name, config["max_file_bytes"])
    metadata["language"] = "python"
    metadata["recoverability"] = "recovered_source"
    strings = extract_strings(recovered, config["max_strings"], config["max_string_chars"])
    toolchain = extract_toolchain(strings, rules, metadata, recovered)
    prompt = extract_prompt_features(strings, rules, config["max_prompt_candidates"], recovered)
    text, encoding = source_text(recovered, "python")
    if encoding:
        metadata["source_encoding"] = encoding
    return {
        "metadata": metadata,
        "toolchain": toolchain,
        "prompt": prompt,
        "code_style": analyze_code_style(text, "python", "recovered_source"),
    }


def _mark_recovered(item: dict[str, Any], entrypoint: str, recovered_sha256: str) -> dict[str, Any]:
    marked = copy.deepcopy(item)
    original_source = marked.get("source", "recovered")
    marked["source"] = f"recovered_pyinstaller:{entrypoint}:{original_source}"
    marked["recovery_origin"] = {
        "layer": "pyinstaller_recovered_entry",
        "entrypoint": entrypoint,
        "recovered_source_sha256": recovered_sha256,
    }
    return marked


def merge_recovered_features(
    parent_toolchain: dict[str, Any],
    parent_prompt: dict[str, Any],
    parent_code_style: dict[str, Any],
    recovery: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Merge recovered direct/strong evidence back into the parent feature set."""
    if recovery.get("status") != "recovered":
        return parent_toolchain, parent_prompt, parent_code_style

    entrypoint = recovery["entrypoint"]
    recovered_sha256 = recovery["recovered_source_sha256"]
    recovered = recovery["features"]
    toolchain = copy.deepcopy(parent_toolchain)
    prompt = copy.deepcopy(parent_prompt)
    code_style = copy.deepcopy(parent_code_style)

    existing = {
        (item.get("type"), item.get("value"), item.get("source"), item.get("offset"))
        for item in toolchain.get("evidence", [])
    }
    for item in recovered["toolchain"].get("evidence", []):
        marked = _mark_recovered(item, entrypoint, recovered_sha256)
        key = (marked.get("type"), marked.get("value"), marked.get("source"), marked.get("offset"))
        if key not in existing:
            toolchain.setdefault("evidence", []).append(marked)
            existing.add(key)
    if "PyInstaller" not in toolchain.setdefault("packaging_candidates", []):
        toolchain["packaging_candidates"].append("PyInstaller")

    prompt.setdefault("embedded_prompts", [])
    prompt_hashes = {item.get("text_hash") for item in prompt["embedded_prompts"]}
    for item in recovered["prompt"].get("embedded_prompts", []):
        marked = _mark_recovered(item, entrypoint, recovered_sha256)
        if marked.get("text_hash") not in prompt_hashes:
            prompt["embedded_prompts"].append(marked)
            prompt_hashes.add(marked.get("text_hash"))
    structural = prompt.setdefault("structural_features", {})
    for name, value in recovered["prompt"].get("structural_features", {}).items():
        structural[name] = bool(structural.get(name) or value)
    prompt.setdefault("structural_artifacts", [])
    known_artifacts = {
        (item.get("type"), item.get("value"), item.get("offset"), item.get("source"))
        for item in prompt["structural_artifacts"]
    }
    for item in recovered["prompt"].get("structural_artifacts", []):
        marked = _mark_recovered(item, entrypoint, recovered_sha256)
        key = (marked.get("type"), marked.get("value"), marked.get("offset"), marked.get("source"))
        if key not in known_artifacts:
            prompt["structural_artifacts"].append(marked)
            known_artifacts.add(key)
    prompt["special_tokens"] = list(dict.fromkeys(prompt.get("special_tokens", []) + recovered["prompt"].get("special_tokens", [])))

    code_style.setdefault("recovered_layers", []).append({
        "entrypoint": entrypoint,
        "recovered_source_sha256": recovered_sha256,
        "analysis": recovered["code_style"],
    })
    return toolchain, prompt, code_style


def recover_and_analyze_pyinstaller(
    sample: Path,
    config: dict[str, Any],
    rules: dict[str, Any],
) -> dict[str, Any]:
    """Extract the PyInstaller entry `.pyc`, decompile it, and return static features.

    The return value deliberately contains no recovered source text. Temporary
    files, including staged copies and extractor output, are removed on return.
    """
    extractor = shutil.which("pyinstxtractor-ng")
    decompiler = shutil.which("pycdc")
    if not extractor or not decompiler:
        missing = [name for name, path in (("pyinstxtractor-ng", extractor), ("pycdc", decompiler)) if not path]
        return {"status": "tool_unavailable", "missing_tools": missing}

    timeout = int(config.get("pyinstaller_timeout_seconds", 120))
    with tempfile.TemporaryDirectory(prefix="aisig-pyinstaller-") as directory:
        work = Path(directory)
        staged = work / "input.bin"
        shutil.copyfile(sample, staged)
        os.chmod(staged, 0o400)

        try:
            info = _run([extractor, "--info", str(staged)], work, timeout)
            entrypoint = _entrypoint_from_info(info.stdout)
            extraction = _run([extractor, str(staged)], work, timeout)
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "timeout_seconds": timeout}
        except OSError as exc:
            return {"status": "tool_error", "message": f"{type(exc).__name__}: {exc}"}

        extracted = Path(f"{staged}_extracted")
        if extraction.returncode != 0 or not extracted.is_dir():
            return {"status": "extraction_failed", "extractor_exit_code": extraction.returncode}

        candidates = sorted(extracted.rglob(entrypoint)) if entrypoint else []
        if not candidates:
            return {
                "status": "entrypoint_not_found",
                "entrypoint": entrypoint,
                "extractor_exit_code": extraction.returncode,
            }
        entry_pyc = candidates[0]
        try:
            decompiled = _run([decompiler, str(entry_pyc)], work, timeout)
        except subprocess.TimeoutExpired:
            return {"status": "decompilation_timeout", "entrypoint": entry_pyc.name, "timeout_seconds": timeout}
        except OSError as exc:
            return {"status": "tool_error", "message": f"{type(exc).__name__}: {exc}"}
        if decompiled.returncode != 0 or not decompiled.stdout.strip():
            return {"status": "decompilation_failed", "entrypoint": entry_pyc.name, "decompiler_exit_code": decompiled.returncode}

        recovered = decompiled.stdout.encode("utf-8", errors="replace")
        recovered_sha256 = hashlib.sha256(recovered).hexdigest()
        features = _analysis_from_recovered_text(recovered, f"recovered_{entry_pyc.stem}.py", config, rules)
        return {
            "status": "recovered",
            "extractor": "pyinstxtractor-ng",
            "decompiler": "pycdc",
            "entrypoint": entry_pyc.name,
            "recovered_source_sha256": recovered_sha256,
            "recovered_source_size": len(recovered),
            "features": features,
        }
