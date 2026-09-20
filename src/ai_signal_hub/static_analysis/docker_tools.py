from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from pathlib import Path
from typing import Any

from .materials import AnalysisUnit, MaterialIndex


def _id(sha256: str, tool: str, location: str, content: str) -> str:
    digest = hashlib.sha256(f"{tool}:{location}:{content}".encode("utf-8")).hexdigest()[:24]
    return f"unit:{sha256[:12]}:{digest}"


def _is_apk_or_dex(data: bytes) -> bool:
    if data.startswith(b"dex\n"):
        return True
    if not data.startswith(b"PK\x03\x04"):
        return False
    try:
        from io import BytesIO
        with zipfile.ZipFile(BytesIO(data)) as archive:
            return any(name == "classes.dex" or re.fullmatch(r"classes\d+\.dex", name)
                       for name in archive.namelist())
    except zipfile.BadZipFile:
        return False


def _is_native(data: bytes) -> bool:
    return data.startswith((b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"))


_JAVA_METHOD = re.compile(
    r"(?m)^[ \t]*(?:@[\w.$]+(?:\([^\n]*\))?[ \t]*)*"
    r"(?:(?:public|protected|private|static|final|abstract|synchronized|native|strictfp|default)[ \t]+)*"
    r"(?:<[^>{}\n]+>[ \t]+)?(?:[\w.$?<>\[\],]+[ \t]+)?"
    r"(?P<name>[A-Za-z_$][\w$]*)[ \t]*\([^;{}\n]*\)[ \t]*"
    r"(?:throws[ \t]+[^{}\n]+)?\{"
)
_JAVA_INVOCATION = re.compile(r"(?<![\w$])(?:(?P<class>[A-Za-z_$][\w$]*)\s*\.\s*)?(?P<name>[A-Za-z_$][\w$]*)\s*\(")
_JAVA_STRING = re.compile(r'"(?P<value>(?:\\.|[^"\\])*)"')


def _matching_brace(text: str, opening: int) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    index = opening
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
        elif block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                index += 1
        elif quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char == "/" and next_char == "/":
            line_comment = True
            index += 1
        elif char == "/" and next_char == "*":
            block_comment = True
            index += 1
        elif char in {'"', "'"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return None


def _java_units(content: str, relative: str, sha256: str) -> list[AnalysisUnit]:
    artifact = f"jadx:{relative}"
    units: list[AnalysisUnit] = []
    spans: list[tuple[int, int]] = []
    for match in _JAVA_METHOD.finditer(content):
        name = match.group("name")
        if name in {"if", "for", "while", "switch", "catch", "synchronized"}:
            continue
        opening = content.find("{", match.start(), match.end())
        end = _matching_brace(content, opening)
        if end is None:
            continue
        method = content[match.start():end]
        start_line = content.count("\n", 0, match.start()) + 1
        end_line = content.count("\n", 0, end) + 1
        method_unit = AnalysisUnit(
            _id(sha256, "jadx-method", f"{relative}:{start_line}:{name}", method), artifact,
            sha256, "decompiled_method", "java", "decompiled_source", method,
            {"member_path": relative, "source_lines": [start_line, end_line], "symbol": name,
             "class_name": Path(relative).stem},
            {"tool": "jadx", "version": "1.5.6", "source_mapping_quality": "decompiler_generated",
             "relation_quality": "lexical_candidate"},
            parse_status="partial", limitations=["lexical_method_boundary_from_decompiler_output",
                                                   "decompiled_names_and_layout_are_not_author_style"],
            probable_role="unknown",
        )
        units.append(method_unit)
        spans.append((match.start(), end))
        for literal in _JAVA_STRING.finditer(method):
            value = literal.group("value")
            if not value:
                continue
            literal_line = start_line + method.count("\n", 0, literal.start())
            units.append(AnalysisUnit(
                _id(sha256, "jadx-string", f"{relative}:{literal_line}:{literal.start()}", value),
                artifact, sha256, "string", "java", "decompiled_string_literal", value,
                {"member_path": relative, "source_lines": [literal_line, literal_line],
                 "owner_symbol": name, "owner_unit_id": method_unit.unit_id},
                {"tool": "jadx", "version": "1.5.6", "source_mapping_quality": "decompiler_generated",
                 "relation_quality": "lexical_candidate"},
                {"callers": []}, parse_status="partial",
                limitations=["string_literal_from_decompiler_output"], probable_role="unknown",
            ))
    if spans:
        remainder_parts: list[str] = []
        cursor = 0
        for start, end in spans:
            remainder_parts.append(content[cursor:start])
            cursor = end
        remainder_parts.append(content[cursor:])
        remainder = "".join(remainder_parts)
        if remainder.strip():
            units.append(AnalysisUnit(
                _id(sha256, "jadx-class-structure", relative, remainder), artifact, sha256,
                "decompiled_class_structure", "java", "decompiled_source", remainder,
                {"member_path": relative},
                {"tool": "jadx", "version": "1.5.6", "source_mapping_quality": "decompiler_generated"},
                parse_status="partial", limitations=["method_bodies_stored_as_separate_units",
                                                       "decompiled_names_and_layout_are_not_author_style"],
                probable_role="unknown",
            ))
        return units
    return [AnalysisUnit(
        _id(sha256, "jadx-class", relative, content), artifact, sha256,
        "decompiled_class", "java", "decompiled_source", content,
        {"member_path": relative},
        {"tool": "jadx", "version": "1.5.6", "source_mapping_quality": "decompiler_generated"},
        parse_status="partial", limitations=["method_boundaries_not_recovered",
                                               "decompiled_names_and_layout_are_not_author_style"],
        probable_role="unknown",
    )]


def _resolve_java_relations(units: list[AnalysisUnit]) -> None:
    by_artifact: dict[str, list[AnalysisUnit]] = {}
    for unit in units:
        by_artifact.setdefault(unit.artifact_id, []).append(unit)
    controls = {"if", "for", "while", "switch", "catch", "synchronized", "return", "new", "throw"}
    for artifact_units in by_artifact.values():
        methods = [unit for unit in artifact_units if unit.kind == "decompiled_method"]
        names: dict[str, list[AnalysisUnit]] = {}
        for method in methods:
            names.setdefault(str(method.location.get("symbol") or ""), []).append(method)
        strings = [unit for unit in artifact_units if unit.kind == "string"]
        structure = next((unit for unit in artifact_units if unit.kind == "decompiled_class_structure"), None)
        for method in methods:
            calls: list[str] = []
            for match in _JAVA_INVOCATION.finditer(method.content):
                name = match.group("name")
                if name in controls or name == method.location.get("symbol") and match.start() < method.content.find("{"):
                    continue
                targets = names.get(name) or []
                if len(targets) == 1 and targets[0].unit_id != method.unit_id:
                    calls.append(targets[0].unit_id)
            method.references["calls"] = list(dict.fromkeys(calls))
            method.references.setdefault("callers", [])
            owned_strings = [unit for unit in strings if unit.location.get("owner_unit_id") == method.unit_id]
            method.references["strings"] = [unit.unit_id for unit in owned_strings]
            for string in owned_strings:
                string.references["callers"] = [method.unit_id]
            if structure:
                identifiers = set(re.findall(r"\b[A-Za-z_$][\w$]*\b", method.content))
                if any(re.search(rf"\b{re.escape(name)}\b\s*=", structure.content) for name in identifiers):
                    method.references["definitions"] = [structure.unit_id]
        by_id = {unit.unit_id: unit for unit in methods}
        for caller in methods:
            for callee_id in caller.references.get("calls", []):
                if callee_id in by_id:
                    by_id[callee_id].references.setdefault("callers", []).append(caller.unit_id)
        for method in methods:
            method.references["callers"] = list(dict.fromkeys(method.references.get("callers", [])))


def _address_value(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip().lower().removeprefix("0x").replace(":", "")
    try:
        return int(cleaned, 16)
    except ValueError:
        return None


class DockerStaticTools:
    """Run fixed decompilers in short-lived, network-disabled containers."""

    def __init__(self, *, enabled: bool, jadx_image: str, ghidra_image: str,
                 timeout_seconds: int = 600, docker_executable: str = "docker"):
        self.enabled = enabled
        self.jadx_image = jadx_image
        self.ghidra_image = ghidra_image
        self.timeout_seconds = timeout_seconds
        self.docker = docker_executable

    def augment(self, base: MaterialIndex, data: bytes, sample: dict[str, Any], artifact_dir: Path) -> MaterialIndex:
        kind = "jadx" if _is_apk_or_dex(data) else "ghidra" if _is_native(data) else None
        if kind is None:
            return base
        if not self.enabled:
            base.limitations.append(f"{kind}_docker_disabled")
            base.tool_runs.append({"tool": kind, "status": "unavailable", "reason": "docker_disabled"})
            return base
        if shutil.which(self.docker) is None:
            base.limitations.append("docker_command_missing")
            base.tool_runs.append({"tool": kind, "status": "unavailable", "reason": "docker_command_missing"})
            return base
        image = self.jadx_image if kind == "jadx" else self.ghidra_image
        if not self._image_available(image):
            base.limitations.append(f"{kind}_docker_image_missing")
            base.tool_runs.append({"tool": kind, "status": "unavailable", "reason": "image_missing", "image": image})
            return base
        output_dir = artifact_dir / "docker_static" / f"{kind}-{uuid.uuid4().hex[:12]}"
        output_dir.mkdir(parents=True, exist_ok=False)
        try:
            with tempfile.TemporaryDirectory(prefix=f"ai-signal-{kind}-") as temp:
                input_dir = Path(temp) / "input"
                input_dir.mkdir()
                suffix = ".apk" if kind == "jadx" and data.startswith(b"PK") else ".dex" if kind == "jadx" else ".bin"
                (input_dir / f"sample{suffix}").write_bytes(data)
                run = self._run(kind, image, input_dir, output_dir, f"sample{suffix}")
            (output_dir / "container.log").write_text(run.pop("log"), encoding="utf-8")
            run["artifact_dir"] = str(output_dir.resolve())
            base.tool_runs.append(run)
            if run["status"] != "completed":
                base.limitations.append(f"{kind}_{run['status']}")
                return base
            recovered = self._read_jadx(output_dir, sample) if kind == "jadx" else self._read_ghidra(output_dir, sample)
            if not recovered.units:
                run["status"] = "failed"
                run["reason"] = "no_decompiler_material"
                base.limitations.append(f"{kind}_no_decompiler_material")
                return base
            obsolete = {
                "no_decompiler_material", "binary_strings_only",
                f"{kind}_missing_dependency", f"{kind}_not_enabled",
                f"{kind}_docker_image_missing", f"{kind}_no_decompiler_material",
            }
            base.limitations = [item for item in base.limitations if item not in obsolete]
            base.units.extend(recovered.units)
            base.capabilities = {key: base.capabilities.get(key, False) or recovered.capabilities.get(key, False)
                                 for key in set(base.capabilities) | set(recovered.capabilities)}
            base.limitations.extend(item for item in recovered.limitations if item not in base.limitations)
            base.status = "partial" if base.units else recovered.status
            return base
        except Exception as exc:
            base.limitations.append(f"{kind}_adapter_error:{type(exc).__name__}")
            base.tool_runs.append({"tool": kind, "status": "failed", "reason": type(exc).__name__, "image": image})
            return base

    def _image_available(self, image: str) -> bool:
        try:
            result = subprocess.run(
                [self.docker, "image", "inspect", image], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=15, check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _run(self, kind: str, image: str, input_dir: Path, output_dir: Path, filename: str) -> dict[str, Any]:
        name = f"ai-signal-{kind}-{uuid.uuid4().hex[:12]}"
        command = [
            self.docker, "run", "--rm", "--name", name, "--hostname", "ai-signal-static", "--pull", "never",
            "--network", "none", "--cpus", "2", "--memory", "6g", "--pids-limit", "256",
            "--add-host", "ai-signal-static:127.0.0.1",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=3g",
            "--tmpfs", "/home/analyzer:rw,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=700",
            "--env", "HOME=/home/analyzer",
            "--mount", f"type=bind,source={input_dir.resolve()},target=/input,readonly",
            "--mount", f"type=bind,source={output_dir.resolve()},target=/output",
            image,
        ]
        if kind == "jadx":
            command.extend(["--output-dir", "/output", "--threads-count", "2", "/input/" + filename])
        else:
            command.extend([
                "/tmp", "AISignal", "-import", "/input/" + filename,
                "-scriptPath", "/opt/ai-signal-scripts", "-postScript", "GhidraExport.java",
                "/output/ghidra.jsonl", "-analysisTimeoutPerFile", str(self.timeout_seconds),
                "-max-cpu", "2", "-deleteProject",
            ])
        try:
            completed = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                errors="replace", timeout=self.timeout_seconds + 60, check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            log = (completed.stdout or "")[-200_000:]
            return {"tool": kind, "image": image,
                    "status": "completed" if completed.returncode == 0 else "failed",
                    "exit_code": completed.returncode, "network": "none", "log": log}
        except subprocess.TimeoutExpired as exc:
            subprocess.run([self.docker, "rm", "-f", name], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=30, check=False,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            output = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else str(exc.stdout or "")
            return {"tool": kind, "image": image, "status": "timeout", "exit_code": None,
                    "network": "none", "log": output[-200_000:]}

    @staticmethod
    def _read_jadx(output_dir: Path, sample: dict[str, Any]) -> MaterialIndex:
        sha256 = str(sample.get("sha256") or "unknown")
        units: list[AnalysisUnit] = []
        total = 0
        for path in sorted(output_dir.rglob("*.java"))[:5000]:
            if total >= 64 * 1024 * 1024:
                break
            content = path.read_text(encoding="utf-8", errors="replace")
            total += len(content.encode("utf-8"))
            relative = path.relative_to(output_dir).as_posix()
            units.extend(_java_units(content, relative, sha256))
        _resolve_java_relations(units)
        return MaterialIndex(
            sha256, "java", "partial" if units else "failed",
            {"text": bool(units), "constants": bool(units),
             "functions": any(unit.kind == "decompiled_method" for unit in units),
             "xrefs": any(bool(unit.references.get("calls") or unit.references.get("callers")
                                or unit.references.get("strings")) for unit in units),
             "dataflow": False}, units,
            ["jadx_decompilation_may_be_incomplete", "decompiled_style_not_author_style",
             "jadx_relations_are_lexical_candidates"],
        )

    @staticmethod
    def _read_ghidra(output_dir: Path, sample: dict[str, Any]) -> MaterialIndex:
        sha256 = str(sample.get("sha256") or "unknown")
        path = output_dir / "ghidra.jsonl"
        units: list[AnalysisUnit] = []
        records: list[dict[str, Any]] = []
        metadata: dict[str, Any] = {}
        imports: list[str] = []
        if path.is_file():
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[:30000]:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                kind = item.get("record_type")
                if kind == "metadata":
                    metadata = item
                elif kind == "import" and item.get("name"):
                    imports.append(str(item["name"]))
                elif kind in {"function", "string"} and item.get("content"):
                    records.append(item)
        for item in records:
            kind = item.get("record_type")
            content = str(item["content"])
            location = str(item.get("address") or "unknown")
            units.append(AnalysisUnit(
                        _id(sha256, "ghidra", location, content), f"ghidra:{location}", sha256,
                        "decompiled_function" if kind == "function" else "string",
                        str(metadata.get("language") or "native"),
                        "decompiled_pseudocode" if kind == "function" else "extracted_string",
                        content, {"virtual_address": location, "symbol": item.get("name"),
                                  "body_start": item.get("body_start"), "body_end": item.get("body_end")},
                        {"tool": "ghidra", "version": metadata.get("version"),
                         "source_mapping_quality": "virtual_address"},
                        {"calls": item.get("calls") or [], "callers": [], "definitions": [],
                         "resources": [], "strings": [],
                         "referenced_from_addresses": item.get("references") or []},
                        "parsed" if item.get("decompile_completed", True) else "partial",
                        ["decompiled_names_and_layout_are_not_author_style"] if kind == "function" else [],
                        "unknown",
                    ))
        functions = [unit for unit in units if unit.kind == "decompiled_function"]
        strings = [unit for unit in units if unit.kind == "string"]
        names: dict[str, list[str]] = {}
        for function in functions:
            name = str(function.location.get("symbol") or "")
            for key in {name, name.rsplit("::", 1)[-1]}:
                if key:
                    names.setdefault(key, []).append(function.unit_id)
        by_id = {unit.unit_id: unit for unit in functions}
        for function in functions:
            resolved, unresolved = [], []
            for called in function.references.get("calls", []):
                targets = names.get(str(called)) or names.get(str(called).rsplit("::", 1)[-1]) or []
                if len(targets) == 1:
                    resolved.append(targets[0])
                else:
                    unresolved.append(str(called))
            function.references["calls"] = list(dict.fromkeys(resolved))
            function.references["unresolved_calls"] = list(dict.fromkeys(unresolved))
            for callee_id in resolved:
                by_id[callee_id].references.setdefault("callers", []).append(function.unit_id)
        for string in strings:
            callers: list[str] = []
            for address in string.references.pop("referenced_from_addresses", []):
                reference = _address_value(address)
                if reference is None:
                    continue
                for function in functions:
                    start = _address_value(function.location.get("body_start") or function.location.get("virtual_address"))
                    end = _address_value(function.location.get("body_end") or function.location.get("virtual_address"))
                    if start is not None and end is not None and start <= reference <= end:
                        callers.append(function.unit_id)
            string.references["callers"] = list(dict.fromkeys(callers))
            for caller_id in string.references["callers"]:
                by_id[caller_id].references.setdefault("strings", []).append(string.unit_id)
        for function in functions:
            function.references["callers"] = list(dict.fromkeys(function.references.get("callers", [])))
            function.references["strings"] = list(dict.fromkeys(function.references.get("strings", [])))
        if imports:
            content = "\n".join(dict.fromkeys(imports))
            units.append(AnalysisUnit(
                _id(sha256, "ghidra", "imports", content), "ghidra:imports", sha256,
                "import_table", str(metadata.get("language") or "native"), "import_table",
                content, {"virtual_address": None},
                {"tool": "ghidra", "version": metadata.get("version"), "source_mapping_quality": "loader"},
                parse_status="parsed", probable_role="unknown",
            ))
        return MaterialIndex(
            sha256, str(metadata.get("language") or "native"), "partial" if units else "failed",
            {"text": bool(units), "constants": any(unit.kind == "string" for unit in units),
             "functions": any(unit.kind == "decompiled_function" for unit in units),
             "xrefs": any(bool(unit.references.get("calls") or unit.references.get("callers")
                                or unit.references.get("strings")) for unit in units),
             "dataflow": False}, units,
            ["ghidra_decompilation_may_be_incomplete", "decompiled_style_not_author_style"],
        )
