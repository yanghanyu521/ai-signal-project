from __future__ import annotations

import ast
import hashlib
import io
import re
import shutil
import zipfile
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AnalysisUnit:
    unit_id: str
    artifact_id: str
    sample_sha256: str
    kind: str
    language: str
    representation: str
    content: str
    location: dict[str, Any]
    provenance: dict[str, Any]
    references: dict[str, list[str]] = field(default_factory=dict)
    parse_status: str = "parsed"
    limitations: list[str] = field(default_factory=list)
    probable_role: str = "application"
    parent_artifact_id: str | None = None

    def as_dict(self, *, include_content: bool = True) -> dict[str, Any]:
        value = {
            "unit_id": self.unit_id, "artifact_id": self.artifact_id,
            "parent_artifact_id": self.parent_artifact_id, "sample_sha256": self.sample_sha256,
            "kind": self.kind, "language": self.language,
            "representation": self.representation,
            "content_hash": "sha256:" + hashlib.sha256(self.content.encode("utf-8")).hexdigest(),
            "location": self.location, "provenance": self.provenance,
            "references": self.references, "parse_status": self.parse_status,
            "limitations": self.limitations, "probable_role": self.probable_role,
        }
        if include_content:
            value["content"] = self.content
        return value


@dataclass
class MaterialIndex:
    sample_sha256: str
    language: str
    status: str
    capabilities: dict[str, bool]
    units: list[AnalysisUnit]
    limitations: list[str] = field(default_factory=list)
    tool_runs: list[dict[str, Any]] = field(default_factory=list)

    def public_summary(self) -> dict[str, Any]:
        return {
            "schema_version": "analysis-materials/1.0",
            "status": self.status, "language": self.language,
            "capabilities": self.capabilities, "unit_count": len(self.units),
            "limitations": self.limitations,
            "tool_runs": self.tool_runs,
            "units": [unit.as_dict(include_content=False) for unit in self.units],
        }


def _unit_id(sha256: str, kind: str, start: int, content: str) -> str:
    digest = hashlib.sha256(f"{kind}:{start}:{content}".encode("utf-8")).hexdigest()[:16]
    return f"unit:{sha256[:12]}:{digest}"


def _lines(text: str, start: int, end: int) -> str:
    return "".join(text.splitlines(keepends=True)[start - 1:end])


def _python_index(text: str, sha256: str) -> MaterialIndex:
    artifact = f"sample:{sha256}"
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        unit = AnalysisUnit(_unit_id(sha256, "module_init", 1, text), artifact, sha256,
                            "module_init", "python", "original_source", text,
                            {"source_lines": [1, max(1, len(text.splitlines()))], "file_offset": 0},
                            {"tool": "python_ast", "version": "stdlib", "source_mapping_quality": "exact"},
                            parse_status="partial", limitations=[f"syntax_error:{exc.msg}"])
        return MaterialIndex(sha256, "python", "partial",
                             {"text": True, "constants": True, "functions": False,
                              "xrefs": False, "dataflow": False}, [unit], ["python_ast_parse_failed"])

    definitions: dict[str, str] = {}
    raw: list[tuple[ast.AST, AnalysisUnit]] = []
    function_nodes = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    occupied: set[int] = set()
    for node in function_nodes:
        start, end = node.lineno, getattr(node, "end_lineno", node.lineno)
        content = _lines(text, start, end)
        kind = "source_class" if isinstance(node, ast.ClassDef) else "source_function"
        uid = _unit_id(sha256, kind, start, content)
        definitions[node.name] = uid
        occupied.update(range(start, end + 1))
        raw.append((node, AnalysisUnit(
            uid, artifact, sha256, kind, "python", "original_source", content,
            {"source_lines": [start, end], "file_offset": len("".join(text.splitlines(keepends=True)[:start - 1]).encode("utf-8"))},
            {"tool": "python_ast", "version": "stdlib", "source_mapping_quality": "exact"},
        )))
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        names = []
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                names.append(target.id)
        if not names:
            continue
        start, end = node.lineno, getattr(node, "end_lineno", node.lineno)
        content = _lines(text, start, end)
        uid = _unit_id(sha256, "config", start, content)
        for name in names:
            definitions[name] = uid
        occupied.update(range(start, end + 1))
        raw.append((node, AnalysisUnit(
            uid, artifact, sha256, "config", "python", "original_source", content,
            {"source_lines": [start, end], "file_offset": len("".join(text.splitlines(keepends=True)[:start - 1]).encode("utf-8"))},
            {"tool": "python_ast", "version": "stdlib", "source_mapping_quality": "exact"},
        )))
    module_lines = [line for number, line in enumerate(text.splitlines(keepends=True), 1) if number not in occupied]
    module = "".join(module_lines)
    if module.strip() or not raw:
        raw.insert(0, (tree, AnalysisUnit(
            _unit_id(sha256, "module_init", 1, module), artifact, sha256,
            "module_init", "python", "original_source", module,
            {"source_lines": [1, max(1, len(text.splitlines()))], "file_offset": 0},
            {"tool": "python_ast", "version": "stdlib", "source_mapping_quality": "line_set"},
            limitations=["non_contiguous_module_lines"] if raw else [],
        )))
    callers: dict[str, list[str]] = {uid: [] for uid in definitions.values()}
    for node, unit in raw:
        calls = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = child.func.id if isinstance(child.func, ast.Name) else (
                    child.func.attr if isinstance(child.func, ast.Attribute) else None)
                if name:
                    calls.append(definitions.get(name, name))
                    if name in definitions and unit.unit_id != definitions[name]:
                        callers[definitions[name]].append(unit.unit_id)
        unit.references = {
            "calls": list(dict.fromkeys(calls)),
            "callers": [],
            "definitions": [definitions[name] for name in definitions if re.search(rf"\b{re.escape(name)}\b", unit.content)],
            "resources": [], "strings": [],
        }
    for _, unit in raw:
        unit.references["callers"] = list(dict.fromkeys(callers.get(unit.unit_id, [])))
    return MaterialIndex(sha256, "python", "completed",
                         {"text": True, "constants": True, "functions": True,
                          "xrefs": True, "dataflow": True}, [unit for _, unit in raw],
                         ["dataflow_is_bounded_to_static_ast_relations"])


def _lexical_index(text: str, sha256: str, language: str) -> MaterialIndex:
    artifact = f"sample:{sha256}"
    if language == "javascript":
        pattern = re.compile(r"(?m)^(?:export\s+)?(?:async\s+)?function\s+([\w$]+)\s*\([^)]*\)\s*\{")
    else:
        pattern = re.compile(r"(?im)^\s*function\s+([\w-]+)\s*\{")
    matches = list(pattern.finditer(text))
    units: list[AnalysisUnit] = []
    starts = [match.start() for match in matches] + [len(text)]
    if matches and text[:matches[0].start()].strip():
        prefix = text[:matches[0].start()]
        units.append(AnalysisUnit(_unit_id(sha256, "module_init", 1, prefix), artifact, sha256,
                                  "module_init", language, "original_source", prefix,
                                  {"source_lines": [1, prefix.count("\n") + 1], "file_offset": 0},
                                  {"tool": "bounded_lexical_splitter", "version": "1", "source_mapping_quality": "exact"},
                                  limitations=["no_ast_relation_proof"]))
    for pos, match in enumerate(matches):
        content = text[match.start():starts[pos + 1]]
        line = text.count("\n", 0, match.start()) + 1
        units.append(AnalysisUnit(_unit_id(sha256, "source_function", line, content), artifact, sha256,
                                  "source_function", language, "original_source", content,
                                  {"source_lines": [line, line + content.count("\n")], "file_offset": len(text[:match.start()].encode("utf-8"))},
                                  {"tool": "bounded_lexical_splitter", "version": "1", "source_mapping_quality": "exact"},
                                  limitations=["function_end_is_lexical_next_definition", "no_ast_relation_proof"]))
    if not units:
        units.append(AnalysisUnit(_unit_id(sha256, "module_init", 1, text), artifact, sha256,
                                  "module_init", language, "original_source", text,
                                  {"source_lines": [1, max(1, text.count("\n") + 1)], "file_offset": 0},
                                  {"tool": "bounded_lexical_splitter", "version": "1", "source_mapping_quality": "exact"},
                                  parse_status="partial", limitations=["no_function_boundaries_recognized", "no_ast_relation_proof"]))
    return MaterialIndex(sha256, language, "partial",
                         {"text": True, "constants": True, "functions": bool(matches),
                          "xrefs": False, "dataflow": False}, units,
                         ["lexical_materials_only", "no_code_execution"])


def _string_index(data: bytes, sample: dict[str, Any], language: str = "binary") -> MaterialIndex:
    from aisig.string_extract import extract_strings

    sha256 = str(sample.get("sha256") or "unknown")
    artifact = f"sample:{sha256}"
    units = []
    for item in extract_strings(data, 512, 4096):
        content = str(item.get("value") or "")
        if not content:
            continue
        offset = int(item.get("offset") or 0)
        unit = AnalysisUnit(
            _unit_id(sha256, "string", offset, content), artifact, sha256,
            "string", language, "extracted_string", content,
            {"file_offset": offset, "encoding": item.get("encoding")},
            {"tool": "aisig_string_extract", "version": "1", "source_mapping_quality": "exact_offset"},
            parse_status="parsed", limitations=["no_call_relation_from_string_scan"],
        )
        units.append(unit)
    file_type = str(sample.get("file_type") or "").lower()
    native = data.startswith((b"MZ", b"\x7fELF")) or "pe32" in file_type or "elf" in file_type
    limitations = ["binary_strings_only", "no_decompiler_material"]
    if native:
        limitations.append("ghidra_missing_dependency" if not shutil.which("analyzeHeadless") else "ghidra_not_enabled")
    return MaterialIndex(sha256, language, "partial" if units else "unsupported",
                         {"text": False, "constants": bool(units), "functions": False,
                          "xrefs": False, "dataflow": False}, units, limitations)


def _archive_index(data: bytes, sample: dict[str, Any]) -> MaterialIndex:
    sha256 = str(sample.get("sha256") or "unknown")
    units: list[AnalysisUnit] = []
    limitations = ["bounded_archive_member_scan", "archive_members_never_executed_or_extracted"]
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()[:128]
            if len(archive.infolist()) > len(members):
                limitations.append("member_limit_reached")
            for info in members:
                if info.is_dir() or info.file_size > 2 * 1024 * 1024 or info.compress_size == 0 and info.file_size > 0:
                    continue
                if info.file_size / max(1, info.compress_size) > 100:
                    limitations.append(f"compression_ratio_rejected:{info.filename}")
                    continue
                if total + info.file_size > 16 * 1024 * 1024:
                    limitations.append("expanded_byte_limit_reached")
                    break
                member = archive.read(info)
                total += len(member)
                suffix = info.filename.lower().rsplit(".", 1)[-1] if "." in info.filename else ""
                member_language = {"py": "python", "js": "javascript", "mjs": "javascript",
                                   "ps1": "powershell"}.get(suffix)
                if member_language:
                    text = member.decode("utf-8", errors="replace")
                    child = _python_index(text, sha256) if member_language == "python" else _lexical_index(text, sha256, member_language)
                    id_map = {unit.unit_id: "unit:" + hashlib.sha256(
                        f"{sha256}:{info.filename}:{unit.unit_id}".encode("utf-8")
                    ).hexdigest()[:28] for unit in child.units}
                    for unit in child.units:
                        unit.unit_id = id_map[unit.unit_id]
                        unit.references = {key: [id_map.get(value, value) for value in values]
                                           for key, values in unit.references.items()}
                        unit.artifact_id = f"member:{info.filename}"
                        unit.parent_artifact_id = f"sample:{sha256}"
                        unit.location["member_path"] = info.filename
                        if any(part in info.filename.lower() for part in ("site-packages/", "node_modules/", "vendor/")):
                            unit.probable_role = "dependency"
                    units.extend(child.units)
                elif suffix in {"dex", "so", "dll"}:
                    child = _string_index(member, {**sample, "file_type": suffix}, suffix)
                    for unit in child.units:
                        unit.unit_id = "unit:" + hashlib.sha256(
                            f"{sha256}:{info.filename}:{unit.unit_id}".encode("utf-8")
                        ).hexdigest()[:28]
                        unit.artifact_id = f"member:{info.filename}"
                        unit.parent_artifact_id = f"sample:{sha256}"
                        unit.location["member_path"] = info.filename
                    units.extend(child.units)
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        return MaterialIndex(sha256, "archive", "failed",
                             {"text": False, "constants": False, "functions": False,
                              "xrefs": False, "dataflow": False}, [],
                             [f"archive_parse_failed:{type(exc).__name__}"])
    if any(str(unit.location.get("member_path", "")).endswith(".dex") for unit in units):
        limitations.append("jadx_missing_dependency" if not shutil.which("jadx") else "jadx_not_enabled")
    return MaterialIndex(sha256, "archive", "partial" if units else "unsupported",
                         {"text": any(unit.representation == "original_source" for unit in units),
                          "constants": bool(units),
                          "functions": any(unit.kind == "source_function" for unit in units),
                          "xrefs": any(bool(unit.references.get("calls")) for unit in units),
                          "dataflow": any(unit.language == "python" for unit in units)}, units, limitations)


def build_material_index(data: bytes, sample: dict[str, Any]) -> MaterialIndex:
    sha256 = str(sample.get("sha256") or "unknown")
    language = str(sample.get("language") or "unknown").lower()
    if data.startswith(b"PK\x03\x04"):
        return _archive_index(data, sample)
    if language not in {"python", "javascript", "powershell"}:
        return _string_index(data, sample, language)
    try:
        text = data.decode(str(sample.get("source_encoding") or "utf-8"), errors="strict")
    except (UnicodeDecodeError, LookupError):
        text = data.decode("utf-8", errors="replace")
    return _python_index(text, sha256) if language == "python" else _lexical_index(text, sha256, language)


def split_large_units(index: MaterialIndex, max_unit_tokens: int) -> MaterialIndex:
    """Split oversized units without dropping content; budget uses a byte/token estimate."""
    max_bytes = max(256, max_unit_tokens * 3)
    replacements: dict[str, list[AnalysisUnit]] = {}
    for unit in index.units:
        if len(unit.content.encode("utf-8")) <= max_bytes:
            continue
        pieces: list[str] = []
        pending = ""
        for line in unit.content.splitlines(keepends=True) or [unit.content]:
            if len(line.encode("utf-8")) > max_bytes:
                if pending:
                    pieces.append(pending)
                    pending = ""
                width = max(1, max_bytes // 3)
                pieces.extend(line[pos:pos + width] for pos in range(0, len(line), width))
            elif pending and len((pending + line).encode("utf-8")) > max_bytes:
                pieces.append(pending)
                pending = line
            else:
                pending += line
        if pending:
            pieces.append(pending)
        fragments = []
        start_line = (unit.location.get("source_lines") or [None])[0]
        consumed_lines = 0
        for number, content in enumerate(pieces, 1):
            uid = _unit_id(index.sample_sha256, f"{unit.kind}_fragment", number,
                           unit.unit_id + content)
            line = start_line + consumed_lines if isinstance(start_line, int) else None
            fragment = AnalysisUnit(
                uid, unit.artifact_id, unit.sample_sha256, f"{unit.kind}_fragment",
                unit.language, unit.representation, content,
                {**unit.location, "parent_unit_id": unit.unit_id,
                 "source_lines": [line, line + content.count("\n")] if line else unit.location.get("source_lines")},
                {**unit.provenance, "recovery_steps": ["budget_aware_structural_split"]},
                {key: list(values) for key, values in unit.references.items()},
                unit.parse_status, [*unit.limitations, "split_from_oversized_unit"],
                unit.probable_role, unit.parent_artifact_id,
            )
            fragments.append(fragment)
            consumed_lines += content.count("\n")
        for number, fragment in enumerate(fragments):
            fragment.references["previous"] = [fragments[number - 1].unit_id] if number else []
            fragment.references["next"] = [fragments[number + 1].unit_id] if number + 1 < len(fragments) else []
        replacements[unit.unit_id] = fragments
    if not replacements:
        return index
    first_ids = {old: fragments[0].unit_id for old, fragments in replacements.items()}
    units = []
    for unit in index.units:
        candidates = replacements.get(unit.unit_id, [unit])
        for candidate in candidates:
            candidate.references = {key: [first_ids.get(value, value) for value in values]
                                    for key, values in candidate.references.items()}
            units.append(candidate)
    index.units = units
    index.limitations.append("oversized_units_split_by_request_context_limit")
    return index
