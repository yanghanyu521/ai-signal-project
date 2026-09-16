from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator


def validate_result(result: dict, schema_path: str | Path) -> list[str]:
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors = []
    for error in sorted(validator.iter_errors(result), key=lambda item: list(item.absolute_path)):
        location = ".".join(str(part) for part in error.absolute_path) or "$"
        errors.append(f"{location}: {error.message}")
    return errors


def validate_evidence(result: dict, blocks: list[dict]) -> list[str]:
    block_map = {block["block_id"]: block for block in blocks}
    errors: list[str] = []
    for claim in result.get("claims", []):
        for evidence in claim.get("evidence", []):
            block = block_map.get(evidence.get("block_id"))
            if not block:
                errors.append(f"{claim.get('claim_id')}: 证据块不存在")
                continue
            if evidence.get("excerpt") not in block["text"]:
                errors.append(f"{claim.get('claim_id')}: 证据片段不能在块中精确匹配")
    return errors
