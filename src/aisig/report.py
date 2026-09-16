from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_artifacts(out_dir: Path, result: dict[str, Any], strings: list[dict[str, Any]], schema_path: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "metadata.json", result["sample"])
    with (out_dir / "strings.jsonl").open("w", encoding="utf-8") as handle:
        for item in strings:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")
    write_json(out_dir / "toolchain_features.json", result["features"]["toolchain"])
    write_json(out_dir / "prompt_features.json", result["features"]["prompt"])
    write_json(out_dir / "code_style_features.json", result["features"]["code_style"])
    write_json(out_dir / "features.json", result["features"])
    write_json(out_dir / "classification.json", result["classification"])
    jsonschema.validate(result, json.loads(schema_path.read_text(encoding="utf-8")))
    write_json(out_dir / "result.json", result)
