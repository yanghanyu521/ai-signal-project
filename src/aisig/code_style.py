from __future__ import annotations

import ast
import re
from collections import Counter
from typing import Any


def _base_result(language: str | None, recoverability: str) -> dict[str, Any]:
    return {"status": "not_trained", "language": language, "recoverability": recoverability, "metrics": {}, "ai_generated_detection": {"status": "not_trained", "heuristic_score": None}}


def _naming(values: list[str]) -> dict[str, float]:
    if not values:
        return {"snake_case": 0.0, "camel_case": 0.0, "other": 0.0}
    snake = sum("_" in value and value.lower() == value for value in values)
    camel = sum(bool(re.match(r"^[a-z]+(?:[A-Z][a-z0-9]*)+$", value)) for value in values)
    return {"snake_case": round(snake / len(values), 3), "camel_case": round(camel / len(values), 3), "other": round(1 - ((snake + camel) / len(values)), 3)}


def analyze_code_style(text: str | None, language: str | None, recoverability: str) -> dict[str, Any]:
    result = _base_result(language, recoverability)
    if text is None or recoverability not in {"original_source", "recovered_source"}:
        return result
    lines = text.splitlines()
    nonblank = [line for line in lines if line.strip()]
    comments = [line for line in nonblank if line.lstrip().startswith(("#", "'", "//"))]
    metrics: dict[str, Any] = {
        "loc": len(lines),
        "blank_ratio": round((len(lines) - len(nonblank)) / max(len(lines), 1), 3),
        "comment_ratio": round(len(comments) / max(len(nonblank), 1), 3),
        "mean_identifier_length": None,
        "naming_style": {},
    }
    if language == "python":
        try:
            tree = ast.parse(text)
            nodes = list(ast.walk(tree))
            names = [node.id for node in nodes if isinstance(node, ast.Name)]
            functions = [node for node in nodes if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
            handlers = [node for node in nodes if isinstance(node, ast.ExceptHandler)]
            metrics.update({
                "function_count": len(functions),
                "exception_handler_count": len(handlers),
                "exception_handler_ratio": round(len(handlers) / max(len(functions), 1), 3),
                "mean_identifier_length": round(sum(map(len, names)) / len(names), 2) if names else 0.0,
                "naming_style": _naming(names),
                "ast_node_counts": dict(Counter(type(node).__name__ for node in nodes).most_common(20)),
            })
        except SyntaxError as exc:
            result["parse_error"] = str(exc)
    else:
        identifiers = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{1,}\b", text)
        metrics.update({
            "function_count": len(re.findall(r"(?im)^\s*(?:function|sub)\s+", text)),
            "mean_identifier_length": round(sum(map(len, identifiers)) / len(identifiers), 2) if identifiers else 0.0,
            "naming_style": _naming(identifiers),
        })
    result["metrics"] = metrics
    return result
