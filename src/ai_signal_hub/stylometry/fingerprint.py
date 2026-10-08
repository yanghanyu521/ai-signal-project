"""Versioned, source-only fingerprints at file and local granularity."""
from __future__ import annotations

import ast
import hashlib
import io
import json
import keyword
import re
import tokenize
from collections import Counter
from typing import Any


VERSION = "stylometry/1.0"
MIN_TOKENS = 12
_IDENTIFIER = re.compile(r"\b[A-Za-z_][A-Za-z_0-9]*\b")
_ARTIFACTS = (
    ("ai_generation_claim", re.compile(r"(?i)(?:generated\s+(?:by|with)\s+(?:an?\s+)?(?:ai|llm|chatgpt|claude|gpt)|(?:ai|llm)[ -]generated)")),
    ("markdown_code_fence", re.compile(r"^\s*```(?:[\w+-]*)\s*$")),
    ("conversation_residue", re.compile(r"(?i)^\s*(?:here(?:'s| is) (?:the|a) (?:code|script|solution)|as an ai language model)\b")),
    ("template_placeholder", re.compile(r"(?i)(?:<\s*(?:your[_ -]?(?:api[_ -]?key|value|code)|insert[_ -]?here)\s*>|\{\{\s*\w+\s*\}\})")),
)


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _ratios(values: Counter[str]) -> dict[str, float]:
    total = sum(values.values())
    return {key: round(values[key] / total, 6) for key in sorted(values) if values[key]} if total else {}


def _naming(names: list[str]) -> dict[str, float]:
    counts: Counter[str] = Counter()
    for name in names:
        if re.fullmatch(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)+", name):
            counts["snake_case"] += 1
        elif re.fullmatch(r"[a-z][a-z0-9]*(?:[A-Z][a-z0-9]*)+", name):
            counts["camelCase"] += 1
        elif re.fullmatch(r"[A-Z][a-z0-9]*(?:[A-Z][a-z0-9]*)+", name):
            counts["PascalCase"] += 1
        else:
            counts["other"] += 1
    return _ratios(counts)


def _python_tokens(text: str) -> tuple[list[str], list[tuple[int, str]], int, int]:
    tokens: list[str] = []
    comments: list[tuple[int, str]] = []
    strings = numbers = 0
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT:
                comments.append((token.start[0], token.string))
            elif token.type == tokenize.STRING:
                strings += 1
                tokens.append("STRING")
            elif token.type == tokenize.NUMBER:
                numbers += 1
                tokens.append("NUMBER")
            elif token.type == tokenize.NAME:
                tokens.append("NAME" if not keyword.iskeyword(token.string) else token.string)
            elif token.type == tokenize.OP:
                tokens.append(token.string)
    except (tokenize.TokenError, IndentationError):
        pass
    return tokens, comments, strings, numbers


def _tree_metrics(text: str) -> tuple[dict[str, Any], list[ast.AST], str | None]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError) as exc:
        return {}, [], type(exc).__name__
    nodes = list(ast.walk(tree))
    counts = Counter(type(node).__name__ for node in nodes)
    patterns = Counter(
        f"{type(node).__name__}>{type(child).__name__}"
        for node in nodes for child in ast.iter_child_nodes(node)
    )
    functions = [node for node in nodes if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    lengths = [max(1, node.end_lineno - node.lineno + 1) for node in functions]
    complexity = [1 + sum(isinstance(child, (ast.If, ast.For, ast.While, ast.Try,
                 ast.ExceptHandler, ast.BoolOp, ast.IfExp, ast.Match)) for child in ast.walk(fn))
                  for fn in functions]
    branches = sum(isinstance(node, (ast.If, ast.IfExp, ast.Match)) for node in nodes)
    loops = sum(isinstance(node, (ast.For, ast.AsyncFor, ast.While)) for node in nodes)
    exceptions = sum(isinstance(node, (ast.Try, ast.ExceptHandler, ast.Raise)) for node in nodes)
    return {
        "ast_node_distribution": _ratios(counts),
        "ast_pattern_distribution": _ratios(patterns),
        "function_length_distribution": sorted(lengths),
        "cyclomatic_complexity_distribution": sorted(complexity),
        "branch_ratio": round(branches / max(len(nodes), 1), 6),
        "loop_ratio": round(loops / max(len(nodes), 1), 6),
        "exception_ratio": round(exceptions / max(len(nodes), 1), 6),
        "argument_count_distribution": sorted(len(fn.args.posonlyargs) + len(fn.args.args)
                                              + len(fn.args.kwonlyargs) for fn in functions),
        "return_count": sum(isinstance(node, ast.Return) for node in nodes),
        "class_count": sum(isinstance(node, ast.ClassDef) for node in nodes),
    }, functions, None


def _metrics(text: str, language: str) -> tuple[dict[str, Any], list[ast.AST], str | None]:
    lines = text.splitlines()
    nonblank = [line for line in lines if line.strip()]
    if language == "python":
        tokens, comments, string_count, number_count = _python_tokens(text)
        tree_metrics, functions, parse_error = _tree_metrics(text)
        docstrings = []
        if parse_error is None:
            parsed = ast.parse(text)
            docstrings = [value for node in ast.walk(parsed)
                          if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                          if (value := ast.get_docstring(node, clean=False))]
        names = [node.id for fn in functions for node in ast.walk(fn) if isinstance(node, ast.Name)]
        if not names and parse_error is None:
            names = [x.id for x in ast.walk(ast.parse(text)) if isinstance(x, ast.Name)]
    else:
        comments = [(i, line) for i, line in enumerate(lines, 1)
                    if line.lstrip().startswith(("//", "#", "'", "/*", "*"))]
        tokens = _IDENTIFIER.findall(text)
        string_count = len(re.findall(r"(['\"])(?:\\.|(?!\1).)*?\1", text))
        number_count = len(re.findall(r"\b\d+(?:\.\d+)?\b", text))
        tree_metrics, functions, parse_error = {}, [], "parser_not_available"
        docstrings = []
        names = tokens
    comment_tokens = sum(len(_IDENTIFIER.findall(comment)) for _, comment in comments)
    lengths = [len(_IDENTIFIER.findall(comment)) for _, comment in comments]
    explanatory = sum(bool(re.search(r"(?i)\b(?:because|this function|this variable|the following|step \d+)\b", comment))
                      for _, comment in comments)
    indent = Counter(len(line) - len(line.lstrip(" \t")) for line in nonblank)
    token_counts = Counter(tokens)
    bigrams = Counter(zip(tokens, tokens[1:]))
    metrics = {
        "loc": len(lines), "effective_code_lines": max(0, len(nonblank) - len(comments)),
        "blank_ratio": round((len(lines) - len(nonblank)) / max(len(lines), 1), 6),
        "comment_ratio": round(len(comments) / max(len(nonblank), 1), 6),
        "comment_tokens_per_code_token": round(comment_tokens / max(len(tokens), 1), 6),
        "comment_length_distribution": sorted(lengths),
        "explanatory_comment_ratio": round(explanatory / max(len(comments), 1), 6),
        "docstring_count": len(docstrings),
        "docstring_length_distribution": sorted(len(_IDENTIFIER.findall(value)) for value in docstrings),
        "mean_identifier_length": round(sum(map(len, names)) / max(len(names), 1), 6),
        "naming_style": _naming(names),
        "indent_distribution": _ratios(indent),
        "string_literal_ratio": round(string_count / max(len(tokens), 1), 6),
        "number_literal_ratio": round(number_count / max(len(tokens), 1), 6),
        "token_unigrams": _ratios(token_counts),
        "token_bigrams": _ratios(Counter({f"{a}|{b}": count for (a, b), count in bigrams.items()})),
        "effective_tokens": len(tokens),
        **tree_metrics,
    }
    return metrics, functions, parse_error


def _profile(text: str, language: str, sha256: str, *, granularity: str,
             start: int, end: int, member_path: str | None = None) -> dict[str, Any]:
    metrics, _, parse_error = _metrics(text, language)
    stable = {key: metrics[key] for key in (
        "ast_node_distribution", "ast_pattern_distribution", "branch_ratio", "loop_ratio",
        "exception_ratio", "cyclomatic_complexity_distribution") if key in metrics}
    raw = {key: metrics[key] for key in (
        "blank_ratio", "comment_ratio", "comment_tokens_per_code_token", "mean_identifier_length",
        "naming_style", "indent_distribution", "token_unigrams", "token_bigrams")}
    length = metrics["effective_tokens"]
    return {
        "fingerprint_version": VERSION, "asset_kind": "code", "granularity": granularity,
        "sample_sha256": sha256, "member_path": member_path, "language": language,
        "source_kind": "original_source", "start_line": start, "end_line": end,
        "content_hash": "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "effective_tokens": length, "information_status": "low_information" if length < MIN_TOKENS else "comparable",
        "metrics": metrics, "raw_style_hash": _digest(raw),
        "structure_hash": _digest(stable) if stable else None,
        "analysis_coverage": {"lexical": True, "ast": parse_error is None, "parse_error": parse_error},
        "generator_family_hypothesis": "unknown", "generator_model_hypothesis": "unknown",
        "generator_version_hypothesis": "unknown", "prompt_strategy_hypothesis": "unknown",
        "reference_dataset_version": None, "calibration_status": "not_supported",
    }


def build_code_generation_signals(text: str | None, language: str | None,
                                  source_kind: str | None, sha256: str,
                                  member_path: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "metrics": {}, "style_indicators": [], "generation_artifacts": [],
        "hallucination_candidates": [], "local_profiles": [], "fingerprint": None,
        "source_hypotheses": {"generator_family_hypothesis": "unknown",
                              "generator_model_hypothesis": "unknown",
                              "generator_version_hypothesis": "unknown",
                              "prompt_strategy_hypothesis": "unknown",
                              "reference_dataset_version": None, "calibration_status": "not_supported"},
        "analysis_status": {"status": "unavailable", "reason": "original_source_required",
                            "asset_kind": "code", "source_kind": source_kind},
    }
    if not text or source_kind != "original_source" or language not in {"python", "javascript", "powershell"}:
        return result
    lines = text.splitlines()
    fingerprint = _profile(text, language, sha256, granularity="file", start=1,
                           end=max(1, len(lines)), member_path=member_path)
    result["fingerprint"] = fingerprint
    result["metrics"] = fingerprint["metrics"]
    result["analysis_status"] = {"status": "completed" if fingerprint["analysis_coverage"]["ast"]
                                 else "partial", "reason": fingerprint["analysis_coverage"]["parse_error"],
                                 "asset_kind": "code", "source_kind": source_kind,
                                 "effective_tokens": fingerprint["effective_tokens"]}
    if language == "python" and fingerprint["analysis_coverage"]["ast"]:
        _, functions, _ = _metrics(text, language)
        for fn in functions:
            start, end = fn.lineno, fn.end_lineno
            snippet = "\n".join(lines[start - 1:end])
            result["local_profiles"].append(_profile(snippet, language, sha256,
                granularity="function", start=start, end=end, member_path=member_path))
        locals_ = result["local_profiles"]
        for left, right in zip(locals_, locals_[1:]):
            x = left["metrics"].get("comment_ratio", 0)
            y = right["metrics"].get("comment_ratio", 0)
            if abs(x - y) >= 0.45 and min(left["effective_tokens"], right["effective_tokens"]) >= MIN_TOKENS:
                result["style_indicators"].append({
                    "label": "comment_density_shift", "evidence_status": "observed_indicator",
                    "left_lines": [left["start_line"], left["end_line"]],
                    "right_lines": [right["start_line"], right["end_line"]],
                    "left_comment_ratio": x, "right_comment_ratio": y,
                    "interpretation": "局部注释密度变化，不推断作者或模型数量",
                })
    else:
        # Bounded, stable segments when a trusted parser is unavailable.
        for start in range(1, len(lines) + 1, 40):
            end = min(len(lines), start + 39)
            snippet = "\n".join(lines[start - 1:end])
            result["local_profiles"].append(_profile(snippet, language, sha256,
                granularity="segment", start=start, end=end, member_path=member_path))
    for lineno, line in enumerate(lines, 1):
        for label, pattern in _ARTIFACTS:
            match = pattern.search(line)
            if match:
                result["generation_artifacts"].append({
                    "label": label, "asset_kind": "code", "line": lineno,
                    "start_char": match.start(), "end_char": match.end(),
                    "raw_value": match.group(), "source_kind": source_kind,
                    "evidence_text_hash": "sha256:" + hashlib.sha256(match.group().encode()).hexdigest(),
                    "evidence_status": "observed_indicator", "proves_generator_model": False,
                })
    return result


def build_text_profile(text: str, sha256: str, *, asset_kind: str,
                       source_location: dict[str, Any]) -> dict[str, Any]:
    """A separate descriptive fingerprint for instructions or readable data."""
    if asset_kind not in {"instruction", "data_text"}:
        raise ValueError("text asset_kind must be instruction or data_text")
    words = re.findall(r"\b\w+\b", text.casefold())
    punctuation = Counter(char for char in text if char in ".!?;:,.\n")
    metrics = {"word_count": len(words), "mean_word_length": round(
        sum(map(len, words)) / max(len(words), 1), 6),
        "punctuation_distribution": _ratios(punctuation),
        "imperative_cue_ratio": round(sum(word in {"generate", "write", "return", "ignore", "create", "list"}
                                        for word in words) / max(len(words), 1), 6),
        "token_unigrams": _ratios(Counter(words)),
    }
    return {"fingerprint_version": VERSION, "asset_kind": asset_kind,
            "sample_sha256": sha256, "source_location": source_location,
            "content_hash": "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "style_profile": metrics,
            "information_status": "low_information" if len(words) < MIN_TOKENS else "comparable",
            "generator_model_hypothesis": "unknown", "calibration_status": "not_supported"}
