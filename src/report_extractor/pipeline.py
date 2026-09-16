from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from .deterministic import extract_deterministic
from .llm import extract_with_deepseek, validate_and_convert_llm
from .parsers import parse_document
from .utils import sha256_bytes, stable_id, utc_now, write_json
from .validate import validate_evidence, validate_result


def _source_tier(hostname: str | None) -> str:
    host = (hostname or "").lower()
    if host.endswith("cert.gov.ua"):
        return "government_cert"
    if any(host.endswith(domain) for domain in ["cloud.google.com", "anthropic.com", "microsoft.com", "ibm.com"]):
        return "primary_vendor"
    if any(host.endswith(domain) for domain in ["sentinelone.com", "hunt.io", "checkpoint.com"]):
        return "security_research"
    return "unknown"


def _merge_entities(*groups: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    for group in groups:
        for entity in group:
            existing = merged.get(entity["entity_id"])
            if not existing:
                merged[entity["entity_id"]] = entity
            else:
                aliases = set(existing.get("aliases") or []) | set(entity.get("aliases") or [])
                if entity.get("name") != existing.get("name"):
                    aliases.add(entity.get("name"))
                existing["aliases"] = sorted(alias for alias in aliases if alias)
    return list(merged.values())


def extract_report(
    source_path: str | Path,
    *,
    canonical_url: str | None = None,
    output_dir: str | Path | None = None,
    use_llm: bool = False,
    schema_path: str | Path | None = None,
) -> dict:
    source = Path(source_path)
    data = source.read_bytes()
    digest = sha256_bytes(data)
    document_id = stable_id("document", canonical_url or source.name, digest)
    parsed = parse_document(source, document_id)
    publisher = urlsplit(canonical_url).hostname if canonical_url else None
    document = {
        "document_id": document_id,
        "title": parsed.get("title") or source.stem,
        "canonical_url": canonical_url,
        "publisher": publisher,
        "authors": parsed.get("authors") or [],
        "publication_date": parsed.get("publication_date"),
        "retrieved_at": utc_now(),
        "content_type": parsed["content_type"],
        "content_sha256": digest,
        "source_tier": _source_tier(publisher),
        "language": parsed.get("language"),
        "parent_report_id": None,
        "acquisition_status": "fetched",
    }
    blocks = parsed["blocks"]
    deterministic = extract_deterministic(document, blocks)
    llm_converted = {"entities": [], "claims": [], "warnings": []}
    llm_candidate = None
    extractors = [{"name": "deterministic-p0", "version": "0.1", "role": "deterministic"}]
    errors: list[dict] = []
    if use_llm:
        try:
            llm_candidate = extract_with_deepseek(blocks)
            llm_converted = validate_and_convert_llm(document_id, blocks, llm_candidate)
            extractors.append({"name": "deepseek", "version": llm_candidate["model"], "role": "llm"})
            for chunk_error in llm_candidate.get("chunk_errors", []):
                errors.append({
                    "stage": "llm_extraction",
                    "code": "chunk_failed",
                    "message": f"DeepSeek 第 {chunk_error['chunk']} 块失败: {chunk_error['error_type']}: {chunk_error['message']}",
                    "recoverable": True,
                })
            for warning in llm_converted["warnings"]:
                errors.append({"stage": "llm_validation", "code": "candidate_dropped", "message": warning, "recoverable": True})
        except Exception as exc:
            errors.append({"stage": "llm_extraction", "code": type(exc).__name__, "message": str(exc), "recoverable": True})
    entities = _merge_entities(deterministic["entities"], llm_converted["entities"])
    claims = list({claim["claim_id"]: claim for claim in deterministic["claims"] + llm_converted["claims"]}.values())
    result = {
        "schema_version": "0.1",
        "document": document,
        "entities": entities,
        "claims": claims,
        "sample_links": [],
        "cross_validation": [],
        "extraction": {
            "pipeline_version": "0.1",
            "extractors": [{"name": "parser", "version": parsed["content_type"], "role": "parser"}, *extractors, {"name": "evidence-validator", "version": "0.1", "role": "validator"}],
            "validation_status": "passed",
            "review_status": "not_reviewed",
        },
        "errors": errors,
    }
    evidence_errors = validate_evidence(result, blocks)
    for message in evidence_errors:
        errors.append({"stage": "evidence_validation", "code": "evidence_mismatch", "message": message, "recoverable": False})
    if schema_path:
        schema_errors = validate_result(result, schema_path)
        for message in schema_errors:
            errors.append({"stage": "schema_validation", "code": "schema_error", "message": message, "recoverable": False})
    if any(not error.get("recoverable", False) for error in errors):
        result["extraction"]["validation_status"] = "failed"
    elif errors:
        result["extraction"]["validation_status"] = "warnings"
    if llm_converted["claims"]:
        result["extraction"]["review_status"] = "needs_review"
    if output_dir:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        write_json(output / "document.json", document)
        write_json(output / "blocks.json", blocks)
        if llm_candidate is not None:
            write_json(output / "llm_candidates.json", llm_candidate)
        write_json(output / "report_result.json", result)
    return result
