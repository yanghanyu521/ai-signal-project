from __future__ import annotations

import re
from typing import Iterable

from .utils import normalize_space, stable_id


CONFIRMED_RE = re.compile(
    r"\b(?:confirmed|verified|observed|demonstrated|identified|detected)\b|确认|证实|验证|观察到|检测到|发现",
    re.I,
)
LIKELY_RE = re.compile(
    r"\b(?:likely|probably|assess(?:ed|ment)?|believe|believed|suspect(?:ed)?)\b|很可能|高度可能|研判|评估认为|认为|据信",
    re.I,
)
POSSIBLE_RE = re.compile(
    r"\b(?:may|might|could|possibly|possible|potentially|appears? to|seems? to)\b|可能|或许|疑似|推测|推断",
    re.I,
)
SPECULATIVE_RE = re.compile(r"\b(?:speculat(?:e|ed|ive)|hypothes(?:is|ized))\b|猜测|假设", re.I)
NEGATIVE_RE = re.compile(
    r"\b(?:no evidence|not observed|not confirmed|cannot confirm|could not confirm|unable to confirm|did not observe|without evidence)\b|"
    r"没有证据|无证据|未观察到|尚未观察到|未确认|无法确认|不能确认|未发现",
    re.I,
)
ATTRIBUTION_RE = re.compile(
    r"\b(?:attribute[ds]? to|attribution|associated with|linked to|state-sponsored|government-backed)\b|归因|关联到|国家支持|政府支持",
    re.I,
)
HIGH_CONF_RE = re.compile(r"\bhigh confidence\b|高度确信|高置信度", re.I)
MEDIUM_CONF_RE = re.compile(r"\bmedium confidence\b|中等置信度", re.I)
LOW_CONF_RE = re.compile(r"\blow confidence\b|低置信度", re.I)


PREDICATES_BY_FIELD = {
    "time": {"observed_during"},
    "status": {"has_operational_status"},
    "artifacts": {"has_artifact", "has_indicator", "affects_platform", "uses_tool"},
    "attribution": {"attributed_to", "associated_with_region"},
    "targets": {"targets"},
    "ai_involvement": {"has_ai_role", "has_autonomy_level", "has_human_role", "has_ai_work_share"},
    "ai_signals.toolchain": {"uses_model", "uses_provider", "uses_agent", "uses_tool"},
    "ai_signals.prompts": {"uses_prompt"},
    "ai_signals.code_style": {"has_code_style_feature"},
    "key_behaviors": {"performs_technique"},
    "limitations": {"limits_or_contradicts"},
}


def _evidence_text(event: dict, evidence_ids: Iterable[str]) -> str:
    wanted = set(evidence_ids)
    return " ".join(
        item.get("excerpt", "")
        for item in event.get("evidence", [])
        if item.get("evidence_id") in wanted
    )


def _claim_evidence_id(claim: dict) -> str | None:
    evidence = (claim.get("evidence") or [None])[0]
    if not evidence:
        return None
    return stable_id("evidence", evidence.get("block_id"), evidence.get("excerpt"))


def _allowed_predicates(field_path: str) -> set[str] | None:
    normalized = re.sub(r"\[\d+\]", "", field_path).removeprefix("event.")
    for prefix, predicates in PREDICATES_BY_FIELD.items():
        if normalized == prefix or normalized.startswith(f"{prefix}."):
            return predicates
    return None


def _matching_claims(field_path: str, evidence_ids: list[str], llm_claims: list[dict]) -> list[dict]:
    wanted = set(evidence_ids)
    allowed = _allowed_predicates(field_path)
    matches = []
    for claim in llm_claims:
        evidence_id = _claim_evidence_id(claim)
        if evidence_id not in wanted:
            continue
        if allowed is not None and claim.get("predicate") not in allowed:
            continue
        matches.append(claim)
    return matches


def _author_confidence(text: str, claims: list[dict], actor: dict | None) -> str:
    values = [claim.get("author_confidence") for claim in claims]
    for level in ["explicit_high", "explicit_medium", "explicit_low", "implicit"]:
        if level in values:
            return level
    if HIGH_CONF_RE.search(text) or actor and actor.get("confidence") == "high":
        return "explicit_high"
    if MEDIUM_CONF_RE.search(text) or actor and actor.get("confidence") == "medium":
        return "explicit_medium"
    if LOW_CONF_RE.search(text) or actor and actor.get("confidence") == "low":
        return "explicit_low"
    return "not_stated"


def _claim_type_and_status(text: str, claims: list[dict], field_path: str, actor: dict | None) -> tuple[str, str]:
    # “遥测未发现，因此可能仍是PoC”中的否定证据是推断PoC状态的依据，
    # 不能把PoC结论本身标成 denied。状态结论优先保留作者的不确定性措辞。
    if field_path == "event.status" and POSSIBLE_RE.search(text):
        return "author_inference", "possible"
    if NEGATIVE_RE.search(text):
        return "negative_evidence", "denied"
    if claims:
        claim_type_order = ["negative_evidence", "direct_observation", "author_assessment", "author_inference", "methodology", "limitation"]
        status_order = ["denied", "asserted", "likely", "possible", "speculative", "unknown"]
        claim_types = [claim.get("claim_type") for claim in claims]
        statuses = [claim.get("assertion_status") for claim in claims]
        claim_type = next((value for value in claim_type_order if value in claim_types), "author_assessment")
        status = next((value for value in status_order if value in statuses), "unknown")
        return claim_type, status
    if SPECULATIVE_RE.search(text):
        return "author_inference", "speculative"
    if POSSIBLE_RE.search(text):
        return "author_inference", "possible"
    if LIKELY_RE.search(text):
        return "author_assessment", "likely"
    if actor is not None or field_path.startswith("event.attribution") or ATTRIBUTION_RE.search(text):
        return "author_assessment", "asserted"
    return "direct_observation", "asserted"


def _strength(text: str, claim_type: str, assertion_status: str, author_confidence: str) -> tuple[str, str]:
    if not text:
        return "unknown", "字段有值但缺少可回指证据，不能评定强度"
    if assertion_status == "denied":
        return "strong", "报告明确给出否定或未观察到的证据；强度与结论极性分开保存"
    if CONFIRMED_RE.search(text) and assertion_status == "asserted":
        return "confirmed", "报告使用确认、证实、观察或检测等明确措辞"
    if assertion_status in {"possible", "speculative"}:
        return "weak", "报告使用可能、疑似、推测或假设等不确定措辞"
    if assertion_status == "likely" or claim_type == "author_inference":
        if author_confidence == "explicit_high":
            return "strong", "报告属于评估/推断，但作者明确给出高置信度"
        return "moderate", "报告属于作者评估或推断，未达到明确确认"
    if claim_type == "author_assessment":
        if author_confidence == "explicit_high":
            return "strong", "报告作者作出高置信度评估，但仍与直接确认区分"
        return "moderate", "报告作者作出归因或判断，未给出直接确认措辞"
    if assertion_status == "asserted":
        return "strong", "报告以事实陈述方式直接描述该结论"
    return "unknown", "报告没有提供足够的确定性措辞"


def assess_field(
    event: dict,
    field_path: str,
    conclusion: object,
    evidence_ids: list[str],
    *,
    llm_claims: list[dict] | None = None,
    deterministic_evidence_ids: set[str] | None = None,
    actor: dict | None = None,
) -> dict:
    llm_claims = llm_claims or []
    deterministic_evidence_ids = deterministic_evidence_ids or set()
    text = _evidence_text(event, evidence_ids)
    claims = _matching_claims(field_path, evidence_ids, llm_claims)
    claim_type, assertion_status = _claim_type_and_status(text, claims, field_path, actor)
    author_confidence = _author_confidence(text, claims, actor)
    evidence_strength, rationale = _strength(text, claim_type, assertion_status, author_confidence)
    has_deterministic = bool(set(evidence_ids) & deterministic_evidence_ids)
    has_llm = bool(claims)
    extractor_method = "hybrid" if has_deterministic and has_llm else "deepseek_candidate" if has_llm else "deterministic_rule"
    extractor_confidence = 0.85 if extractor_method == "hybrid" else 0.75 if extractor_method == "deepseek_candidate" else 0.9
    return {
        "assessment_id": stable_id("field-assessment", event["event_id"], field_path, str(conclusion), *evidence_ids),
        "field_path": field_path,
        "conclusion": conclusion,
        "claim_type": claim_type,
        "assertion_status": assertion_status,
        "author_confidence": author_confidence,
        "extractor_method": extractor_method,
        "extractor_confidence": extractor_confidence,
        "evidence_strength": evidence_strength,
        "evidence_ids": list(dict.fromkeys(evidence_ids)),
        "rationale": rationale,
    }


def build_field_assessments(
    event: dict,
    *,
    llm_claims: list[dict] | None = None,
    deterministic_event: dict | None = None,
) -> list[dict]:
    deterministic_evidence_ids = {
        item["evidence_id"] for item in (deterministic_event or {}).get("evidence", [])
    }
    entries: list[tuple[str, object, list[str], dict | None]] = [
        ("event.identity.event_name", event["identity"]["event_name"], event["identity"]["evidence_ids"], None),
        ("event.identity.event_type", event["identity"]["event_type"], event["identity"]["evidence_ids"], None),
        ("event.time", {key: event["time"].get(key) for key in ["start", "end", "precision", "description"]}, event["time"]["evidence_ids"], None),
        ("event.status", event["status"]["value"], event["status"]["evidence_ids"], None),
        ("event.ai_involvement", {key: event["ai_involvement"].get(key) for key in ["roles", "stages", "autonomy_level", "human_role", "output_handling"]}, event["ai_involvement"]["evidence_ids"], None),
    ]
    groups = [
        ("artifacts", event.get("artifacts", []), None),
        ("attribution.actors", event.get("attribution", {}).get("actors", []), "actor"),
        ("targets", event.get("targets", []), None),
        ("ai_signals.toolchain", event.get("ai_signals", {}).get("toolchain", []), None),
        ("ai_signals.prompts", event.get("ai_signals", {}).get("prompts", []), None),
        ("ai_signals.code_style", event.get("ai_signals", {}).get("code_style", []), None),
        ("key_behaviors", event.get("key_behaviors", []), None),
        ("outcomes", event.get("outcomes", []), None),
        ("limitations", event.get("limitations", []), None),
    ]
    for group_name, values, marker in groups:
        for index, value in enumerate(values):
            conclusion = {key: item for key, item in value.items() if key not in {"evidence_ids", "artifact_id"}}
            entries.append((f"event.{group_name}[{index}]", conclusion, value.get("evidence_ids", []), value if marker == "actor" else None))
    assessments = []
    for field_path, conclusion, evidence_ids, actor in entries:
        if not evidence_ids:
            continue
        assessments.append(
            assess_field(
                event,
                field_path,
                conclusion,
                evidence_ids,
                llm_claims=llm_claims,
                deterministic_evidence_ids=deterministic_evidence_ids,
                actor=actor,
            )
        )
    return assessments
