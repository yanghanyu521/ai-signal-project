from __future__ import annotations

import re
from dataclasses import dataclass, field

from .utils import SHA256_RE, normalize_space, sha256_text, stable_id


FAMILIES = [
    "PROMPTFLUX", "PROMPTSTEAL", "LAMEHUG", "FRUITSHELL", "PROMPTLOCK",
    "QUIETVAULT", "MalTerminal", "Slopoly", "Skynet", "Hades", "HONESTCUE",
]
ACTORS = ["APT28", "FROZENLAKE", "UAC-0001", "GTG-1002", "Coral Sleet", "Hive0163"]
MODELS = [
    "gemini-1.5-flash-latest", "Gemini 1.5 Flash", "Qwen2.5-Coder-32B-Instruct",
    "GPT-4", "GPT-4.1", "gpt-4.1-2025-04-14", "Claude",
]
PROVIDERS = ["Google Gemini API", "Gemini API", "Hugging Face API", "OpenAI chat completions API", "OpenAI API"]
AGENTS = ["Claude Code", "Hermes", "Model Context Protocol", "MCP"]

MODEL_NORMALIZATION = {
    "gemini 1.5 flash": "gemini-1.5-flash",
    "gemini-1.5-flash-latest": "gemini-1.5-flash-latest",
    "qwen2.5-coder-32b-instruct": "qwen2.5-coder-32b-instruct",
    "gpt-4": "gpt-4",
    "gpt-4.1": "gpt-4.1",
    "gpt-4.1-2025-04-14": "gpt-4.1-2025-04-14",
    "claude": "claude",
}


def _find_terms(text: str, terms: list[str]) -> list[tuple[str, tuple[int, int]]]:
    found = []
    for term in terms:
        for match in re.finditer(rf"(?<![\w-]){re.escape(term)}(?![\w-])", text, re.IGNORECASE):
            found.append((text[match.start():match.end()], match.span()))
    return sorted(found, key=lambda item: item[1])


def _excerpt(text: str, start: int, end: int, radius: int = 220) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return text[left:right].strip()


def _assertion(text: str) -> tuple[str, str, str]:
    lower = text.lower()
    if any(term in lower for term in ["no evidence", "not observed", "unable to determine", "无法确定", "没有证据"]):
        return "unknown", "negative_evidence", "implicit"
    if any(term in lower for term in ["likely", "appears", "suggests", "可能", "疑似"]):
        return "likely", "author_assessment", "implicit"
    if any(term in lower for term in ["speculate", "speculation", "推测"]):
        return "speculative", "author_inference", "explicit_low"
    return "asserted", "direct_observation", "not_stated"


@dataclass
class ExtractionState:
    document_id: str
    entities: dict[tuple[str, str], dict] = field(default_factory=dict)
    claims: list[dict] = field(default_factory=list)

    def entity(self, entity_type: str, name: str, normalized: str | None = None, **attributes: object) -> dict:
        normalized_name = normalize_space(normalized or name).lower()
        key = (entity_type, normalized_name)
        if key not in self.entities:
            self.entities[key] = {
                "entity_id": stable_id("entity", entity_type, normalized_name),
                "entity_type": entity_type,
                "name": normalize_space(name),
                "normalized_name": normalized_name,
                "aliases": [],
                "attributes": attributes,
            }
        return self.entities[key]

    def claim(self, subject: dict, predicate: str, obj: dict | object, block: dict, span: tuple[int, int], *, claim_type: str | None = None, assertion_status: str | None = None) -> None:
        excerpt = _excerpt(block["text"], *span)
        inferred_status, inferred_type, author_confidence = _assertion(excerpt)
        object_value = {"entity_id": obj["entity_id"]} if isinstance(obj, dict) and "entity_id" in obj else {"value": obj, "unit": None}
        claim_key = (subject["entity_id"], predicate, str(object_value), block["block_id"], excerpt)
        self.claims.append(
            {
                "claim_id": stable_id("claim", *claim_key),
                "subject_id": subject["entity_id"],
                "predicate": predicate,
                "object": object_value,
                "claim_type": claim_type or inferred_type,
                "assertion_status": assertion_status or inferred_status,
                "author_confidence": author_confidence,
                "extractor_confidence": 0.96,
                "evidence": [
                    {
                        "document_id": self.document_id,
                        "block_id": block["block_id"],
                        "section": block.get("section"),
                        "locator": {
                            "page": block.get("page"),
                            "paragraph": block.get("paragraph"),
                            "char_start": span[0],
                            "char_end": span[1],
                            "table": block.get("table"),
                        },
                        "excerpt": excerpt,
                        "excerpt_sha256": sha256_text(excerpt),
                    }
                ],
            }
        )


def _subject_for_block(state: ExtractionState, block: dict, document_subject: dict) -> dict:
    family_hits = _find_terms(block["text"], FAMILIES)
    if family_hits:
        name, _ = family_hits[0]
        return state.entity("malware_family", name, name.upper())
    actor_hits = _find_terms(block["text"], ACTORS)
    if actor_hits:
        name, _ = actor_hits[0]
        return state.entity("threat_actor", name, name.upper())
    return document_subject


def extract_deterministic(document: dict, blocks: list[dict]) -> dict:
    state = ExtractionState(document["document_id"])
    document_subject = state.entity("campaign", document.get("title") or document["document_id"])
    for block in blocks:
        text = block["text"]
        subject = _subject_for_block(state, block, document_subject)

        for name, span in _find_terms(text, FAMILIES):
            state.entity("malware_family", name, name.upper())
        actor_hits = _find_terms(text, ACTORS)
        for name, span in actor_hits:
            actor = state.entity("threat_actor", name, name.upper())
            if subject["entity_type"] == "malware_family" and actor["entity_id"] != subject["entity_id"]:
                state.claim(subject, "attributed_to", actor, block, span, claim_type="author_assessment")

        for raw, span in _find_terms(text, MODELS):
            normalized = MODEL_NORMALIZATION.get(raw.lower(), raw.lower())
            model = state.entity("ai_model", raw, normalized)
            state.claim(subject, "uses_model", model, block, span)

        for raw, span in _find_terms(text, PROVIDERS):
            provider = state.entity("ai_provider", raw)
            state.claim(subject, "uses_provider", provider, block, span)

        for raw, span in _find_terms(text, AGENTS):
            agent = state.entity("agent_framework", raw)
            state.claim(subject, "uses_agent", agent, block, span)

        for match in SHA256_RE.finditer(text):
            indicator = state.entity("indicator", match.group(0).lower(), attributes_type="sha256")
            state.claim(subject, "has_indicator", indicator, block, match.span())

        for match in re.finditer(r"\bCVE-\d{4}-\d{4,7}\b", text, re.IGNORECASE):
            cve = state.entity("vulnerability", match.group(0).upper())
            state.claim(subject, "performs_technique", cve, block, match.span())

        status_patterns = [
            (r"\bexperimental\b|proof[- ]of[- ]concept|\bPoC\b|development or testing phase", "experimental"),
            (r"observed in operations|live operations|in the wild", "observed_in_operations"),
            (r"successful intrusion|confirmed intrusion|compromised", "confirmed_intrusion"),
        ]
        for pattern, value in status_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                state.claim(subject, "has_operational_status", value, block, match.span())

        role_patterns = [
            (r"self[- ]modification|rewrite its own source|regeneration", "runtime_generator"),
            (r"autonomous (?:attack )?agent|autonomous operator|unattended|YOLO mode", "autonomous_operator"),
            (r"AI-assisted (?:iterative )?development|development accelerator|likely (?:AI|LLM)[- ]generated", "development_accelerator"),
            (r"prompt injection|evade AI detection|bypass detection or analysis by LLM", "analysis_evasion_target"),
        ]
        for pattern, value in role_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                state.claim(subject, "has_ai_role", value, block, match.span(), claim_type="author_assessment")

        autonomy_patterns = [
            (r"80\s*(?:to|-|–)\s*90%", "80-90% tactical work"),
            (r"unattended|YOLO mode", "unattended"),
            (r"human[- ]in[- ]the[- ]loop", "human_in_loop"),
        ]
        for pattern, value in autonomy_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                predicate = "has_ai_work_share" if "%" in value else "has_autonomy_level"
                state.claim(subject, predicate, value, block, match.span())

    unique_claims = {claim["claim_id"]: claim for claim in state.claims}
    return {"entities": list(state.entities.values()), "claims": list(unique_claims.values())}
