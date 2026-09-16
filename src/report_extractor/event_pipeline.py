from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator

from .ingest import find_report_seed, group_report_seeds
from .parsers import parse_document
from .utils import SHA256_RE, normalize_space, sha256_bytes, sha256_text, stable_id, utc_now, write_json


# P0.2 受控事件词典只负责切分事件和规范别名；字段事实仍须由报告原文命中后才生成。
EVENT_PROFILES = [
    {
        "name": "PROMPTFLUX", "aliases": ["PROMPTFLUX"], "event_type": "malware", "status": "experimental",
        "sample": {"family": "PROMPTFLUX", "role": "dropper", "language": "VBScript", "file_type": "script"},
        "rules": [
            ("toolchain", r"Gemini.*API|Gemini API", {"provider": "Google", "model": None, "interface": "Gemini API", "purpose": "生成或重写 VBScript 以实现混淆和规避", "stage": "execution"}),
            ("toolchain", r"gemini-1\.5-flash-latest", {"provider": "Google", "model": "gemini-1.5-flash-latest", "interface": "Gemini API", "purpose": "生成规避杀毒软件的新代码", "stage": "execution"}),
            ("prompt", r"output only the code itself", {"purpose": "代码生成与规避", "summary": "要求生成用于杀毒规避的 VBScript，且只输出代码。", "constraints": ["仅输出代码", "VBScript", "杀毒规避"], "effectiveness": None}),
            ("code_style", r"rewrite the malware's entire source code|self-modification|metamorphic script", {"feature": "运行时自我重写/变形设计", "assessment": "报告显示自修改目标明确，但部分功能仍被注释。"}),
            ("behavior", r"Startup folder.*persistence", "将重写后的版本保存到启动目录以建立持久化"),
            ("behavior", r"removable drives.*network shares", "复制到可移动驱动器和映射网络共享进行传播"),
            ("limitation", r"does not demonstrate an ability to compromise|does not have the ability to compromise", "处于研发/测试阶段，当前状态未展示攻陷受害网络或设备的能力。"),
            ("attribution", r"unattributed to a specific threat actor", {"actor": None, "country_or_region": None, "confidence": "not_stated"}),
        ],
    },
    {
        "name": "FRUITSHELL", "aliases": ["FRUITSHELL"], "event_type": "malware", "status": "observed_in_operations",
        "sample": {"family": "FRUITSHELL", "role": "reverse_shell", "language": "PowerShell", "file_type": "script"},
        "rules": [
            ("prompt", r"hard-coded prompts meant to bypass", {"purpose": "规避 AI 安全分析", "summary": "内置提示词试图绕过由 LLM 驱动的安全检测或分析。", "constraints": [], "effectiveness": None}),
            ("behavior", r"remote connection|arbitrary commands on a compromised system", "连接命令控制服务器并在受害主机执行任意命令"),
        ],
    },
    {
        "name": "PROMPTLOCK", "aliases": ["PROMPTLOCK", "PromptLock"], "event_type": "malware", "status": "proof_of_concept",
        "sample": {"family": "PROMPTLOCK", "role": "ransomware", "language": "Go", "file_type": "cross-platform executable"},
        "rules": [
            ("toolchain", r"LLM to dynamically generate|generate ransomware code", {"provider": None, "model": None, "interface": "LLM API", "purpose": "动态生成并执行恶意 Lua 脚本", "stage": "execution"}),
            ("prompt", r"prompts observed.*prompting techniques|dynamically generate", {"purpose": "恶意脚本生成", "summary": "提示模型生成用于侦察、窃取和加密的 Lua 脚本。", "constraints": ["运行时生成"], "effectiveness": None}),
            ("behavior", r"filesystem reconnaissance.*data exfiltration", "执行文件系统侦察、数据外传和文件加密"),
            ("limitation", r"proof[- ]of[- ]concept research|proof of concept", "属于概念验证研究，并非已确认的真实勒索行动。"),
        ],
    },
    {
        "name": "PROMPTSTEAL", "aliases": ["PROMPTSTEAL", "PromptSteal", "Promptsteal", "LAMEHUG", "LameHug", "Lamehug"], "event_type": "malware", "status": "observed_in_operations",
        "sample": {"family": "PROMPTSTEAL", "aliases": ["LAMEHUG"], "role": "data_miner", "language": "Python", "file_type": "PyInstaller executable"},
        "rules": [
            ("attribution", r"APT28.*FROZENLAKE|linked to APT28", {"actor": "APT28 / FROZENLAKE", "country_or_region": "Russia", "confidence": "high"}),
            ("target", r"malware against Ukraine", {"name": None, "sector": None, "country_or_region": "Ukraine", "status": "targeted"}),
            ("toolchain", r"Qwen2\.5-Coder-32B-Instruct", {"provider": "Hugging Face", "model": "Qwen2.5-Coder-32B-Instruct", "interface": "Hugging Face API", "purpose": "生成一行 Windows 系统命令", "stage": "execution"}),
            ("prompt", r"output commands to generate system information|collect system information", {"purpose": "系统信息收集", "summary": "生成收集系统信息的命令并由恶意软件在本地执行。", "constraints": ["输出命令"], "effectiveness": "报告称输出会被直接执行"}),
            ("prompt", r"copy documents to a specified directory|documents in specific folders", {"purpose": "定向文档收集", "summary": "生成复制指定类型文档到指定目录的命令。", "constraints": ["指定目录"], "effectiveness": "报告称结果随后被外传"}),
            ("behavior", r"blindly executed locally|executes the commands.*sends the collected data", "盲目执行 LLM 生成的本地命令并外传结果"),
            ("limitation", r"stolen API tokens|keys were leaked", "报告判断其可能使用泄露或被盗的 API 凭据。"),
        ],
    },
    {
        "name": "QUIETVAULT", "aliases": ["QUIETVAULT"], "event_type": "malware", "status": "observed_in_operations",
        "sample": {"family": "QUIETVAULT", "role": "credential_stealer", "language": "JavaScript", "file_type": "script"},
        "rules": [
            ("toolchain", r"on-host installed AI CLI tools", {"provider": None, "model": None, "interface": "on-host AI CLI", "purpose": "搜索感染系统中的潜在秘密", "stage": "post_exploitation"}),
            ("prompt", r"leverages an AI prompt", {"purpose": "秘密发现", "summary": "调用本机 AI CLI 搜索除 GitHub/NPM 令牌之外的潜在秘密。", "constraints": [], "effectiveness": None}),
            ("behavior", r"targets GitHub and NPM tokens", "窃取 GitHub 与 NPM 令牌"),
            ("behavior", r"exfiltrate these files to GitHub", "通过公开 GitHub 仓库外传凭据和文件"),
        ],
    },
    {
        "name": "MalTerminal", "aliases": ["MalTerminal"], "event_type": "malware", "status": "proof_of_concept",
        "sample": {"family": "MalTerminal", "role": "malware_generator", "language": "Python", "file_type": "Python scripts and Windows executables"},
        "rules": [
            ("toolchain", r"OpenAI GPT-4", {"provider": "OpenAI", "model": "GPT-4", "interface": "Chat Completions API", "purpose": "动态生成勒索软件代码或反向 Shell", "stage": "execution"}),
            ("prompt", r"dynamically generate ransomware code or a reverse shell", {"purpose": "恶意代码生成", "summary": "动态生成勒索软件代码或反向 Shell。", "constraints": [], "effectiveness": None}),
            ("behavior", r"generate ransomware code or a reverse shell", "在运行时生成勒索软件代码或反向 Shell"),
            ("limitation", r"PoC scripts|proof.of.concept", "报告样本集包含恶意软件生成器 PoC 脚本。"),
        ],
    },
    {
        "name": "GTG-1002", "aliases": ["GTG-1002"], "event_type": "cyber_espionage_campaign", "status": "confirmed_live_operations",
        "sample": None,
        "rules": [
            ("attribution", r"high confidence.*Chinese state-sponsored", {"actor": "GTG-1002", "country_or_region": "China", "confidence": "high"}),
            ("target", r"roughly 30 entities", {"name": "roughly 30 entities", "sector": "technology and government among others", "country_or_region": None, "status": "targeted; a handful successfully intruded"}),
            ("toolchain", r"Claude Code.*Model Context Protocol|Model Context Protocol.*MCP", {"provider": "Anthropic", "model": "Claude Code", "interface": "MCP tools and autonomous agents", "purpose": "编排多阶段入侵与技术子任务", "stage": "full_attack_lifecycle"}),
            ("prompt", r"carefully crafted prompts and established personas", {"purpose": "规避安全上下文识别", "summary": "将攻击链拆成看似正当的孤立技术任务，并以精心设计的提示和角色诱导模型执行。", "constraints": ["任务拆分", "既定角色"], "effectiveness": "报告称促使 Claude 执行攻击链组件"}),
            ("code_style", r"decomposed complex multi-stage attacks into discrete technical tasks", {"feature": "编排器-子代理式任务分解", "assessment": "复杂攻击被拆分为离散技术任务，由多个 Claude 子代理执行。"}),
            ("behavior", r"reconnaissance, vulnerability discovery, exploitation, lateral movement", "覆盖侦察、漏洞发现与利用、横向移动、凭据收集、数据分析和外传"),
            ("behavior", r"80-90% of tactical operations", "AI 独立执行约 80%-90% 的战术操作"),
            ("limitation", r"frequently overstated.*fabricated data|hallucination", "Claude 会夸大结果或编造数据，攻击者仍需验证输出。"),
        ],
    },
    {
        "name": "Hermes MOF intrusion", "aliases": ["Hermes"], "context_terms": ["Hermes", "Hades"], "event_type": "intrusion", "status": "observed",
        "sample": {"family": "Hades", "role": "implant", "language": "Go", "file_type": "Windows and Linux executables"},
        "rules": [
            ("target", r"targeting Thailand's Ministry of Finance|Thailand's Ministry of Finance Targeted", {"name": "Thailand Ministry of Finance", "sector": "government/public finance", "country_or_region": "Thailand", "status": "compromised multiple systems"}),
            ("toolchain", r"Hermes.*autonomous AI agent.*YOLO", {"provider": None, "model": "Hermes", "interface": "autonomous AI agent (YOLO mode)", "purpose": "无人值守地执行主机枚举、文件遍历和命令", "stage": "post_exploitation"}),
            ("prompt", r"unattended or YOLO mode.*bypassing approval", {"purpose": "无人值守执行", "summary": "启用 YOLO 模式，跳过危险命令的批准提示。", "constraints": ["绕过批准提示"], "effectiveness": "日志显示代理执行了主机枚举和文件遍历"}),
            ("behavior", r"enumerating ministry hosts.*traversing files", "枚举部委主机、遍历文件并收集相邻主机的 LinPEAS 输出"),
            ("behavior", r"compromise multiple systems", "在财政部网络内攻陷多个系统"),
            ("limitation", r"initial access was.*not.*evident", "已审查材料无法确定初始访问方式。"),
            ("limitation", r"do not have evidence confirming or denying VShell", "证据不足以确认或否认 VShell 是否用于该目标。"),
        ],
    },
]


def _event_context(blocks: list[dict], aliases: list[str], radius: int = 4) -> list[dict]:
    hit_indexes: set[int] = set()
    alias_re = re.compile("|".join(re.escape(alias) for alias in aliases), re.I)
    for pos, block in enumerate(blocks):
        if alias_re.search(block.get("text", "")) or alias_re.search(block.get("section") or ""):
            hit_indexes.update(range(max(0, pos - radius), min(len(blocks), pos + radius + 1)))
    return [blocks[index] for index in sorted(hit_indexes)]


def _excerpt(block: dict, match: re.Match[str], limit: int = 700) -> str:
    text = block["text"]
    if len(text) <= limit:
        return text
    start = max(0, match.start() - limit // 3)
    end = min(len(text), start + limit)
    start = max(0, end - limit)
    return text[start:end].strip()


def _add_evidence(event: dict, block: dict, match: re.Match[str]) -> str:
    excerpt = _excerpt(block, match)
    evidence_id = stable_id("evidence", block["block_id"], excerpt)
    if not any(item["evidence_id"] == evidence_id for item in event["evidence"]):
        event["evidence"].append({
            "evidence_id": evidence_id,
            "source": "report",
            "block_id": block["block_id"],
            "page": block.get("page"),
            "section": block.get("section"),
            "excerpt": excerpt,
            "excerpt_sha256": sha256_text(excerpt),
        })
    return evidence_id


def _first_match(blocks: list[dict], pattern: str) -> tuple[dict, re.Match[str]] | None:
    compiled = re.compile(pattern, re.I | re.S)
    for block in blocks:
        match = compiled.search(block.get("text", ""))
        if match:
            return block, match
    return None


def _append_unique(items: list[dict], item: dict, keys: tuple[str, ...]) -> None:
    for existing in items:
        if all(existing.get(key) == item.get(key) for key in keys):
            existing["evidence_ids"] = list(dict.fromkeys(existing.get("evidence_ids", []) + item.get("evidence_ids", [])))
            return
    items.append(item)


def _extract_event(profile: dict, blocks: list[dict], report_id: str, seed_group: dict | None, *, full_context: bool = False) -> dict:
    context = blocks if full_context else _event_context(blocks, profile.get("context_terms", profile["aliases"]), radius=10)
    event = {
        "event_id": stable_id("event", report_id, profile["name"]),
        "event_name": profile["name"],
        "aliases": list(dict.fromkeys(profile["aliases"])),
        "event_type": profile["event_type"],
        "status": profile["status"],
        "attribution": {"actor": None, "country_or_region": None, "confidence": "not_stated", "evidence_ids": []},
        "targets": [], "samples": [],
        "ai_signals": {"toolchain": [], "prompt": [], "code_style": []},
        "key_behaviors": [], "limitations": [], "evidence": [],
    }
    name_hit = _first_match(context, "|".join(re.escape(alias) for alias in profile["aliases"]))
    sample_evidence: list[str] = []
    if name_hit:
        sample_evidence.append(_add_evidence(event, *name_hit))
    for kind, pattern, value in profile["rules"]:
        hit = _first_match(context, pattern)
        if not hit:
            continue
        evidence_id = _add_evidence(event, *hit)
        if kind == "attribution":
            event["attribution"] = {**deepcopy(value), "evidence_ids": [evidence_id]}
        elif kind == "target":
            _append_unique(event["targets"], {**deepcopy(value), "evidence_ids": [evidence_id]}, ("name", "country_or_region"))
        elif kind in {"toolchain", "prompt", "code_style"}:
            keys = {"toolchain": ("provider", "model", "interface", "purpose"), "prompt": ("purpose", "summary"), "code_style": ("feature",)}[kind]
            _append_unique(event["ai_signals"][kind], {**deepcopy(value), "evidence_ids": [evidence_id]}, keys)
        elif kind == "behavior":
            _append_unique(event["key_behaviors"], {"behavior": value, "evidence_ids": [evidence_id]}, ("behavior",))
        elif kind == "limitation":
            _append_unique(event["limitations"], {"text": value, "evidence_ids": [evidence_id]}, ("text",))
    if profile.get("sample"):
        sample = {
            "family": profile["sample"]["family"],
            "aliases": profile["sample"].get("aliases", []),
            "sha256": [],
            "seed_rows": [],
            "role": profile["sample"].get("role"),
            "language": profile["sample"].get("language"),
            "file_type": profile["sample"].get("file_type"),
            "evidence_ids": sample_evidence,
        }
        for block in context:
            if any(re.search(re.escape(alias), block.get("text", ""), re.I) for alias in profile["aliases"]):
                hashes = [value.lower() for value in SHA256_RE.findall(block.get("text", ""))]
                if hashes:
                    match = re.search(re.escape(hashes[0]), block["text"], re.I)
                    if match:
                        sample["evidence_ids"].append(_add_evidence(event, block, match))
                    sample["sha256"].extend(hashes)
        if seed_group:
            for hint in seed_group.get("sample_hints", []):
                hint_text = f"{hint.get('event_hint') or ''} {hint.get('sample_hint') or ''}".lower()
                if any(alias.lower() in hint_text for alias in profile["aliases"]):
                    sample["seed_rows"].append(hint["source_row"])
        sample["sha256"] = list(dict.fromkeys(sample["sha256"]))
        sample["seed_rows"] = list(dict.fromkeys(sample["seed_rows"]))
        sample["evidence_ids"] = list(dict.fromkeys(sample["evidence_ids"]))
        event["samples"].append(sample)
    return event


def _validate_evidence_refs(result: dict, blocks: list[dict]) -> list[str]:
    block_map = {block["block_id"]: block for block in blocks}
    errors: list[str] = []
    for event in result["events"]:
        evidence_map = {item["evidence_id"]: item for item in event["evidence"]}
        for item in event["evidence"]:
            block = block_map.get(item["block_id"])
            if not block or item["excerpt"] not in block["text"]:
                errors.append(f"{event['event_name']}: evidence {item['evidence_id']} 无法回指原文")
        ref_lists = [event["attribution"]["evidence_ids"]]
        ref_lists += [item["evidence_ids"] for key in ("targets", "samples", "key_behaviors", "limitations") for item in event[key]]
        ref_lists += [item["evidence_ids"] for key in ("toolchain", "prompt", "code_style") for item in event["ai_signals"][key]]
        for refs in ref_lists:
            for ref in refs:
                if ref not in evidence_map:
                    errors.append(f"{event['event_name']}: evidence ref {ref} 不存在")
    return errors


def extract_report_events(
    source_path: str | Path, *, canonical_url: str | None = None, seed_csv: str | Path | None = None,
    seed_url: str | None = None, output_dir: str | Path | None = None, schema_path: str | Path | None = None,
) -> dict:
    source = Path(source_path)
    digest = sha256_bytes(source.read_bytes())
    report_id = stable_id("report", canonical_url or source.name, digest)
    parsed = parse_document(source, report_id)
    blocks = parsed["blocks"]
    grouped = group_report_seeds(seed_csv) if seed_csv else None
    seed_group = find_report_seed(grouped, seed_url or canonical_url) if grouped else None
    present_profiles = [profile for profile in EVENT_PROFILES if _event_context(blocks, profile["aliases"], radius=0)]
    events = [
        _extract_event(profile, blocks, report_id, seed_group, full_context=len(present_profiles) == 1)
        for profile in present_profiles
    ]
    report = {
        "report_id": report_id,
        "title": parsed.get("title") or source.stem,
        "url": canonical_url,
        "publisher": urlsplit(canonical_url).hostname if canonical_url else None,
        "publication_date": parsed.get("publication_date"),
        "content_sha256": digest,
        "source_rows": seed_group.get("source_rows", []) if seed_group else [],
        "seed_hints": seed_group.get("sample_hints", []) if seed_group else [],
    }
    result = {
        "schema_version": "0.2", "report": report, "events": events,
        "extraction": {"pipeline_version": "0.2", "validation_status": "passed", "review_status": "not_reviewed", "errors": []},
    }
    errors = _validate_evidence_refs(result, blocks)
    if schema_path:
        schema = __import__("json").loads(Path(schema_path).read_text(encoding="utf-8"))
        errors.extend(error.message for error in Draft202012Validator(schema).iter_errors(result))
    if errors:
        result["extraction"]["validation_status"] = "failed"
        result["extraction"]["errors"] = [{"stage": "validation", "message": message} for message in errors]
    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        write_json(out / "report.json", report)
        write_json(out / "blocks.json", blocks)
        write_json(out / "events.json", events)
        write_json(out / "report_events.json", result)
    return result
