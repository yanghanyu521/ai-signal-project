from __future__ import annotations

import json
import io
import sys
import zipfile
from pathlib import Path

import httpx

from ai_signal_hub.config import Settings
from ai_signal_hub.static_analysis.llm import SampleLLMClient
from ai_signal_hub.static_analysis.materials import build_material_index, split_large_units
from ai_signal_hub.static_analysis.pipeline import run_static_analysis
from ai_signal_hub.static_analysis.query import StaticQueryService
from ai_signal_hub.static_analysis.docker_tools import DockerStaticTools
from ai_signal_hub.database import Database
from ai_signal_hub.repository import Repository


SOURCE = b'''MODEL_ALIAS = "nebula-not-in-rules"
PROMPT = "\xe8\xaf\xb7\xe5\xaf\xb9\xe8\xbf\x99\xe6\xae\xb5\xe8\xae\xb0\xe5\xbd\x95\xe8\xbf\x9b\xe8\xa1\x8c\xe5\x88\x86\xe7\xb1\xbb"

def build_payload():
    return {"deployment": MODEL_ALIAS, "dialog": [{"speaker": "human", "body": PROMPT}]}

def send(client):
    return client.invoke(build_payload())
'''


def sample() -> dict:
    return {"sha256": "a" * 64, "language": "python", "source_encoding": "utf-8"}


def test_python_material_index_has_real_functions_and_relations() -> None:
    index = build_material_index(SOURCE, sample())
    assert index.status == "completed"
    assert index.capabilities["dataflow"] is True
    send = next(unit for unit in index.units if "def send" in unit.content)
    assert any(value.startswith("unit:") for value in send.references["calls"])
    build = next(unit for unit in index.units if "def build_payload" in unit.content)
    definitions = StaticQueryService(index).execute("get_definitions", {"unit_id": build.unit_id})
    assert any("nebula-not-in-rules" in unit["content"] for unit in definitions["units"])


def test_query_layer_rejects_arbitrary_file_or_shell_requests() -> None:
    service = StaticQueryService(build_material_index(SOURCE, sample()))
    assert service.execute("read_file", {"path": "C:/Windows/System32/config/SAM"})["status"] == "rejected"
    assert service.execute("execute_shell", {"command": "whoami"})["status"] == "rejected"
    assert service.execute("get_unit", {"unit_id": "unit:not-indexed"})["reason"] == "unknown_unit_id"


def test_local_llm_chain_accepts_unknown_names_and_rejects_bad_citations(tmp_path: Path) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append(body)
        units = json.loads(body["messages"][1]["content"])["units"]
        facts = []
        unit = next((item for item in units if "nebula-not-in-rules" in item["content"]), None)
        invoke_unit = next((item for item in units if "invoke" in item["content"]), None)
        if unit is not None:
            facts.extend([
                {"signal_group": "toolchain", "raw_value": "nebula-not-in-rules",
                 "normalized_value": {"model_identifier_raw": "nebula-not-in-rules"},
                 "source_unit_ids": [unit["unit_id"]], "role": "application",
                 "semantic_review_status": "needs_review", "limitations": []},
                {"signal_group": "toolchain", "raw_value": "invented-by-model",
                 "normalized_value": {"model_identifier_raw": "invented-by-model", "model_vendor": "GuessCo"},
                 "source_unit_ids": [unit["unit_id"]], "role": "application"},
            ])
        if invoke_unit is not None:
            facts.append({"signal_group": "toolchain", "raw_value": "invoke",
                          "normalized_value": {}, "source_unit_ids": [invoke_unit["unit_id"]],
                          "role": "application"})
        response = {"facts": facts, "queries": []}
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(response)}}],
                                         "usage": {"prompt_tokens": 20}})

    client = SampleLLMClient(base_url="http://127.0.0.1:11434/v1", model="fixture-model",
                             api_key=None, allow_remote=False, transport=httpx.MockTransport(handler))
    result = run_static_analysis(SOURCE, sample(), tmp_path, llm_client=client, max_input_tokens=10000)
    facts = result["run"]["facts"]
    assert any(fact["raw_value"] == "nebula-not-in-rules" for fact in facts)
    assert any(item["reason"] == "raw_value_not_in_material" for item in result["run"]["rejected_facts"])
    assert any(item["reason"] == "toolchain_fact_has_no_typed_identity"
               for item in result["run"]["rejected_facts"])
    assert result["run"]["coverage"]["screened_units"] == result["materials"]["unit_count"]
    assert calls


def test_sample_llm_reuses_deepseek_defaults_and_cc_api(monkeypatch) -> None:
    for name in ("SAMPLE_LLM_API_KEY", "DEEPSEEK_API_KEY", "SAMPLE_LLM_MODEL",
                 "DEEPSEEK_MODEL", "SAMPLE_LLM_BASE_URL", "DEEPSEEK_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("cc-api", "fixture-secret")
    settings = Settings()
    assert settings.sample_llm_enabled is True
    assert settings.sample_llm_api_key == "fixture-secret"
    assert settings.sample_llm_model == "deepseek-v4-flash"
    assert settings.sample_llm_base_url == "https://api.deepseek.com"
    assert settings.sample_llm_max_requests == 128


def test_deepseek_v4_payload_uses_thinking_and_no_total_budget(monkeypatch) -> None:
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(200, json={
            "choices": [{"message": {"content": '{"facts": [], "queries": []}'}}],
            "usage": {"total_tokens": 10},
        })

    monkeypatch.setenv("SAMPLE_LLM_THINKING", "enabled")
    monkeypatch.setenv("SAMPLE_LLM_REASONING_EFFORT", "low")
    client = SampleLLMClient(
        base_url="https://api.deepseek.com", model="deepseek-v4-flash",
        api_key="fixture", allow_remote=True, transport=httpx.MockTransport(handler),
    )
    client.analyze([])
    assert captured["thinking"] == {"type": "enabled"}
    assert captured["reasoning_effort"] == "low"
    assert "temperature" not in captured


def test_remote_sample_llm_requires_explicit_policy() -> None:
    try:
        SampleLLMClient(base_url="https://external.example/v1", model="x", api_key=None, allow_remote=False)
    except ValueError as exc:
        assert "外发未启用" in str(exc)
    else:
        raise AssertionError("remote sample service must be rejected by default")


def test_request_limit_is_visible_not_silent(tmp_path: Path) -> None:
    class NeverCalled:
        def analyze(self, units, context=None):
            raise AssertionError("unit beyond request cap must not be sent")

    result = run_static_analysis(SOURCE, sample(), tmp_path, llm_client=NeverCalled(), max_requests=0)
    assert result["run"]["status"] == "partial"
    assert result["run"]["coverage"]["screened_units"] == 0
    assert result["run"]["coverage"]["unprocessed_unit_ids"]
    assert result["run"]["budget"]["configured_total_token_budget"] is None


def test_javascript_powershell_and_binary_have_truthful_material_status() -> None:
    js = build_material_index(b"function run(x) { return client.invoke(x); }", {
        "sha256": "b" * 64, "language": "javascript", "source_encoding": "utf-8"})
    ps = build_material_index(b"function Invoke-Thing { param($x) Write-Output $x }", {
        "sha256": "c" * 64, "language": "powershell", "source_encoding": "utf-8"})
    binary = build_material_index(b"MZ\x00\x00example-model-marker\x00", {
        "sha256": "d" * 64, "language": None, "file_type": "PE32"})
    assert js.status == ps.status == "partial"
    assert js.capabilities["functions"] is True and js.capabilities["xrefs"] is False
    assert ps.capabilities["functions"] is True and ps.capabilities["dataflow"] is False
    assert binary.status == "partial" and "no_decompiler_material" in binary.limitations


def test_sample_analysis_runs_are_append_only(tmp_path: Path) -> None:
    database = Database(tmp_path / "knowledge.db")
    database.initialize()
    repository = Repository(database)
    base = {
        "schema_version": "0.2", "sample": {"sha256": "e" * 64, "size": 1,
        "file_type": "text", "language": "python", "recoverability": "original_source"},
        "features": {"toolchain": {"evidence": []}, "prompt": {"embedded_prompts": []},
                     "code_style": {}, "recovery": {}},
        "classification": {"llm_involvement": {"label": "unknown"},
                           "model_attribution": {}}, "errors": [],
    }
    repository.upsert_sample(base)
    changed = json.loads(json.dumps(base))
    changed["classification"]["llm_involvement"]["label"] = "probable"
    repository.upsert_sample(changed)
    runs = repository.sample_analysis_runs("e" * 64)
    assert len(runs) == 2
    assert {run["result_json"]["classification"]["llm_involvement"]["label"] for run in runs} == {"unknown", "probable"}


def test_oversized_unit_is_split_without_content_loss() -> None:
    source = ("def huge():\n" + "    value = '" + ("x" * 9000) + "'\n").encode()
    index = build_material_index(source, {"sha256": "f" * 64, "language": "python", "source_encoding": "utf-8"})
    original = next(unit.content for unit in index.units if unit.kind == "source_function")
    split_large_units(index, 512)
    fragments = [unit for unit in index.units if unit.kind == "source_function_fragment"]
    assert len(fragments) > 1
    assert "".join(unit.content for unit in fragments) == original
    assert fragments[0].references["next"] == [fragments[1].unit_id]


class FixtureDockerTools(DockerStaticTools):
    def _image_available(self, image: str) -> bool:
        return True

    def _run(self, kind, image, input_dir, output_dir, filename):
        if kind == "jadx":
            path = output_dir / "sources" / "fixture" / "Client.java"
            path.parent.mkdir(parents=True)
            path.write_text('''class Client {
    String model = "docker-nebula";
    void send() {
        client.invoke(model);
    }
}
''', encoding="utf-8")
        else:
            (output_dir / "ghidra.jsonl").write_text("\n".join([
                json.dumps({"record_type": "metadata", "tool": "ghidra", "version": "fixture",
                            "language": "x86:LE:64:default"}),
                json.dumps({"record_type": "function", "name": "entry", "address": "00401000",
                            "calls": ["invoke_model"], "content": "void entry(void) { invoke_model(); }",
                            "decompile_completed": True}),
            ]), encoding="utf-8")
        return {"tool": kind, "image": image, "status": "completed", "exit_code": 0,
                "network": "none", "log": "fixture"}


def test_docker_adapters_add_real_decompiler_material_contract(tmp_path: Path) -> None:
    tools = FixtureDockerTools(enabled=True, jadx_image="fixture/jadx", ghidra_image="fixture/ghidra",
                               docker_executable=sys.executable)
    apk_buffer = io.BytesIO()
    with zipfile.ZipFile(apk_buffer, "w") as archive:
        archive.writestr("classes.dex", b"dex\n035\x00fixture")
    apk_data = apk_buffer.getvalue()
    apk_sample = {"sha256": "1" * 64, "language": None, "file_type": "Zip archive"}
    apk = tools.augment(build_material_index(apk_data, apk_sample), apk_data, apk_sample, tmp_path / "apk")
    assert any(unit.representation == "decompiled_source" and "docker-nebula" in unit.content for unit in apk.units)
    assert any(unit.kind == "decompiled_method" and "client.invoke" in unit.content for unit in apk.units)
    assert apk.capabilities["functions"] is True
    assert apk.tool_runs[-1]["status"] == "completed"

    native_data = b"MZ\x00\x00harmless fixture"
    native_sample = {"sha256": "2" * 64, "language": None, "file_type": "PE32"}
    native = tools.augment(build_material_index(native_data, native_sample), native_data, native_sample,
                           tmp_path / "native")
    function = next(unit for unit in native.units if unit.kind == "decompiled_function")
    assert function.location["virtual_address"] == "00401000"
    assert function.references["calls"] == ["invoke_model"]
