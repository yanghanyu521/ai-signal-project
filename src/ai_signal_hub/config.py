from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_ROOT = PROJECT_ROOT.parent


def _path_env(name: str, default: Path) -> Path:
    value = os.getenv(name)
    return Path(value).expanduser().resolve() if value else default.resolve()


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    project_root: Path = PROJECT_ROOT
    workspace_root: Path = WORKSPACE_ROOT
    data_dir: Path = _path_env("AI_SIGNAL_HUB_DATA_DIR", PROJECT_ROOT / "data")
    legacy_sample_project: Path = _path_env(
        "AI_SIGNAL_HUB_SAMPLE_COMPONENT_DIR", PROJECT_ROOT / "components" / "ai_signal_demo"
    )
    legacy_report_project: Path = _path_env(
        "AI_SIGNAL_HUB_REPORT_COMPONENT_DIR", PROJECT_ROOT / "components" / "report_extractor"
    )
    seed_data_dir: Path = _path_env(
        "AI_SIGNAL_HUB_SEED_DATA_DIR", PROJECT_ROOT / "components" / "seed_data"
    )
    max_upload_bytes: int = int(os.getenv("AI_SIGNAL_HUB_MAX_UPLOAD_BYTES", "104857600"))
    host: str = os.getenv("AI_SIGNAL_HUB_HOST", "127.0.0.1")
    port: int = int(os.getenv("AI_SIGNAL_HUB_PORT", "8000"))
    sample_llm_enabled: bool = field(default_factory=lambda: _bool_env("SAMPLE_LLM_ENABLED", True))
    sample_llm_base_url: str = field(default_factory=lambda: os.getenv(
        "SAMPLE_LLM_BASE_URL", os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    ))
    sample_llm_model: str = field(default_factory=lambda: os.getenv(
        "SAMPLE_LLM_MODEL", os.getenv("DEEPSEEK_MODEL", "deepseek-v4-flash")
    ))
    sample_llm_api_key: str | None = field(default_factory=lambda: (
        os.getenv("SAMPLE_LLM_API_KEY") or os.getenv("DEEPSEEK_API_KEY") or os.getenv("cc-api")
    ))
    sample_llm_allow_remote: bool = field(default_factory=lambda: _bool_env("SAMPLE_LLM_ALLOW_REMOTE", False))
    sample_llm_transfer_policy: str = field(default_factory=lambda: os.getenv(
        "SAMPLE_LLM_TRANSFER_POLICY", "local_only"
    ).strip().lower())
    sample_llm_mode: str = field(default_factory=lambda: os.getenv("SAMPLE_LLM_MODE", "coverage"))
    sample_llm_max_requests: int = field(default_factory=lambda: int(os.getenv("SAMPLE_LLM_MAX_REQUESTS", "128")))
    sample_llm_max_reasoning_rounds: int = field(default_factory=lambda: int(os.getenv("SAMPLE_LLM_MAX_REASONING_ROUNDS", "4")))
    sample_llm_max_queries_per_round: int = field(default_factory=lambda: int(os.getenv("SAMPLE_LLM_MAX_QUERIES_PER_ROUND", "8")))
    sample_llm_max_context_units: int = field(default_factory=lambda: int(os.getenv("SAMPLE_LLM_MAX_CONTEXT_UNITS", "32")))
    sample_llm_timeout_seconds: float = field(default_factory=lambda: float(os.getenv("SAMPLE_LLM_TIMEOUT_SECONDS", "240")))
    sample_llm_max_input_tokens: int = field(default_factory=lambda: int(os.getenv("SAMPLE_LLM_MAX_INPUT_TOKENS", "64000")))
    sample_llm_max_output_tokens: int = field(default_factory=lambda: int(os.getenv("SAMPLE_LLM_MAX_OUTPUT_TOKENS", "16384")))
    static_tools_docker_enabled: bool = field(default_factory=lambda: _bool_env("STATIC_TOOLS_DOCKER_ENABLED", True))
    jadx_docker_image: str = field(default_factory=lambda: os.getenv("JADX_DOCKER_IMAGE", "ai-signal/jadx:1.5.6"))
    ghidra_docker_image: str = field(default_factory=lambda: os.getenv("GHIDRA_DOCKER_IMAGE", "ai-signal/ghidra:12.1.3"))
    static_tool_timeout_seconds: int = field(default_factory=lambda: int(os.getenv("STATIC_TOOL_TIMEOUT_SECONDS", "600")))

    @property
    def database_path(self) -> Path:
        return self.data_dir / "knowledge.db"

    @property
    def quarantine_dir(self) -> Path:
        return self.data_dir / "quarantine"

    @property
    def sample_artifact_dir(self) -> Path:
        return self.data_dir / "artifacts" / "samples"

    @property
    def report_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def generated_report_dir(self) -> Path:
        return self.data_dir / "generated_reports"

    @property
    def report_template_path(self) -> Path:
        return self.project_root / "templates" / "global_report.md.j2"

    def ensure_directories(self) -> None:
        for path in (
            self.data_dir,
            self.quarantine_dir,
            self.sample_artifact_dir,
            self.report_dir,
            self.generated_report_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)


settings = Settings()
