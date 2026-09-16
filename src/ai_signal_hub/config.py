from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_ROOT = PROJECT_ROOT.parent


def _path_env(name: str, default: Path) -> Path:
    value = os.getenv(name)
    return Path(value).expanduser().resolve() if value else default.resolve()


@dataclass(frozen=True)
class Settings:
    project_root: Path = PROJECT_ROOT
    workspace_root: Path = WORKSPACE_ROOT
    data_dir: Path = _path_env("AI_SIGNAL_HUB_DATA_DIR", PROJECT_ROOT / "data")
    legacy_sample_project: Path = _path_env(
        "AI_SIGNAL_HUB_LEGACY_SAMPLE_PROJECT", WORKSPACE_ROOT / "ai_signal_demo"
    )
    legacy_report_project: Path = _path_env(
        "AI_SIGNAL_HUB_LEGACY_REPORT_PROJECT", WORKSPACE_ROOT / "报告信息抽取"
    )
    max_upload_bytes: int = int(os.getenv("AI_SIGNAL_HUB_MAX_UPLOAD_BYTES", "104857600"))
    host: str = os.getenv("AI_SIGNAL_HUB_HOST", "127.0.0.1")
    port: int = int(os.getenv("AI_SIGNAL_HUB_PORT", "8000"))

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
