from __future__ import annotations

import re
from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path
from typing import Annotated

import uvicorn
from fastapi import Body, FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from . import __version__
from .config import settings
from .database import Database
from .legacy import LegacyAdapters, LegacyUnavailable
from .repository import Repository
from .report_llm import ReportModelConfigurationError, ReportModelError
from .services import HubService
from .storage import UploadTooLarge


database = Database(settings.database_path)
repository = Repository(database)
legacy = LegacyAdapters(settings)
service = HubService(settings, repository, legacy)


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.ensure_directories()
    database.initialize()
    yield


app = FastAPI(
    title="AI 信号提取统一平台 API",
    version=__version__,
    description="恶意样本纯静态 AI 信号、报告事件证据、交叉验证、知识库、统计与报告生成。",
    lifespan=lifespan,
)


class CrossValidationRequest(BaseModel):
    sample_sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    report_id: str
    event_id: str | None = None
    sample_family: str | None = None


class CaseCrossValidationRequest(BaseModel):
    sample_sha256: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    report_id: str | None = None
    event_id: str | None = None


class LegacyImportRequest(BaseModel):
    include_samples: bool = True
    include_events: bool = True
    include_reports: bool = True


class GeneratedReportRequest(BaseModel):
    title: str = Field(default="AI 安全事件与样本分析统计报告", min_length=1, max_length=200)
    date_from: date | None = None
    date_to: date | None = None


class EventContextUpdateRequest(BaseModel):
    organizations: list[str] = Field(default_factory=list, max_length=50)
    countries_or_regions: list[str] = Field(default_factory=list, max_length=50)


@app.get("/api/v1/health", tags=["system"])
def health() -> dict:
    return {
        "status": "ok",
        "version": __version__,
        "database": str(settings.database_path),
        "legacy": legacy.availability(),
        "security_mode": "static_only_local",
    }


@app.post("/api/v1/samples/analyze", tags=["samples"])
def analyze_sample(
    file: Annotated[UploadFile, File(description="单个待静态分析文件")],
    source_case: Annotated[str | None, Form()] = None,
) -> dict:
    try:
        file.file.seek(0)
        return service.analyze_sample(file.file, file.filename, source_case)
    except UploadTooLarge as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except LegacyUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"样本静态分析失败: {exc}") from exc


@app.get("/api/v1/samples", tags=["samples"])
def list_samples(limit: Annotated[int, Query(ge=1, le=500)] = 100, offset: Annotated[int, Query(ge=0)] = 0) -> list[dict]:
    return repository.list_samples(limit, offset)


@app.get("/api/v1/samples/{sha256}", tags=["samples"])
def get_sample(sha256: str) -> dict:
    if not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
        raise HTTPException(status_code=400, detail="无效 SHA-256")
    result = repository.get_sample(sha256)
    if not result:
        raise HTTPException(status_code=404, detail="样本不存在")
    return result


@app.get("/api/v1/samples/{sha256}/associations", tags=["samples"])
def get_sample_associations(
    sha256: str, limit: Annotated[int, Query(ge=1, le=100)] = 10,
    include_unmatched: Annotated[bool, Query(description="同时返回零分及不可比较的样本对，并提供原因")] = False,
) -> dict:
    if not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
        raise HTTPException(status_code=400, detail="无效 SHA-256")
    try:
        return service.similarity.associations(sha256, limit, include_unmatched)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/v1/samples/recluster", tags=["samples"])
def recluster_samples() -> dict:
    try:
        return service.similarity.rebuild()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"样本聚类失败: {exc}") from exc


@app.post("/api/v1/reports/analyze", tags=["reports"])
def analyze_report(
    file: Annotated[UploadFile, File(description="PDF/HTML/DOCX/Markdown/TXT 报告")],
    canonical_url: Annotated[str | None, Form()] = None,
    use_llm: Annotated[bool, Form(description="兼容参数：默认 true；报告不再支持规则模式，false 返回 400")] = True,
    target_name: Annotated[str, Form(description="要从报告中定向抽取的样本或家族名称")] = "",
    target_aliases: Annotated[str | None, Form(description="可选别名，逗号分隔")] = None,
) -> dict:
    try:
        file.file.seek(0)
        return service.analyze_report(
            file.file,
            file.filename,
            canonical_url,
            use_llm,
            target_name,
            [item.strip() for item in (target_aliases or "").replace("，", ",").split(",") if item.strip()],
        )
    except UploadTooLarge as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ReportModelConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ReportModelError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except LegacyUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"报告抽取失败: {exc}") from exc


@app.get("/api/v1/reports", tags=["reports"])
def list_reports(limit: Annotated[int, Query(ge=1, le=500)] = 100, offset: Annotated[int, Query(ge=0)] = 0) -> list[dict]:
    return repository.list_reports(limit, offset)


@app.get("/api/v1/reports/{report_id}", tags=["reports"])
def get_report(report_id: str) -> dict:
    result = repository.get_report(report_id)
    if not result:
        raise HTTPException(status_code=404, detail="报告不存在")
    return result


@app.post("/api/v1/analysis-cases", tags=["analysis-cases"])
def analyze_case(
    sample_file: Annotated[UploadFile | None, File(description="可选：新样本")] = None,
    report_file: Annotated[UploadFile | None, File(description="可选：新报告")] = None,
    case_id: Annotated[str | None, Form()] = None,
    title: Annotated[str | None, Form()] = None,
    notes: Annotated[str | None, Form()] = None,
    existing_sample_sha256: Annotated[str | None, Form()] = None,
    existing_report_id: Annotated[str | None, Form()] = None,
    source_case: Annotated[str | None, Form()] = None,
    canonical_url: Annotated[str | None, Form()] = None,
    use_llm: Annotated[bool, Form(description="报告默认使用大模型；上传报告时 false 返回 400")] = True,
    target_name: Annotated[str | None, Form()] = None,
    target_aliases: Annotated[str | None, Form(description="可选别名，逗号分隔")] = None,
) -> dict:
    try:
        if sample_file:
            sample_file.file.seek(0)
        if report_file:
            report_file.file.seek(0)
        return service.analyze_case(
            case_id=case_id,
            title=title,
            notes=notes,
            sample_source=sample_file.file if sample_file else None,
            sample_filename=sample_file.filename if sample_file else None,
            existing_sample_sha256=existing_sample_sha256,
            report_source=report_file.file if report_file else None,
            report_filename=report_file.filename if report_file else None,
            existing_report_id=existing_report_id,
            source_case=source_case,
            canonical_url=canonical_url,
            use_llm=use_llm,
            target_name=target_name,
            target_aliases=[
                item.strip()
                for item in (target_aliases or "").replace("，", ",").split(",")
                if item.strip()
            ],
        )
    except UploadTooLarge as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ReportModelConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ReportModelError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except LegacyUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"联合分析失败: {exc}") from exc


@app.get("/api/v1/analysis-cases", tags=["analysis-cases"])
def list_analysis_cases(
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[dict]:
    return repository.list_cases(limit, offset)


@app.get("/api/v1/analysis-cases/{case_id}", tags=["analysis-cases"])
def get_analysis_case(case_id: str) -> dict:
    result = repository.get_case(case_id)
    if not result:
        raise HTTPException(status_code=404, detail="分析案例不存在")
    return result


@app.post("/api/v1/cross-validations", tags=["validation"])
def cross_validate(request: CrossValidationRequest) -> dict:
    try:
        return service.cross_validate(**request.model_dump())
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"交叉验证失败: {exc}") from exc


@app.post("/api/v1/analysis-cases/{case_id}/cross-validate", tags=["validation"])
def cross_validate_case(case_id: str, request: CaseCrossValidationRequest) -> dict:
    try:
        return service.cross_validate_case(case_id=case_id, **request.model_dump())
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"案例交叉验证失败: {exc}") from exc


@app.get("/api/v1/knowledge/search", tags=["knowledge"])
def search_knowledge(q: Annotated[str, Query(min_length=1, max_length=200)], limit: Annotated[int, Query(ge=1, le=200)] = 50) -> dict:
    return repository.search(q, limit)


@app.post("/api/v1/knowledge/import-legacy", tags=["knowledge"])
def import_legacy(request: LegacyImportRequest = Body(default_factory=LegacyImportRequest)) -> dict:
    try:
        return service.import_legacy(**request.model_dump())
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"旧项目导入失败: {exc}") from exc


@app.patch("/api/v1/events/{event_id}/context", tags=["knowledge"])
def update_event_context(event_id: str, request: EventContextUpdateRequest) -> dict:
    try:
        return repository.save_event_context_override(event_id, **request.model_dump())
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/statistics/overview", tags=["statistics"])
def statistics_overview(
    date_from: Annotated[date | None, Query()] = None,
    date_to: Annotated[date | None, Query()] = None,
) -> dict:
    if date_from and date_to and date_from > date_to:
        raise HTTPException(status_code=400, detail="date_from 不能晚于 date_to")
    return repository.statistics(
        date_from=date_from.isoformat() if date_from else None,
        date_to=date_to.isoformat() if date_to else None,
    )


@app.post("/api/v1/generated-reports", tags=["generated-reports"])
def generate_report(request: GeneratedReportRequest) -> dict:
    try:
        if request.date_from and request.date_to and request.date_from > request.date_to:
            raise ValueError("date_from 不能晚于 date_to")
        return service.generate_report(**request.model_dump(mode="json"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"统计报告生成失败: {exc}") from exc


@app.get("/api/v1/generated-reports", tags=["generated-reports"])
def list_generated_reports(limit: Annotated[int, Query(ge=1, le=500)] = 100) -> list[dict]:
    return repository.list_generated_reports(limit)


@app.get("/api/v1/generated-reports/{report_id}/download", tags=["generated-reports"])
def download_generated_report(report_id: str) -> FileResponse:
    record = repository.get_generated_report(report_id)
    if not record:
        raise HTTPException(status_code=404, detail="生成报告不存在")
    path = Path(record["file_path"])
    if not path.is_file() or settings.generated_report_dir.resolve() not in path.resolve().parents:
        raise HTTPException(status_code=404, detail="生成报告文件不存在")
    return FileResponse(path, media_type="text/markdown; charset=utf-8", filename=f"{report_id}.md")


def run() -> None:
    uvicorn.run("ai_signal_hub.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    run()
