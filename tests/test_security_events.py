from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai_signal_hub.database import Database
from ai_signal_hub.security_events import SecurityEventLibrary, parse_sample_text

XLSX = Path(__file__).resolve().parents[1] / "AI安全事件库.xlsx"


@pytest.fixture
def library(tmp_path):
    database = Database(tmp_path / "test.db")
    database.initialize()
    return SecurityEventLibrary(database)


def test_parse_sample_text():
    assert parse_sample_text("无")["has_samples"] is False
    assert parse_sample_text(None)["has_samples"] is False
    one = parse_sample_text("SHA256: " + "a" * 64 + "（原表注释）")
    assert one["has_samples"] and one["sample_count"] == 1
    assert one["hashes"] == ["a" * 64]
    two = parse_sample_text("SHA256: " + "a" * 64 + "\nSHA256: " + "b" * 64)
    assert two["sample_count"] == 2 and len(two["entries"]) == 2


@pytest.mark.skipif(not XLSX.is_file(), reason="事件库 xlsx 不在仓库检出中")
def test_import_xlsx_idempotent_and_filters(library):
    result = library.import_xlsx(XLSX)
    assert result["imported"] == 60
    assert library.import_xlsx(XLSX)["imported"] == 60
    listing = library.list(limit=500)
    assert listing["total"] == 60
    assert all(item["sample_count"] >= 0 for item in listing["items"])
    typed = library.list(event_type="恶意行为调用AI", limit=500)
    assert 0 < typed["total"] < 60
    assert all("恶意行为调用AI" in item["event_types"] for item in typed["items"])
    with_samples = library.list(has_samples=True, limit=500)
    assert with_samples["total"] > 0
    assert all(item["has_samples"] for item in with_samples["items"])
    none = library.list(has_samples=False, limit=500)
    assert with_samples["total"] + none["total"] == 60
    ranged = library.list(report_date_from="2025-07-01", report_date_to="2025-07-31", limit=500)
    assert ranged["total"] > 0
    assert all(item["event_date"].startswith("2025-07") for item in ranged["items"])
    seen = library.list(first_seen_from="2026-10-12", first_seen_to="2026-10-12", limit=500)
    assert seen["total"] > 0
    found = library.list(q="LAMEHUG", limit=500)
    assert found["total"] >= 1
    detail = library.get("AISEC-20250717-APT28-LAMEHUG")
    assert detail["summary"] and detail["sources"]
    assert detail["samples"]["has_samples"] is True
    assert detail["samples"]["sample_count"] == 1


def test_crud_cycle_and_validation(library):
    created = library.create({
        "name": "测试事件", "event_date": "2026-01-02",
        "event_types": ["AI辅助恶意样本开发"], "summary": "概要",
        "sample_text": "SHA256: " + "c" * 64, "source": "https://example.com/a ; https://example.com/b",
    })
    event_id = created["event_id"]
    assert event_id.startswith("AISEC-20260102-CUSTOM-")
    assert created["has_samples"] and created["sample_count"] == 1
    with pytest.raises(ValueError, match="已存在"):
        library.create({"event_id": event_id, "name": "重复"})
    with pytest.raises(ValueError, match="事件类型"):
        library.create({"name": "非法类型", "event_types": ["其他"]})
    with pytest.raises(ValueError, match="名称"):
        library.create({"name": " "})
    updated = library.update(event_id, {"name": "测试事件v2", "event_types": ["Agent编排攻击行动"],
                                        "sample_text": "无", "summary": "更新概要"})
    assert updated["name"] == "测试事件v2" and updated["has_samples"] is False
    assert updated["first_seen_at"] == created["first_seen_at"]
    library.delete(event_id)
    assert library.get(event_id) is None
    with pytest.raises(KeyError):
        library.delete(event_id)
    with pytest.raises(KeyError):
        library.update(event_id, {"name": "不存在"})


def test_api_read_and_not_found():
    from ai_signal_hub import main
    main.database.initialize()  # idempotent schema migration, no data writes
    client = TestClient(main.app)
    response = client.get("/api/v1/security-events/nonexistent-event")
    assert response.status_code == 404
    listing = client.get("/api/v1/security-events", params={"limit": 5})
    assert listing.status_code == 200
    assert "items" in listing.json() and "total" in listing.json()
