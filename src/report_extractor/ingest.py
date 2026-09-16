from __future__ import annotations

import csv
from pathlib import Path

from .utils import normalize_space, normalize_url, stable_id, utc_now, virus_total_sha256, write_json


FIELD_MAP = {
    "时间": "date_raw",
    "事件": "event_raw",
    "样本": "sample_raw",
    "事件来源": "event_source_raw",
    "样本来源": "sample_source_raw",
}


def collect_csv(csv_path: str | Path) -> dict:
    path = Path(csv_path)
    records: list[dict] = []
    source_index: dict[str, dict] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = set(FIELD_MAP) - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV 缺少字段: {', '.join(sorted(missing))}")
        for row_number, row in enumerate(reader, start=2):
            cleaned = {target: normalize_space(row.get(source)) for source, target in FIELD_MAP.items()}
            if not any(cleaned.values()):
                continue
            sources = []
            for source_kind, raw_key in (("event_report", "event_source_raw"), ("sample_reference", "sample_source_raw")):
                raw = cleaned[raw_key]
                normalized = normalize_url(raw)
                status = "ready" if normalized else ("missing" if not raw else "needs_resolution")
                source = {
                    "source_kind": source_kind,
                    "raw": raw or None,
                    "url": normalized,
                    "status": status,
                    "vt_sha256": virus_total_sha256(normalized),
                }
                sources.append(source)
                if normalized:
                    item = source_index.setdefault(
                        normalized,
                        {
                            "source_id": stable_id("source", normalized),
                            "url": normalized,
                            "kinds": [],
                            "rows": [],
                        },
                    )
                    if source_kind not in item["kinds"]:
                        item["kinds"].append(source_kind)
                    item["rows"].append(row_number)
            records.append(
                {
                    "record_id": stable_id("seed", path.name, row_number),
                    "source_row": row_number,
                    **cleaned,
                    "sources": sources,
                }
            )
    duplicate_urls = [item["url"] for item in source_index.values() if len(set(item["rows"])) > 1]
    return {
        "schema_version": "0.1",
        "generated_at": utc_now(),
        "source_csv": str(path.resolve()),
        "summary": {
            "nonempty_records": len(records),
            "unique_urls": len(source_index),
            "duplicate_urls": len(duplicate_urls),
            "needs_resolution": sum(
                1 for record in records for source in record["sources"] if source["status"] == "needs_resolution"
            ),
        },
        "duplicate_url_values": sorted(duplicate_urls),
        "records": records,
        "sources": sorted(source_index.values(), key=lambda item: item["url"]),
    }


def collect_to_file(csv_path: str | Path, output_path: str | Path) -> dict:
    result = collect_csv(csv_path)
    write_json(output_path, result)
    return result


def group_report_seeds(csv_path: str | Path) -> dict:
    """按事件报告 URL 聚合 CSV 行。

    同一报告出现多次表示多个样本/事件共享该报告，是有效的一对多关系，
    因而这里称为 report_groups，而不将其作为重复错误。
    """
    collected = collect_csv(csv_path)
    groups: dict[str, dict] = {}
    unresolved_rows: list[int] = []
    for record in collected["records"]:
        report_source = next(
            (item for item in record["sources"] if item["source_kind"] == "event_report"),
            None,
        )
        url = report_source.get("url") if report_source else None
        if not url:
            unresolved_rows.append(record["source_row"])
            continue
        group = groups.setdefault(
            url,
            {
                "report_group_id": stable_id("report-group", url),
                "url": url,
                "source_rows": [],
                "event_hints": [],
                "sample_hints": [],
            },
        )
        group["source_rows"].append(record["source_row"])
        event_hint = normalize_space(record.get("event_raw"))
        if event_hint and event_hint not in group["event_hints"]:
            group["event_hints"].append(event_hint)
        sample_source = next(
            (item for item in record["sources"] if item["source_kind"] == "sample_reference"),
            {},
        )
        sample_hint = {
            "source_row": record["source_row"],
            "event_hint": event_hint or None,
            "sample_hint": normalize_space(record.get("sample_raw")) or None,
            "sample_reference_url": sample_source.get("url"),
            "sha256": sample_source.get("vt_sha256"),
        }
        if any(value for key, value in sample_hint.items() if key != "source_row"):
            group["sample_hints"].append(sample_hint)
    report_groups = sorted(groups.values(), key=lambda item: min(item["source_rows"]))
    return {
        "schema_version": "0.2",
        "generated_at": utc_now(),
        "source_csv": collected["source_csv"],
        "summary": {
            "nonempty_records": collected["summary"]["nonempty_records"],
            "report_groups": len(report_groups),
            "multi_row_report_groups": sum(len(item["source_rows"]) > 1 for item in report_groups),
            "unresolved_report_rows": len(unresolved_rows),
        },
        "unresolved_report_rows": unresolved_rows,
        "report_groups": report_groups,
    }


def find_report_seed(grouped: dict, url: str | None) -> dict | None:
    normalized = normalize_url(url)
    if not normalized:
        return None
    for group in grouped.get("report_groups", []):
        if normalize_url(group.get("url")) == normalized:
            return group
    return None


def group_reports_to_file(csv_path: str | Path, output_path: str | Path) -> dict:
    result = group_report_seeds(csv_path)
    write_json(output_path, result)
    return result
