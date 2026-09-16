from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .fetcher import fetch_public_report
from .event_pipeline_v3 import extract_report_events_v3
from .event_compare_v3 import compare_event_to_sample
from .family_batch import run_family_batch
from .ingest import collect_to_file, group_reports_to_file
from .link_compare import link_report_to_sample
from .pipeline import extract_report
from .utils import read_json, stable_id, write_json


PROJECT_ROOT = Path(__file__).resolve().parents[2]
COMPONENT_ROOT = PROJECT_ROOT / "components" / "report_extractor"
DEFAULT_SCHEMA = COMPONENT_ROOT / "schemas" / "report_extraction.schema.json"
DEFAULT_EVENT_SCHEMA = COMPONENT_ROOT / "schemas" / "report_events_v03.schema.json"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reportctl", description="报告信息抽取 P0")
    sub = parser.add_subparsers(dest="command", required=True)

    collect = sub.add_parser("collect", help="清洗 CSV 并生成来源种子")
    collect.add_argument("--csv", required=True)
    collect.add_argument("--output", required=True)

    collect_reports = sub.add_parser("collect-reports", help="按报告 URL 聚合 CSV 行和样本提示")
    collect_reports.add_argument("--csv", required=True)
    collect_reports.add_argument("--output", required=True)

    fetch = sub.add_parser("fetch", help="安全获取一份公开报告")
    fetch.add_argument("--url", required=True)
    fetch.add_argument("--output-dir", required=True)

    extract = sub.add_parser("extract", help="解析并抽取一份本地报告")
    extract.add_argument("--source", required=True)
    extract.add_argument("--url")
    extract.add_argument("--output-dir", required=True)
    extract.add_argument("--llm", action="store_true")
    extract.add_argument("--schema", default=str(DEFAULT_SCHEMA))

    extract_events = sub.add_parser("extract-events", help="按安全事件拆分并输出精简字段")
    extract_events.add_argument("--source", required=True)
    extract_events.add_argument("--url")
    extract_events.add_argument("--output-dir", required=True)
    extract_events.add_argument("--llm", action="store_true", help="使用DeepSeek补充逐事件语义候选；结果强制人工复核")
    extract_events.add_argument("--target-family", help="可选目标家族；仅在报告正文精确出现时补充事件候选")
    extract_events.add_argument("--target-alias", action="append", default=[], help="目标家族别名，可重复指定")
    extract_events.add_argument("--schema", default=str(DEFAULT_EVENT_SCHEMA))

    link = sub.add_parser("link", help="关联报告与样本结果并比较信号")
    link.add_argument("--report-result", required=True)
    link.add_argument("--sample-result", required=True)
    link.add_argument("--sample-family")
    link.add_argument("--output", required=True)

    compare_events = sub.add_parser("compare-events", help="比较v0.3报告事件与样本静态AI信号")
    compare_events.add_argument("--report-events", required=True)
    compare_events.add_argument("--sample-result", required=True)
    compare_events.add_argument("--event-id")
    compare_events.add_argument("--sample-family")
    compare_events.add_argument("--output", required=True)

    batch = sub.add_parser("batch", help="从 CSV 批量获取并抽取报告")
    batch.add_argument("--csv", required=True)
    batch.add_argument("--output-dir", required=True)
    batch.add_argument("--limit", type=int, default=0)
    batch.add_argument("--llm", action="store_true")
    batch.add_argument("--schema", default=str(DEFAULT_SCHEMA))

    family_batch = sub.add_parser("batch-family-reports", help="批量抽取本地家族HTML、选择目标事件并与样本结果对照")
    family_batch.add_argument("--sample-list", required=True, help="已完成静态特征提取样本清单CSV")
    family_batch.add_argument("--reports-root", required=True, help="按家族分目录的本地HTML报告根目录")
    family_batch.add_argument("--output-dir", required=True)
    family_batch.add_argument("--llm", action="store_true", help="仅对每份报告的目标事件启用DeepSeek补充")
    family_batch.add_argument("--event-schema", default=str(DEFAULT_EVENT_SCHEMA))
    family_batch.add_argument("--profile-schema", default=str(COMPONENT_ROOT / "schemas" / "target_event_profile.schema.json"))
    return parser


def _batch(args: argparse.Namespace) -> dict:
    out = Path(args.output_dir)
    seeds_path = out / "seeds.json"
    seeds = collect_to_file(args.csv, seeds_path)
    event_urls = []
    for record in seeds["records"]:
        for source in record["sources"]:
            if source["source_kind"] == "event_report" and source["status"] == "ready" and source["url"] not in event_urls:
                event_urls.append(source["url"])
    if args.limit > 0:
        event_urls = event_urls[: args.limit]
    outcomes = []
    for url in event_urls:
        document_dir = out / stable_id("source", url).replace(":", "_")
        try:
            fetched = fetch_public_report(url, document_dir)
            result = extract_report(
                fetched["source_path"], canonical_url=fetched["canonical_url"], output_dir=document_dir,
                use_llm=args.llm, schema_path=args.schema,
            )
            outcomes.append({"url": url, "status": "ok", "document_id": result["document"]["document_id"], "output_dir": str(document_dir.resolve())})
        except Exception as exc:
            outcomes.append({"url": url, "status": "failed", "error_type": type(exc).__name__, "message": str(exc)})
    summary = {"requested": len(event_urls), "succeeded": sum(item["status"] == "ok" for item in outcomes), "failed": sum(item["status"] == "failed" for item in outcomes), "outcomes": outcomes}
    write_json(out / "batch_summary.json", summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "collect":
            result = collect_to_file(args.csv, args.output)
        elif args.command == "collect-reports":
            result = group_reports_to_file(args.csv, args.output)
        elif args.command == "fetch":
            result = fetch_public_report(args.url, args.output_dir)
        elif args.command == "extract":
            result = extract_report(args.source, canonical_url=args.url, output_dir=args.output_dir, use_llm=args.llm, schema_path=args.schema)
        elif args.command == "extract-events":
            result = extract_report_events_v3(
                args.source, canonical_url=args.url, output_dir=args.output_dir, schema_path=args.schema, use_llm=args.llm,
                target_event={"name": args.target_family, "aliases": args.target_alias} if args.target_family else None,
            )
        elif args.command == "link":
            result = link_report_to_sample(read_json(args.report_result), read_json(args.sample_result), args.sample_family)
            write_json(args.output, result)
        elif args.command == "compare-events":
            result = compare_event_to_sample(
                read_json(args.report_events), read_json(args.sample_result),
                event_id=args.event_id, sample_family=args.sample_family,
            )
            write_json(args.output, result)
        elif args.command == "batch":
            result = _batch(args)
        elif args.command == "batch-family-reports":
            result = run_family_batch(
                args.sample_list,
                args.reports_root,
                args.output_dir,
                use_llm=args.llm,
                event_schema_path=args.event_schema,
                profile_schema_path=args.profile_schema,
            )
        else:
            raise AssertionError(args.command)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"error": type(exc).__name__, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
