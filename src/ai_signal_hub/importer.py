from __future__ import annotations

import argparse
import json

from .config import settings
from .database import Database
from .legacy import LegacyAdapters
from .repository import Repository
from .services import HubService


def run(include_reports: bool = False) -> dict:
    settings.ensure_directories()
    database = Database(settings.database_path)
    database.initialize()
    service = HubService(settings, Repository(database), LegacyAdapters(settings))
    return service.import_legacy(include_reports=include_reports)


def main() -> None:
    parser = argparse.ArgumentParser(description="幂等导入旧项目的安全结构化结果")
    parser.add_argument("--skip-reports", action="store_false", dest="include_reports", help="跳过旧报告项目 final_v8 的确定性结果")
    parser.set_defaults(include_reports=True)
    args = parser.parse_args()
    print(json.dumps(run(include_reports=args.include_reports), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
