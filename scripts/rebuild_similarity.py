"""Preview and explicitly apply derived similarity results; never analyze payloads.

The SQLite backup is consistent even if the source database uses WAL. Only the
three derived clustering tables are replaced on apply; all original evidence
and case/report records remain untouched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

from ai_signal_hub.config import Settings
from ai_signal_hub.database import Database
from ai_signal_hub.repository import Repository
from ai_signal_hub.similarity import ALGORITHM_VERSION, SampleSimilarityService


PROJECT = Path(__file__).resolve().parents[1]
DERIVED = {"sample_cluster_runs", "sample_clusters", "sample_relations"}


def save(path: Path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")


def readonly(path):
    con = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def fingerprints(path: Path):
    with closing(readonly(path)) as con:
        con.execute("BEGIN")
        tables = [row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        result = {}
        for table in tables:
            escaped = table.replace('"', '""')
            encoded = sorted(json.dumps(dict(row), sort_keys=True, ensure_ascii=False) for row in con.execute(f'SELECT * FROM "{escaped}"'))
            result[table] = {"count": len(encoded), "sha256": hashlib.sha256("\n".join(encoded).encode()).hexdigest()}
        return result


def source_hashes():
    return {name: hashlib.sha256((PROJECT / "src/ai_signal_hub" / name).read_bytes()).hexdigest()
            for name in ("similarity.py", "repository.py", "database.py")}


def backup(source: Path, destination: Path):
    if destination.exists():
        raise ValueError("Backup destination already exists")
    with closing(readonly(source)) as src, closing(sqlite3.connect(destination)) as dst:
        src.backup(dst)


def protected(values):
    return {name: data for name, data in values.items() if name not in DERIVED}


def preview(source: Path, output: Path):
    if output.exists():
        raise ValueError("Preview batch exists; choose a new batch, never overwrite evidence")
    output.mkdir(parents=True)
    baseline = output / "knowledge.before.db"
    working = output / "knowledge.preview.db"
    backup(source, baseline)
    backup(baseline, working)
    before = fingerprints(baseline)
    database = Database(working)
    database.initialize()
    repository = Repository(database)
    run = SampleSimilarityService(repository).rebuild()
    after = fingerprints(working)
    if protected(before) != protected(after):
        raise RuntimeError("Preview changed protected records")
    with closing(readonly(baseline)) as con:
        old_relations = {(r["source_sample_id"], r["target_sample_id"]): dict(r) for r in con.execute("SELECT * FROM sample_relations")}
        old_runs = [dict(r) for r in con.execute("SELECT * FROM sample_cluster_runs")]
    with closing(readonly(working)) as con:
        families = {r["sha256"]: r["source_case"] for r in con.execute("SELECT sha256,source_case FROM samples")}
        comparisons = []
        for r in con.execute("SELECT * FROM sample_relations ORDER BY source_sample_id,target_sample_id"):
            old = old_relations.get((r["source_sample_id"], r["target_sample_id"]), {})
            detail = json.loads(r["details_json"])
            comparisons.append({"left_sha256": r["source_sample_id"], "right_sha256": r["target_sample_id"],
                "left_family": families[r["source_sample_id"]], "right_family": families[r["target_sample_id"]],
                "old": {key: old.get(key) for key in ("overall_similarity", "toolchain_similarity", "prompt_similarity", "code_style_similarity", "same_cluster")},
                "new": {"overall_similarity": r["overall_similarity"] if detail["comparable_weight"] else None,
                    **{key + "_similarity": value["score"] for key, value in detail["groups"].items()},
                    "same_cluster": bool(r["same_cluster"]), "comparison": detail}})
    save(output / "comparisons.json", comparisons)
    fruit = next((sha for sha, family in families.items() if str(family).upper() == "FRUITSHELL"), None)
    manifest = {"source": str(source), "code_sha256": source_hashes(), "before": before, "after": after,
                "old_runs": old_runs, "new_run": run, "protected_records_unchanged": True,
                "pair_count": len(comparisons),
                "positive_pairs": sum((r["new"]["overall_similarity"] or 0) > 1e-6 for r in comparisons),
                "not_comparable_pairs": sum(r["new"]["overall_similarity"] is None for r in comparisons),
                "fruitshell": repository.sample_associations(fruit) if fruit else None}
    save(output / "manifest.json", manifest)
    print(json.dumps({"mode": "preview", "batch": str(output), "sample_count": run["sample_count"],
        "cluster_count": run["cluster_count"], "pair_count": len(comparisons),
        "protected_records_unchanged": True}, ensure_ascii=True))


def apply(source: Path, output: Path):
    if (output / "applied.json").exists():
        raise ValueError("Batch already applied")
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    if Path(manifest["source"]).resolve() != source.resolve() or manifest["code_sha256"] != source_hashes():
        raise ValueError("Source or algorithm changed since preview; create a fresh preview")
    if fingerprints(source) != manifest["before"]:
        raise ValueError("Live database changed since preview; create a fresh preview")
    working = output / "knowledge.preview.db"
    if fingerprints(working) != manifest["after"]:
        raise ValueError("Preview database changed")
    preview_repo = Repository(Database(working))
    with closing(readonly(working)) as con:
        clusters, relations = [], []
        for row in con.execute("SELECT * FROM sample_clusters"):
            item = dict(row); item["details"] = json.loads(item.pop("details_json")); clusters.append(item)
        for row in con.execute("SELECT * FROM sample_relations"):
            item = dict(row); item["details"] = json.loads(item.pop("details_json"))
            item["common_features"] = json.loads(item.pop("common_features_json")); relations.append(item)
    database = Database(source)
    database.initialize()
    run = manifest["new_run"]
    applied = Repository(database).replace_sample_similarity(algorithm_version=ALGORITHM_VERSION,
        distance_threshold=run["distance_threshold"], clusters=clusters, relations=relations,
        details=run["details"], expected_samples=preview_repo.all_sample_results())
    after = fingerprints(source)
    unchanged = protected(after) == protected(manifest["before"])
    save(output / "applied.json", {"run": applied, "after": after, "protected_records_unchanged": unchanged,
                                 "backup": str(output / "knowledge.before.db")})
    if not unchanged:
        raise RuntimeError("Protected records changed concurrently; inspect snapshots; no automatic overwrite")
    print(json.dumps({"mode": "applied", "sample_count": applied["sample_count"],
        "cluster_count": applied["cluster_count"], "protected_records_unchanged": True}, ensure_ascii=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["preview", "apply"])
    parser.add_argument("--batch", required=True)
    args = parser.parse_args()
    if args.batch in {"", ".", ".."} or any(c in args.batch for c in '/\\:'):
        raise ValueError("Batch must be one directory name")
    destination = PROJECT / "data/evaluations" / args.batch
    {"preview": preview, "apply": apply}[args.mode](Settings().database_path, destination)
