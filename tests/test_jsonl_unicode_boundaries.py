from __future__ import annotations

import json

from ai_signal_hub.legacy import _read_strings_jsonl


def test_jsonl_reader_does_not_split_unicode_line_separators(tmp_path) -> None:
    path = tmp_path / "strings.jsonl"
    values = [{"value": "line separator"}, {"value": "nextline"}]
    path.write_text("".join(json.dumps(item, ensure_ascii=False) + "\n" for item in values),
                    encoding="utf-8")
    assert _read_strings_jsonl(path) == values
