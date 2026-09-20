from __future__ import annotations

import re
from typing import Any

from .materials import MaterialIndex


class StaticQueryService:
    """Read-only, bounded queries over the in-memory material index."""

    ALLOWED = {"get_unit", "get_callers", "get_callees", "get_definitions", "get_references", "get_resource", "search_units"}

    def __init__(self, index: MaterialIndex, *, max_chars: int = 12000, max_results: int = 8):
        self.index = index
        self.max_chars = max_chars
        self.max_results = max_results
        self.units = {unit.unit_id: unit for unit in index.units}

    def execute(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name not in self.ALLOWED:
            return {"status": "rejected", "reason": "query_not_allowed"}
        if name == "search_units":
            query = str(arguments.get("query") or "")
            if not query or len(query) > 256:
                return {"status": "rejected", "reason": "invalid_query"}
            pattern = re.compile(re.escape(query), re.IGNORECASE)
            found = [unit for unit in self.index.units if pattern.search(unit.content)][:self.max_results]
            return {"status": "ok", "units": [self._bounded(unit) for unit in found]}
        unit_id = str(arguments.get("unit_id") or "")
        unit = self.units.get(unit_id)
        if unit is None:
            return {"status": "rejected", "reason": "unknown_unit_id"}
        if name in {"get_unit", "get_resource"}:
            if name == "get_resource" and unit.kind != "resource":
                return {"status": "rejected", "reason": "unit_is_not_resource"}
            return {"status": "ok", "units": [self._bounded(unit)]}
        key = {"get_callers": "callers", "get_callees": "calls", "get_definitions": "definitions"}.get(name)
        ids = (unit.references.get(key, []) if key else
               sum((values for ref_key, values in unit.references.items()
                    if not ref_key.startswith("unresolved")), []))
        found = [self.units[item] for item in ids if item in self.units][:self.max_results]
        return {"status": "ok", "units": [self._bounded(item) for item in found],
                "unresolved": [item for item in ids if item not in self.units][:self.max_results]}

    def _bounded(self, unit) -> dict[str, Any]:
        value = unit.as_dict(include_content=True)
        if len(value["content"]) > self.max_chars:
            value["content"] = value["content"][:self.max_chars]
            value["content_truncated"] = True
        return value
