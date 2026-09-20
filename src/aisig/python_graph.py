from __future__ import annotations

import ast
from collections import defaultdict
from itertools import product
from typing import Any, Hashable, Iterable


AI_SDKS = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "ollama": "Ollama",
    "google": "Google",
}


class PythonStaticGraph:
    """Bounded, scope-aware Python provenance graph.

    The graph never imports or evaluates sample code. Multiple reaching
    definitions are kept as a conservative union; opaque calls stop value
    propagation.
    """

    def __init__(self, text: str, *, max_nodes: int = 50_000):
        self.text = text
        self.tree = ast.parse(text)
        self.nodes = list(ast.walk(self.tree))
        if len(self.nodes) > max_nodes:
            raise ValueError("source_ast_node_limit")
        self.node_by_id = {id(node): node for node in self.nodes}
        self.scope: dict[int, str] = {}
        self.locals: dict[str, set[str]] = defaultdict(set)
        self.functions: dict[tuple[str, str], tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = {}
        self.edges: dict[Hashable, set[Hashable]] = defaultdict(set)
        self.external: set[int] = set()
        self.aliases: dict[str, str] = {}
        self.client_info: dict[Hashable, dict[str, Any]] = {}
        self.model_input_roots: list[tuple[int, int, str]] = []
        self._scopes(self.tree, "<module>")
        self._collect_imports()
        for node in self.nodes:
            self._build(node)
        self._collect_clients()
        self._collect_model_input_roots()

    @staticmethod
    def call_name(call: ast.Call) -> str:
        try:
            return ast.unparse(call.func)
        except (AttributeError, ValueError):
            return ""

    def _scopes(self, node: ast.AST, scope: str) -> None:
        self.scope[id(node)] = scope
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            inner = f"{scope}/{node.name}"
            self.functions[(scope, node.name)] = (inner, node)
            args = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
            self.locals[inner].update(arg.arg for arg in args)
            if node.args.vararg:
                self.locals[inner].add(node.args.vararg.arg)
            if node.args.kwarg:
                self.locals[inner].add(node.args.kwarg.arg)
            for child in ast.iter_child_nodes(node):
                self._scopes(child, inner)
            return
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            self.locals[scope].add(node.id)
        for child in ast.iter_child_nodes(node):
            self._scopes(child, scope)

    def _collect_imports(self) -> None:
        for node in self.nodes:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    self.aliases[alias.asname or root] = root.casefold()
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0].casefold()
                for alias in node.names:
                    self.aliases[alias.asname or alias.name] = root

    def symbol(self, scope: str, name: str) -> tuple[str, str, str]:
        local = scope
        while name not in self.locals[local] and local != "<module>":
            local = local.rsplit("/", 1)[0]
        return ("var", local, name)

    def function(self, call: ast.Call) -> tuple[str, ast.FunctionDef | ast.AsyncFunctionDef] | None:
        if not isinstance(call.func, ast.Name):
            return None
        scope = self.scope[id(call)]
        while True:
            match = self.functions.get((scope, call.func.id))
            if match:
                return match
            if scope == "<module>":
                return None
            scope = scope.rsplit("/", 1)[0]

    def _link(self, left: Hashable, right: ast.AST | Hashable) -> None:
        self.edges[left].add(id(right) if isinstance(right, ast.AST) else right)

    def _build(self, node: ast.AST) -> None:
        scope, key = self.scope[id(node)], id(node)
        if isinstance(node, ast.Name):
            self._link(key, self.symbol(scope, node.id))
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and node.value is not None:
                    self._link(self.symbol(scope, target.id), node.value)
        elif isinstance(node, (ast.For, ast.comprehension)):
            for target in ast.walk(node.target):
                if isinstance(target, ast.Name):
                    self._link(self.symbol(scope, target.id), node.iter)
        elif isinstance(node, ast.Return) and node.value:
            self._link(("return", scope), node.value)
        elif isinstance(node, ast.Dict):
            pairs: list[tuple[str, ast.AST]] = []
            for key_node, value_node in zip(node.keys, node.values, strict=True):
                if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                    lowered = key_node.value.casefold()
                    pairs.append((lowered, value_node))
                    self._link(("dict", key, lowered), value_node)
            keys = {name for name, _ in pairs}
            selected = (
                {"content"} if "content" in keys
                else {"messages"} if "messages" in keys
                else {"prompt", "inputs", "contents", "text"}
            )
            for name, value_node in pairs:
                if name in selected:
                    self._link(key, value_node)
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for child in node.elts:
                self._link(key, child)
        elif isinstance(node, (ast.BinOp, ast.JoinedStr, ast.FormattedValue, ast.IfExp, ast.Subscript)):
            for child in ast.iter_child_nodes(node):
                self._link(key, child)
        elif isinstance(node, ast.Call):
            function = self.function(node)
            if function:
                inner, definition = function
                params = [arg.arg for arg in (*definition.args.posonlyargs, *definition.args.args)]
                for param, argument in zip(params, node.args):
                    self._link(("var", inner, param), argument)
                for keyword in node.keywords:
                    if keyword.arg:
                        self._link(("var", inner, keyword.arg), keyword.value)
                self._link(key, ("return", inner))
            elif (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in {"append", "extend"}
                and isinstance(node.func.value, ast.Name)
            ):
                for argument in node.args:
                    self._link(self.symbol(scope, node.func.value.id), argument)
            elif self.call_name(node).endswith(("b64decode", ".decode", ".format", ".join")):
                if isinstance(node.func, ast.Attribute):
                    self._link(key, node.func.value)
                if not self.call_name(node).endswith(".decode"):
                    for argument in node.args:
                        self._link(key, argument)
                    for keyword in node.keywords:
                        self._link(key, keyword.value)
            else:
                self.external.add(key)

    def _collect_clients(self) -> None:
        for node in self.nodes:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or not isinstance(node.value, ast.Call):
                continue
            constructor = self.call_name(node.value).split(".")[0]
            sdk_name = self.aliases.get(constructor, constructor.casefold())
            if sdk_name not in AI_SDKS:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            keywords = {kw.arg: kw.value for kw in node.value.keywords if kw.arg}
            for target in targets:
                if isinstance(target, ast.Name):
                    self.client_info[self.symbol(self.scope[id(node)], target.id)] = {
                        "sdk_name": sdk_name,
                        "sdk_vendor": AI_SDKS[sdk_name],
                        "base_url_node": keywords.get("base_url") or keywords.get("api_base"),
                    }

    def client_for_call(self, call: ast.Call) -> dict[str, Any] | None:
        name = self.call_name(call)
        root = name.split(".")[0]
        if root in self.aliases and self.aliases[root] in AI_SDKS:
            sdk = self.aliases[root]
            return {"sdk_name": sdk, "sdk_vendor": AI_SDKS[sdk], "base_url_node": None}
        return self.client_info.get(self.symbol(self.scope[id(call)], root))

    def is_known_ai_call(self, call: ast.Call) -> bool:
        name = self.call_name(call)
        return bool(
            self.client_for_call(call)
            and name.endswith((".create", ".generate_content", ".chat", ".generate", ".complete"))
        )

    def _collect_model_input_roots(self) -> None:
        for node in self.nodes:
            if not isinstance(node, ast.Call) or not self.is_known_ai_call(node):
                continue
            name = self.call_name(node)
            for keyword in node.keywords:
                if keyword.arg in {"messages", "prompt", "contents", "input"}:
                    self.model_input_roots.append((id(keyword.value), node.lineno, name))
            if name.endswith((".generate_content", ".complete")) and node.args:
                self.model_input_roots.append((id(node.args[0]), node.lineno, name))

    def reachable(self, roots: Iterable[Hashable]) -> set[Hashable]:
        seen: set[Hashable] = set()
        pending = list(roots)
        while pending:
            key = pending.pop()
            if key in seen:
                continue
            seen.add(key)
            pending.extend(self.edges.get(key, ()))
        return seen

    def static_values(self, node_or_key: ast.AST | Hashable | None, *, max_depth: int = 16) -> set[Any]:
        if node_or_key is None:
            return set()
        key = id(node_or_key) if isinstance(node_or_key, ast.AST) else node_or_key
        return self._values(key, set(), max_depth)

    def _values(self, key: Hashable, seen: set[Hashable], depth: int) -> set[Any]:
        if depth < 0 or key in seen:
            return set()
        seen = {*seen, key}
        node = self.node_by_id.get(key) if isinstance(key, int) else None
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float, bool, type(None))):
            return {node.value}
        if isinstance(node, ast.Name):
            return self._values(self.symbol(self.scope[id(node)], node.id), seen, depth - 1)
        if isinstance(node, ast.FormattedValue):
            return self._values(id(node.value), seen, depth - 1)
        if isinstance(node, ast.IfExp):
            return self._values(id(node.body), seen, depth - 1) | self._values(id(node.orelse), seen, depth - 1)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._values(id(node.left), seen, depth - 1)
            right = self._values(id(node.right), seen, depth - 1)
            return {a + b for a, b in product(left, right) if isinstance(a, str) and isinstance(b, str)}
        if isinstance(node, ast.JoinedStr):
            choices: list[set[str]] = []
            for part in node.values:
                values = self._values(id(part), seen, depth - 1)
                strings = {str(value) for value in values if isinstance(value, (str, int, float, bool))}
                if not strings:
                    return set()
                choices.append(strings)
            return {"".join(parts) for parts in product(*choices)}
        values: set[Any] = set()
        for target in self.edges.get(key, ()):
            values.update(self._values(target, seen, depth - 1))
        return values

    def dict_nodes(self, node: ast.AST | None) -> list[ast.Dict]:
        if node is None:
            return []
        found: list[ast.Dict] = []
        for key in self.reachable([id(node)]):
            candidate = self.node_by_id.get(key) if isinstance(key, int) else None
            if isinstance(candidate, ast.Dict) and candidate not in found:
                found.append(candidate)
        return found

    def dict_items(self, node: ast.AST | None) -> dict[str, list[tuple[Any, ast.AST]]]:
        result: dict[str, list[tuple[Any, ast.AST]]] = defaultdict(list)
        for dictionary in self.dict_nodes(node):
            for key_node, value_node in zip(dictionary.keys, dictionary.values, strict=True):
                keys = self.static_values(key_node)
                if len(keys) != 1:
                    continue
                key = next(iter(keys))
                if not isinstance(key, str):
                    continue
                values = self.static_values(value_node)
                result[key.casefold()].extend((value, value_node) for value in values)
        return dict(result)
