"""Bounded prompt evidence recovery. Payloads are data, never imported/executed.

Python uses a conservative, scope-aware dependency graph (not runtime dataflow).
Binary candidates retain container offsets and explicit boundary confidence.
"""
from __future__ import annotations

import ast
import base64
import binascii
import copy
import hashlib
import io
import re
import struct
import zipfile
import zlib
from collections import defaultdict

from .sample_rules import _simhash


VERSION = 'prompt-context-recovery-v1'
MAX_FILE = 100 * 1024 * 1024
MAX_SOURCE = 2 * 1024 * 1024
MAX_TEXT = 32768
MAX_CANDIDATES = 100
MAX_NODES = 50000
MAX_MEMBER = 32 * 1024 * 1024
MAX_EXPANDED = 120 * 1024 * 1024
SECRET = re.compile(r'\b(?:sk-[A-Za-z0-9_-]{12,}|hf_[A-Za-z0-9]{12,})\b')
PATTERNS = {
    'role_definition': r'\byou are (?:(?:an?|the)\b|going to act as\b)|\bact as\b',
    'output_only': r'\b(?:return|output|respond with)\s+(?:only|just)\b',
    'code_only': r'\b(?:only|just)\s+(?:the )?(?:code|command|script)\b',
    'single_line_command': r'\b(?:one[- ]line|single[- ]line)\s+(?:windows )?(?:command|script)\b',
    'self_modification': r'\b(?:rewrite|modify|obfuscat\w*|transform)\s+(?:itself|this (?:script|code)|the (?:script|code))\b',
    'evasion': r'\b(?:evade|bypass|avoid)\b.{0,100}\b(?:detect|antivirus|security|analysis)\b',
    'jailbreak': r'\b(?:ignore (?:all )?(?:previous|prior) instructions|jailbreak|EvilBOT)\b',
    'safety_framing': r'\b(?:authorized|penetration testing|research purpose|educational purpose|CTF)\b',
}
# Unbound binary text requires an instruction AND a task/output cue. Neither
# a model name nor the bare word "prompt" is sufficient.
INSTRUCTION = re.compile(r'(?is)(?:^\s*["\']?(?:you are (?:an? |the |going to act as)|(?:generate|create|write|make) (?:a |an |the )|return only|output only|given a |请|你是)|\b(?:your task is|you need to|please (?:determine|respond|provide))\b)')
TASK = re.compile(r'(?is)(?:\b(?:code|scripts?|commands?|json|response|analysis|instructions|files|screen|click|task|summary|summarize|assistant|validator)\b|代码|脚本|回答|输出|分析)')
ENDPOINT = re.compile(r'(?i)(?:openai\.com|huggingface\.co|generativelanguage\.googleapis\.com|:11434/(?:api|v1)/)')


def _digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def _natural(text, bound=False):
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT or SECRET.search(text):
        return False
    if sum(c.isprintable() or c in '\r\n\t' for c in text) / len(text) < .98:
        return False
    if bound:
        return bool(re.search(r'[A-Za-z\u4e00-\u9fff]', text))
    return len(text) >= 32 and bool(INSTRUCTION.search(text) and TASK.search(text))


def _candidate(text, origin, *, method, boundary='exact_literal', bound=False, completeness='static_component'):
    return {'source': method, 'text': text, 'text_preview': ' '.join(text.split())[:240],
            'text_hash': _digest(text.encode('utf-8')),
            'fuzzy_hash': {'algorithm': 'simhash64_normalized_tokens_v1', 'value': _simhash(text),
                           'normalization': 'unicode_nfkc_lowercase_whitespace_collapse'},
            'features': {k: True for k, p in PATTERNS.items() if re.search(p, text, re.I | re.S)},
            'evidence_level': 'static_candidate', 'target': 'llm_input',
            'boundary': boundary, 'completeness': completeness,
            'call_binding': 'static_dependency_candidate' if bound else 'not_verified',
            'comparison_eligible': boundary != 'uncertain_window',
            'recovery_origin': origin, 'extraction_version': VERSION,
            'interpretation': '静态输入文本/组成部分候选；不证明实际调用、恶意用途或完整运行时输入。'}


def _b64(value):
    if isinstance(value, bytes):
        try:
            value = value.decode('ascii')
        except UnicodeDecodeError:
            return None
    if not isinstance(value, str) or not 44 <= len(value) <= MAX_TEXT * 2:
        return None
    compact = re.sub(r'\s+', '', value)
    if not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', compact) or len(compact) % 4:
        return None
    try:
        raw = base64.b64decode(compact, validate=True)
        return raw.decode('utf-8') if len(raw) <= MAX_TEXT else None
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None


class PythonInputs:
    """Conservative static provenance graph; never evaluates Python calls.

    Loops/branches are unions of possible origins. Runtime input and opaque
    calls are stopping points, so menu prompts and file paths aren't model input.
    """
    def __init__(self, text):
        self.text = text
        self.tree = ast.parse(text)
        self.nodes = list(ast.walk(self.tree))
        if len(self.nodes) > MAX_NODES:
            raise ValueError('source_ast_node_limit')
        self.scope = {}
        self.locals = defaultdict(set)
        self.functions = {}
        self.edges = defaultdict(set)
        self.roots = []
        self.external = set()
        self.aliases = set()
        self.clients = set()
        self._scopes(self.tree, '<module>')
        for n in self.nodes:
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.name.split('.')[0] in {'openai', 'anthropic', 'ollama', 'google'}:
                        self.aliases.add(a.asname or a.name.split('.')[0])
            elif isinstance(n, ast.ImportFrom) and (n.module or '').split('.')[0] in {'openai', 'anthropic', 'ollama', 'google'}:
                self.aliases.update(a.asname or a.name for a in n.names)
        for n in self.nodes:
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call):
                name = ast.unparse(n.value.func)
                if name.split('.')[0] in self.aliases:
                    self.clients.update(t.id for t in n.targets if isinstance(t, ast.Name))
        for n in self.nodes:
            self._build(n)

    def _scopes(self, n, scope):
        self.scope[id(n)] = scope
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            inner = scope + '/' + n.name
            self.functions[(scope, n.name)] = (inner, n)
            for arg in (*n.args.posonlyargs, *n.args.args, *n.args.kwonlyargs):
                self.locals[inner].add(arg.arg)
            for child in ast.iter_child_nodes(n):
                self._scopes(child, inner)
            return
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            self.locals[scope].add(n.id)
        for child in ast.iter_child_nodes(n):
            self._scopes(child, scope)

    def symbol(self, scope, name):
        local = scope
        while name not in self.locals[local] and local != '<module>':
            local = local.rsplit('/', 1)[0]
        return ('var', local, name)

    def function(self, n):
        if not isinstance(n.func, ast.Name):
            return None
        scope = self.scope[id(n)]
        while True:
            match = self.functions.get((scope, n.func.id))
            if match:
                return match
            if scope == '<module>':
                return None
            scope = scope.rsplit('/', 1)[0]

    def _link(self, left, right):
        self.edges[left].add(id(right) if isinstance(right, ast.AST) else right)

    def _build(self, n):
        scope, key = self.scope[id(n)], id(n)
        if isinstance(n, ast.Name):
            self._link(key, self.symbol(scope, n.id))
        elif isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            for t in targets:
                if isinstance(t, ast.Name) and n.value is not None:
                    self._link(self.symbol(scope, t.id), n.value)
        elif isinstance(n, (ast.For, ast.comprehension)):
            for t in ast.walk(n.target):
                if isinstance(t, ast.Name):
                    self._link(self.symbol(scope, t.id), n.iter)
        elif isinstance(n, ast.Return) and n.value:
            self._link(('return', scope), n.value)
        elif isinstance(n, ast.Dict):
            pairs = [(k.value, v) for k, v in zip(n.keys, n.values) if isinstance(k, ast.Constant)]
            keys = {k for k, _ in pairs}
            chosen = {'content'} if 'role' in keys and 'content' in keys else ({'messages'} if 'messages' in keys else {'prompt', 'inputs', 'contents', 'text'})
            for k, v in pairs:
                if k in chosen:
                    self._link(key, v)
        elif isinstance(n, (ast.List, ast.Tuple, ast.Set)):
            for child in n.elts:
                self._link(key, child)
        elif isinstance(n, (ast.BinOp, ast.JoinedStr, ast.FormattedValue, ast.IfExp)):
            for child in ast.iter_child_nodes(n):
                self._link(key, child)
        elif isinstance(n, ast.Subscript):
            self._link(key, n.value)
        elif isinstance(n, ast.Call):
            name = ast.unparse(n.func)
            fn = self.function(n)
            if fn:
                inner, definition = fn
                params = [a.arg for a in (*definition.args.posonlyargs, *definition.args.args)]
                for param, arg in zip(params, n.args):
                    self._link(('var', inner, param), arg)
                for kw in n.keywords:
                    if kw.arg:
                        self._link(('var', inner, kw.arg), kw.value)
                self._link(key, ('return', inner))
            elif isinstance(n.func, ast.Attribute) and n.func.attr in {'append', 'extend'} and isinstance(n.func.value, ast.Name):
                for arg in n.args:
                    self._link(self.symbol(scope, n.func.value.id), arg)
            elif name.endswith(('b64decode', '.decode', '.format', '.join')):
                if isinstance(n.func, ast.Attribute):
                    self._link(key, n.func.value)
                if not name.endswith('.decode'):
                    for arg in n.args:
                        self._link(key, arg)
                    for kw in n.keywords:
                        self._link(key, kw.value)
            else:
                self.external.add(key)
            trusted = name.split('.')[0] in self.aliases | self.clients
            if trusted and name.endswith(('.create', '.generate_content', '.chat', '.generate', '.complete')):
                for kw in n.keywords:
                    if kw.arg in {'messages', 'prompt', 'contents', 'input'}:
                        self.roots.append((id(kw.value), n.lineno, name))
                if name.endswith(('.generate_content', '.complete')) and n.args:
                    self.roots.append((id(n.args[0]), n.lineno, name))
            elif name.endswith('.post'):
                # Deferred until the graph is complete: only a known model URL
                # qualifies a generic HTTP JSON body as a model request.
                pass

    def reachable(self, roots):
        seen, todo = set(), list(roots)
        while todo:
            key = todo.pop()
            if key in seen:
                continue
            seen.add(key)
            todo.extend(self.edges.get(key, ()))
        return seen

    def candidates(self, raw, codec='utf-8', bom=0):
        for n in self.nodes:
            if isinstance(n, ast.Call) and ast.unparse(n.func).endswith('.post'):
                url = n.args[0] if n.args else next((kw.value for kw in n.keywords if kw.arg == 'url'), None)
                reach = self.reachable([id(url)]) if url else set()
                if any(id(c) in reach and isinstance(c, ast.Constant) and isinstance(c.value, str) and ENDPOINT.search(c.value) for c in self.nodes):
                    for kw in n.keywords:
                        if kw.arg == 'json':
                            self.roots.append((id(kw.value), n.lineno, ast.unparse(n.func)))
        reached = self.reachable(r[0] for r in self.roots)
        decode_sources = set()
        for call in self.nodes:
            if isinstance(call, ast.Call) and ast.unparse(call.func) == 'base64.b64decode' and call.args and id(call) in reached:
                decode_sources.update(self.reachable([id(call.args[0])]))
        lines = self.text.splitlines(keepends=True)
        offsets, pos = [], bom
        for line in lines:
            offsets.append(pos)
            pos += len(line.encode(codec))
        result = []
        # Constants in f-strings inherit the entire JoinedStr source location:
        # these are labeled components, not falsely presented as exact byte slices.
        for n in self.nodes:
            if id(n) not in reached or not isinstance(n, ast.Constant) or not isinstance(n.value, (str, bytes)):
                continue
            text, transform = n.value, 'python_literal'
            decoded = _b64(text)
            if decoded and id(n) in decode_sources and _natural(decoded, bound=True):
                text, transform = decoded, 'base64_utf8'
            if not _natural(text, bound=True) or (transform == 'python_literal' and len(text.split()) < 2 and len(text) > 80):
                continue
            start = offsets[n.lineno - 1] + len(lines[n.lineno - 1].encode('utf-8')[:n.col_offset].decode('utf-8').encode(codec))
            end = offsets[n.end_lineno - 1] + len(lines[n.end_lineno - 1].encode('utf-8')[:n.end_col_offset].decode('utf-8').encode(codec))
            origin = {'layer': 'python_source', 'offset': start, 'byte_length': end-start,
                      'line': n.lineno, 'end_line': n.end_lineno, 'transform': transform,
                      'source_span_hash': _digest(raw[start:end]), 'encoding': codec}
            item = _candidate(text, origin, method='python_static_input', bound=True)
            if transform == 'base64_utf8':
                item['completeness'] = 'decoded_static_component'
            item['call_sites'] = [{'line': line, 'callee': name} for root, line, name in self.roots if id(n) in self.reachable([root])]
            result.append(item)
        return result, {'status': 'scanned', 'method': 'scope_aware_dependency_union', 'call_count': len(self.roots),
                        'runtime_values': 'not_evaluated', 'completeness': 'static_components_only',
                        'opaque_calls_reached': len(reached & self.external)}


def _bounded_inflate(data, expected):
    if not 0 <= expected <= MAX_MEMBER:
        raise ValueError('member_size_limit')
    decoder = zlib.decompressobj()
    value = decoder.decompress(data, expected + 1)
    if len(value) != expected or not decoder.eof or decoder.unconsumed_tail:
        raise ValueError('invalid_or_oversize_compressed_member')
    return value


def _pyinstaller_members(data):
    magic = b'MEI\x0c\x0b\x0a\x0b\x0e'
    cookie = data.rfind(magic)
    if cookie < 0:
        return
    if cookie + 88 > len(data):
        raise ValueError('invalid_carchive_cookie')
    _, total, toc_offset, toc_size, _, _ = struct.unpack_from('!8sIIII64s', data, cookie)
    start = cookie + 88 - total
    if start < 0 or toc_size > MAX_MEMBER or not 0 <= toc_offset <= cookie-start-toc_size:
        raise ValueError('invalid_carchive_bounds')
    cursor, end, expanded, count = start+toc_offset, start+toc_offset+toc_size, 0, 0
    while cursor < end:
        if cursor+18 > end or count >= 5000:
            raise ValueError('invalid_carchive_table')
        size, offset, packed, unpacked, flag, kind = struct.unpack_from('!IIIIBc', data, cursor)
        if size < 18 or cursor+size > end or offset+packed > toc_offset:
            raise ValueError('invalid_carchive_entry')
        name = data[cursor+18:cursor+size].rstrip(b'\0').decode('utf-8', 'replace')
        cursor += size
        count += 1
        if kind != b's' or name.startswith(('pyi_', 'pyiboot')):
            continue
        expanded += unpacked
        if unpacked > MAX_MEMBER or expanded > MAX_EXPANDED or flag not in (0, 1):
            raise ValueError('carchive_expansion_limit')
        value = data[start+offset:start+offset+packed]
        value = _bounded_inflate(value, unpacked) if flag else value
        if len(value) != unpacked:
            raise ValueError('invalid_carchive_length')
        yield name, start+offset, value


def _dex_strings(data):
    if len(data) < 112 or not re.match(rb'dex\n0(?:35|37|38|39|40)\x00', data):
        raise ValueError('unsupported_dex_header')
    if struct.unpack_from('<I', data, 40)[0] != 0x12345678:
        raise ValueError('unsupported_dex_endian')
    if struct.unpack_from('<II', data, 32) != (len(data), 112):
        raise ValueError('invalid_dex_file_size')
    size, offset = struct.unpack_from('<II', data, 56)
    if size > 500000 or offset < 112 or offset+4*size > len(data):
        raise ValueError('invalid_dex_string_table')
    for index in range(size):
        pos = struct.unpack_from('<I', data, offset+index*4)[0]
        if pos < 112:
            raise ValueError('invalid_dex_string_offset')
        utf16_size, shift = 0, 0
        for _ in range(5):
            if pos >= len(data):
                raise ValueError('invalid_dex_uleb')
            byte = data[pos]
            pos += 1
            utf16_size |= (byte & 127) << shift
            shift += 7
            if byte < 128:
                break
        else:
            raise ValueError('invalid_dex_uleb')
        end = data.find(b'\0', pos, min(len(data), pos+MAX_TEXT*3+1))
        if end < 0 or utf16_size > MAX_TEXT:
            continue
        try:
            text = data[pos:end].replace(b'\xc0\x80', b'\0').decode('utf-8', 'surrogatepass')
            text = text.encode('utf-16', 'surrogatepass').decode('utf-16')
        except UnicodeError:
            continue
        if len(text.encode('utf-16-le')) // 2 == utf16_size:
            yield index, pos, end-pos, text


def _encoded_candidates(data, layer, origin_extra=None):
    for match in re.finditer(rb'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{44,65536}={0,2}(?![A-Za-z0-9+/=])', data):
        raw = match.group()
        boundary = 'encoded_span'
        # A PYC/serialized script's following type tag can itself be a Base64
        # character. Honor a recognized preceding string length instead of
        # accidentally decoding the next object's tag as prompt content.
        pos = match.start()
        if pos >= 5 and (data[pos-5] & 0x7f) in b'aAust':
            size = struct.unpack_from('<I', data, pos-4)[0]
            if 44 <= size <= len(raw):
                raw = raw[:size]
                boundary = 'length_prefixed_constant'
        elif pos >= 2 and (data[pos-2] & 0x7f) in b'zZ' and 44 <= data[pos-1] <= len(raw):
            raw = raw[:data[pos-1]]
            boundary = 'length_prefixed_constant'
        text = _b64(raw)
        if text and _natural(text):
            origin = {'layer': layer, 'offset': pos, 'byte_length': len(raw),
                      'transform': 'base64_utf8', 'source_span_hash': _digest(raw), **(origin_extra or {})}
            yield _candidate(text, origin, method='encoded_static_input', boundary=boundary, completeness='decoded_constant')


def _binary_windows(data):
    # Go pools have no terminator between literals. Keep only a bounded excerpt
    # here; no exact/fuzzy prompt matching may treat this window as a full literal.
    pattern = rb'(?i)(?:You are (?:an? |the )[^\x00-\x1f]{1,80}(?:generator|validator|expert)|Generate a (?:Lua |Python |PowerShell )?(?:script|code))'
    for match in re.finditer(pattern, data):
        start = match.start()
        from .binary_layout import go_literal_lengths
        try:
            lengths = go_literal_lengths(data, start, MAX_TEXT)
        except (ValueError, struct.error, IndexError):
            lengths = []
        accepted = False
        for length, descriptor in lengths:
            raw = data[start:start+length]
            try:
                text = raw.decode('utf-8')
            except UnicodeDecodeError:
                continue
            if _natural(text):
                accepted = True
                yield _candidate(text, {'layer': 'go_string', 'offset': start, 'byte_length': length,
                    'descriptor_offset': descriptor, 'source_span_hash': _digest(raw), 'transform': 'utf8'},
                    method='go_string_input', boundary='pointer_length_descriptor', completeness='string_constant')
        if accepted:
            continue
        stop = min(len(data), start+2048)
        cut = re.search(rb'[\x00-\x08\x0b\x0c\x0e-\x1f]|[0-9a-fA-F]{40,}', data[start:stop])
        if cut:
            stop = start+cut.start()
        raw = data[start:stop]
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError:
            text = raw.decode('utf-8', 'ignore')
        if _natural(text):
            item = _candidate(text, {'layer': 'binary', 'offset': start, 'byte_length': len(raw),
                                    'source_span_hash': _digest(raw), 'transform': 'utf8_window'},
                             method='binary_instruction_window', boundary='uncertain_window', completeness='excerpt_only')
            # A window hash is a valid evidence hash, not a complete prompt hash.
            item['evidence_text_hash'] = item.pop('text_hash')
            item.pop('fuzzy_hash')
            yield item


def recover_prompt_features(result, data):
    if hashlib.sha256(data).hexdigest() != result.get('sample', {}).get('sha256'):
        raise ValueError('Prompt recovery SHA-256 mismatch')
    output = copy.deepcopy(result)
    if output.get('errors'):
        return output
    prompt = output['features']['prompt']
    diagnostic = {'version': VERSION, 'stages': [], 'candidate_limit': MAX_CANDIDATES,
                  'max_file_bytes': MAX_FILE, 'max_text_chars': MAX_TEXT, 'truncated': False}
    candidates = []

    def add(items):
        for item in items:
            if len(candidates) >= MAX_CANDIDATES:
                diagnostic['truncated'] = True
                break
            candidates.append(item)

    if len(data) > MAX_FILE:
        diagnostic['stages'].append({'stage': 'input', 'status': 'size_limit'})
    elif output['sample'].get('language') == 'python' and not data.startswith((b'MZ', b'\x7fELF')):
        if len(data) > MAX_SOURCE:
            diagnostic['stages'].append({'stage': 'python', 'status': 'source_size_limit'})
        else:
            try:
                bom = 3 if data.startswith(b'\xef\xbb\xbf') else 0
                analyzer = PythonInputs(data[bom:].decode('utf-8'))
                items, detail = analyzer.candidates(data, bom=bom)
                add(items)
                diagnostic['stages'].append({'stage': 'python', **detail})
            except (SyntaxError, UnicodeError, ValueError, RecursionError) as exc:
                diagnostic['stages'].append({'stage': 'python', 'status': 'parse_unavailable', 'error_type': type(exc).__name__})
    elif (output['features'].get('toolchain', {}).get('evidence') or data.startswith(b'PK')
          or b'MEI\x0c\x0b\x0a\x0b\x0e' in data or b'Go build' in data):
        if output['features'].get('toolchain', {}).get('evidence'):
            add(_encoded_candidates(data, 'binary'))
            diagnostic['stages'].append({'stage': 'encoded_constants', 'status': 'scanned', 'candidates': len(candidates)})
        if b'Go build' in data and not data.startswith(b'PK'):
            add(_binary_windows(data))
            diagnostic['stages'].append({'stage': 'go_strings', 'status': 'scanned',
                 'exact_boundaries': sum(p['boundary'] == 'pointer_length_descriptor' for p in candidates),
                 'uncertain_windows': sum(p['boundary'] == 'uncertain_window' for p in candidates)})
        try:
            count = 0
            for name, offset, member in _pyinstaller_members(data):
                count += 1
                add(_encoded_candidates(member, 'pyinstaller_script', {'member': name, 'member_sha256': _digest(member), 'container_offset': offset}))
            diagnostic['stages'].append({'stage': 'carchive', 'status': 'scanned' if count else 'not_detected', 'script_members': count})
        except (ValueError, struct.error, zlib.error) as exc:
            diagnostic['stages'].append({'stage': 'carchive', 'status': 'limited', 'reason': str(exc)[:120]})
        if data.startswith(b'PK'):
            try:
                expanded, members, strings = 0, 0, 0
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    infos = archive.infolist()
                    if len(infos) > 5000:
                        raise ValueError('archive_member_limit')
                    for info in infos:
                        if not re.fullmatch(r'classes\d*\.dex', info.filename):
                            continue
                        expanded += info.file_size
                        if info.file_size > MAX_MEMBER or expanded > MAX_EXPANDED or info.file_size / max(info.compress_size, 1) > 200:
                            raise ValueError('archive_expansion_limit')
                        with archive.open(info) as handle:
                            member = handle.read(MAX_MEMBER+1)
                        if len(member) > MAX_MEMBER:
                            raise ValueError('archive_member_limit')
                        members += 1
                        member_digest = _digest(member)
                        for index, offset, length, value in _dex_strings(member):
                            strings += 1
                            if _natural(value):
                                add([_candidate(value, {'layer': 'apk_dex', 'member': info.filename,
                                    'member_sha256': member_digest, 'string_index': index, 'offset': offset,
                                    'byte_length': length, 'source_span_hash': _digest(member[offset:offset+length]),
                                    'transform': 'dex_mutf8'}, method='dex_string_input', completeness='string_constant')])
                diagnostic['stages'].append({'stage': 'dex', 'status': 'scanned', 'members': members, 'strings': strings})
            except (ValueError, struct.error, zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
                diagnostic['stages'].append({'stage': 'dex', 'status': 'limited', 'error_type': type(exc).__name__})
    else:
        diagnostic['stages'].append({'stage': 'dispatch', 'status': 'outside_supported_scope'})
    existing = prompt.setdefault('embedded_prompts', [])
    keys = {(p.get('text_hash') or p.get('evidence_text_hash'), p.get('source'), p.get('recovery_origin', {}).get('offset')) for p in existing}
    added = 0
    for candidate in candidates:
        key = (candidate.get('text_hash') or candidate.get('evidence_text_hash'), candidate['source'], candidate['recovery_origin'].get('offset'))
        if key not in keys:
            existing.append(candidate)
            keys.add(key)
            added += 1
            if candidate['comparison_eligible']:
                prompt.setdefault('structural_features', {}).update(candidate['features'])
    diagnostic['new_candidates'] = added
    diagnostic['candidate_count'] = sum(p.get('extraction_version') == VERSION for p in existing)
    # Stable on reapplication; preserve all pre-existing feature groups.
    diagnostic.pop('new_candidates')
    prompt['recovery_diagnostics'] = diagnostic
    return output
