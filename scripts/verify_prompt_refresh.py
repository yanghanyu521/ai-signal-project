"""Read-only verification of a prompt migration and its raw evidence spans."""
from __future__ import annotations

import argparse
import ast
import io
import json
import re
import zipfile
from contextlib import closing

from ai_signal_hub.config import Settings
from ai_signal_hub.prompt_recovery import VERSION, _b64, _digest, _dex_strings, _pyinstaller_members
from rebuild_similarity import readonly, save
from refresh_prompt_evidence import without_prompt


def verify(batch):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', batch):
        raise ValueError('Invalid batch')
    settings = Settings()
    output = settings.data_dir / 'evaluations' / batch
    manifest = json.loads((output / 'manifest.json').read_text(encoding='utf-8'))
    with closing(readonly(output / 'knowledge.before.db')) as con:
        before = {r['sha256']: dict(r) for r in con.execute('SELECT * FROM samples')}
    with closing(readonly(output / 'knowledge.preview.db')) as con:
        after = {r['sha256']: dict(r) for r in con.execute('SELECT * FROM samples')}
    assert before.keys() == after.keys()
    allowed = {'result_json', 'artifact_path', 'updated_at'}
    scope = set(manifest['scope'])
    changed = []
    for sha, row in before.items():
        differences = {key for key in row if row[key] != after[sha][key]}
        if sha in scope:
            assert differences <= allowed
            assert without_prompt(json.loads(row['result_json'])) == without_prompt(json.loads(after[sha]['result_json']))
            changed.append(sha)
        else:
            assert not differences
    verified = 0
    fresh_match = 0
    by_layer = {}
    for review in manifest['reviewed']:
        if not review['in_apply_scope']:
            continue
        sha = review['sha256']
        from pathlib import Path
        data = Path(review['input_path']).read_bytes()
        assert _digest(data) == 'sha256:' + sha
        current = json.loads(after[sha]['result_json'])['features']['prompt']['embedded_prompts']
        added = current[review['before_count']:]
        archives = {name: member for name, _, member in _pyinstaller_members(data)}
        dex_cache = {}
        python_constants = None
        for item in added:
            origin = item['recovery_origin']
            layer, transform = origin['layer'], origin['transform']
            member = data
            if layer == 'pyinstaller_script':
                member = archives[origin['member']]
            elif layer == 'apk_dex':
                name = origin['member']
                if name not in dex_cache:
                    with zipfile.ZipFile(io.BytesIO(data)) as archive:
                        value = archive.read(name)
                    dex_cache[name] = (value, {offset: text for _, offset, _, text in _dex_strings(value)})
                member = dex_cache[name][0]
            if 'member_sha256' in origin:
                assert _digest(member) == origin['member_sha256']
            start, length = origin['offset'], origin['byte_length']
            span = member[start:start + length]
            assert len(span) == length and _digest(span) == origin['source_span_hash']
            if layer == 'python_source':
                # A modern Python AST may locate an f-string component without
                # enclosing quotes. Verify it in its original AST, never eval it.
                if python_constants is None:
                    tree = ast.parse(data.decode('utf-8-sig'))
                    python_constants = [n for n in ast.walk(tree) if isinstance(n, ast.Constant)]
                literals = [n.value for n in python_constants
                            if n.lineno == origin['line'] and n.end_lineno == origin['end_line']]
                if transform == 'base64_utf8':
                    literals = [_b64(value) for value in literals]
                assert item['text'] in literals
            elif transform == 'base64_utf8':
                assert _b64(span) == item['text']
            elif transform == 'dex_mutf8':
                assert dex_cache[origin['member']][1][start] == item['text']
            else:
                assert span.decode('utf-8', 'ignore') == item['text']
            digest = _digest(item['text'].encode('utf-8'))
            if item['comparison_eligible']:
                assert item['text_hash'] == digest
            else:
                assert item['evidence_text_hash'] == digest
                assert 'text_hash' not in item and 'fuzzy_hash' not in item
            verified += 1
            by_layer[layer] = by_layer.get(layer, 0) + 1
        fresh_batch = ('20260903_prompt_context_fresh_carchive_v2' if sha.startswith('766c356d6a4b')
                       else '20260903_prompt_context_fresh_v1')
        fresh = json.loads((settings.data_dir / 'evaluations' / fresh_batch / sha / 'result.json').read_text(encoding='utf-8'))
        assert not fresh['errors']
        fresh_items = [p for p in fresh['features']['prompt']['embedded_prompts'] if p.get('extraction_version') == VERSION]
        assert fresh_items == added
        fresh_match += 1
    result = {'scoped_rows_verified': len(changed), 'untouched_rows_verified': len(before) - len(changed),
              'permitted_columns': sorted(allowed), 'raw_evidence_spans_verified': verified,
              'evidence_by_layer': by_layer, 'fresh_pipeline_prompt_matches': fresh_match,
              'protected_groups_unchanged': True, 'raw_samples_hash_verified': True}
    target = output / 'verification.json'
    if target.exists():
        raise ValueError('Do not overwrite verification')
    save(target, result)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--batch', required=True)
    verify(parser.parse_args().batch)
