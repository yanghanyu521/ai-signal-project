"""Inspect the scoped local prompt-gap samples as data, never execute them."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from pathlib import Path

from ai_signal_hub.config import Settings


def scoped_samples():
    settings = Settings()
    baseline = json.loads((settings.data_dir / 'evaluations/20260903_inventory45/inventory.json').read_text(encoding='utf-8'))
    wanted = {r['sha256']: r for r in baseline['records'] if r['toolchain_evidence'] and not r['prompt_candidates']}
    paths = {}
    for path in (settings.workspace_root / '恶意样本文件').rglob('*'):
        if path.is_file() and path.name in wanted:
            paths.setdefault(path.name, path)
    for sha, record in wanted.items():
        path = paths.get(sha)
        if path is None:
            raise ValueError('Missing scoped sample: ' + sha)
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            raise ValueError('Hash mismatch: ' + str(path))
        yield record, path, data


def inspect(prefix):
    for record, path, data in scoped_samples():
        if prefix and not record['sha256'].startswith(prefix):
            continue
        summary = {'sha256': record['sha256'], 'family': record['family'], 'path': str(path), 'bytes': len(data)}
        if record['language'] == 'python':
            tree = ast.parse(data.decode('utf-8-sig'))
            summary['strings'] = [{'line': n.lineno, 'length': len(n.value), 'preview': n.value[:200]}
                                  for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                                  and len(n.value.split()) >= 5 and len(n.value) >= 25][:40]
            summary['calls'] = sorted({ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)})[:80]
        else:
            pattern = rb'(?i)(?:initial_[a-z_]*prompt|validation_criteria|buildValidationPrompt|you are (?:an? |the |going)|Hello ChatGPT|generate a |prompt.{0,16}[:=])'
            hits = list(re.finditer(pattern, data))
            summary['marker_count'] = len(hits)
            summary['contexts'] = [{'offset': m.start(), 'preview': data[max(0,m.start()-30):m.start()+230].decode('utf-8', 'replace')}
                                   for m in hits[:16]]
        print(json.dumps(summary, ensure_ascii=False))


def evaluate(prefix):
    from ai_signal_hub.prompt_recovery import recover_prompt_features
    from rebuild_similarity import readonly
    from contextlib import closing
    with closing(readonly(Settings().database_path)) as con:
        stored = {r['sha256']: json.loads(r['result_json']) for r in con.execute('SELECT sha256,result_json FROM samples')}
    for record, path, data in scoped_samples():
        if prefix and not record['sha256'].startswith(prefix):
            continue
        result = recover_prompt_features(stored[record['sha256']], data)
        prompt = result['features']['prompt']
        print(json.dumps({'sha256':record['sha256'], 'family':record['family'],
              'diagnostics':prompt.get('recovery_diagnostics'),
              'prompts':[{'source':p['source'],'length':len(p.get('text','')), 'preview':p.get('text_preview','')[:110],
                          'origin':p.get('recovery_origin'), 'boundary':p.get('boundary')}
                         for p in prompt['embedded_prompts']]}, ensure_ascii=False))


def fresh(batch, prefix):
    import io
    from contextlib import redirect_stdout
    from ai_signal_hub.legacy import LegacyAdapters
    from rebuild_similarity import fingerprints, save
    if not re.fullmatch(r'[A-Za-z0-9_-]+',batch):
        raise ValueError('Invalid batch')
    settings=Settings()
    output=settings.data_dir/'evaluations'/batch
    if output.exists():
        raise ValueError('Batch already exists')
    output.mkdir(parents=True)
    before=fingerprints(settings.database_path)
    summaries=[]
    for record,path,data in scoped_samples():
        if prefix and not record['sha256'].startswith(prefix):
            continue
        with redirect_stdout(io.StringIO()):
            result=LegacyAdapters(settings).analyze_sample(path,output/record['sha256'])
        prompts=result['features']['prompt']['embedded_prompts']
        summary={'sha256':record['sha256'],'family':record['family'],'errors':result['errors'],
                 'prompt_count':len(prompts),'new_context_candidates':sum('extraction_version' in p for p in prompts),
                 'toolchain_count':len(result['features']['toolchain']['evidence']),
                 'recovery':result['features']['prompt'].get('recovery_diagnostics')}
        summaries.append(summary)
        print(json.dumps({k:v for k,v in summary.items() if k!='recovery'},ensure_ascii=False))
        if hashlib.sha256(path.read_bytes()).hexdigest()!=record['sha256']:
            raise ValueError('Protected input changed')
    if fingerprints(settings.database_path)!=before:
        raise ValueError('Database changed during fresh verification')
    save(output/'summary.json',{'samples':summaries,'database_unchanged':True,'input_hashes_verified':True,
                              'scope':'fresh_uniform_adapter_static_only'})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', default='')
    parser.add_argument('--evaluate', action='store_true')
    parser.add_argument('--fresh-batch')
    args = parser.parse_args()
    if args.fresh_batch:
        fresh(args.fresh_batch,args.prefix)
    else:
        (evaluate if args.evaluate else inspect)(args.prefix)
