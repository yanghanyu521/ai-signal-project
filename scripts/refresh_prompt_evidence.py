"""Preview all 45, then atomically apply only the 13 scoped prompt results.

Read payloads as bytes; no sample execution, external tools, or model calls.
All old artifacts remain intact. Apply requires an unchanged database and code.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path

from ai_signal_hub.config import Settings
from ai_signal_hub.database import Database, json_text, utc_now
from ai_signal_hub.prompt_recovery import VERSION, recover_prompt_features
from ai_signal_hub.repository import Repository
from ai_signal_hub.similarity import SampleSimilarityService
from rebuild_similarity import DERIVED, backup, fingerprints, readonly, save


def code_hashes(settings):
    return {name: hashlib.sha256((settings.project_root/name).read_bytes()).hexdigest() for name in (
        'src/ai_signal_hub/prompt_recovery.py', 'src/ai_signal_hub/binary_layout.py',
        'src/ai_signal_hub/legacy.py', 'src/ai_signal_hub/similarity.py',
        'scripts/refresh_prompt_evidence.py')}


def without_prompt(result):
    value=copy.deepcopy(result)
    value['features'].pop('prompt', None)
    return value


def review_summary(old, new, sha, family):
    before=old['features']['prompt'].get('embedded_prompts',[])
    after=new['features']['prompt'].get('embedded_prompts',[])
    added=after[len(before):]
    return {'sha256':sha,'family':family,'before_count':len(before),'after_count':len(after),
            'added_count':len(added),'exact_boundary_added':sum(p.get('comparison_eligible',True) for p in added),
            'uncertain_boundary_added':sum(not p.get('comparison_eligible',True) for p in added),
            'sources':sorted({p.get('source') for p in added}),
            'diagnostics':new['features']['prompt'].get('recovery_diagnostics'),
            'added_evidence':[{'source':p['source'],'text_hash':p.get('text_hash'),
                 'evidence_text_hash':p.get('evidence_text_hash'),'length':len(p.get('text','')),
                 'preview':p.get('text_preview','')[:100], 'origin':p.get('recovery_origin'),
                 'call_sites':p.get('call_sites',[]), 'boundary':p.get('boundary'),
                 'completeness':p.get('completeness')} for p in added]}


def preview(settings, output):
    if output.exists():
        raise ValueError('Batch exists; never overwrite an audit')
    baseline=json.loads((settings.data_dir/'evaluations/20260903_inventory45/inventory.json').read_text(encoding='utf-8'))
    scope={r['sha256'] for r in baseline['records'] if r['toolchain_evidence'] and not r['prompt_candidates']}
    output.mkdir(parents=True)
    original=output/'knowledge.before.db'
    working=output/'knowledge.preview.db'
    backup(settings.database_path,original)
    backup(original,working)
    before=fingerprints(original)
    with closing(readonly(original)) as con:
        rows=[dict(r) for r in con.execute('SELECT * FROM samples ORDER BY sha256')]
    wanted={r['sha256'] for r in rows}
    paths={}
    for path in (settings.workspace_root/'恶意样本文件').rglob('*'):
        if path.is_file() and path.name in wanted:
            paths.setdefault(path.name,path)
    if set(paths)!=wanted or len(scope)!=13:
        raise ValueError('Expected 45 original paths and 13 scoped samples; inspect inventory')
    reviewed=[]
    for row in rows:
        sha=row['sha256']
        data=paths[sha].read_bytes()
        if hashlib.sha256(data).hexdigest()!=sha:
            raise ValueError('Input hash mismatch: '+sha)
        old=json.loads(row['result_json'])
        new=recover_prompt_features(old,data)
        if without_prompt(old)!=without_prompt(new):
            raise ValueError('Unexpected non-prompt mutation')
        if old['features']['prompt']['embedded_prompts']!=new['features']['prompt']['embedded_prompts'][:len(old['features']['prompt']['embedded_prompts'])]:
            raise ValueError('Prior evidence was changed')
        summary=review_summary(old,new,sha,row['source_case'])
        summary['input_path']=str(paths[sha])
        summary['in_apply_scope']=sha in scope
        reviewed.append(summary)
        artifact=output/('artifacts' if sha in scope else 'regression')/sha
        artifact.mkdir(parents=True)
        save(artifact/'result.json',new)
        if sha in scope:
            for name,value in [('features',new['features']),('metadata',new['sample']),('classification',new['classification']),
                               ('toolchain_features',new['features']['toolchain']),('prompt_features',new['features']['prompt']),
                               ('code_style_features',new['features']['code_style'])]:
                save(artifact/(name+'.json'),value)
            parent=Path(row['artifact_path']).resolve()
            if not parent.is_relative_to(settings.workspace_root.resolve()):
                raise ValueError('Legacy artifact path outside workspace')
            if (parent/'strings.jsonl').is_file():
                shutil.copy2(parent/'strings.jsonl',artifact/'strings.jsonl')
            save(artifact/'revision.json',{'parent_artifact_path':str(parent),'version':VERSION,
                 'input_sha256':sha,'prior_result_sha256':hashlib.sha256(row['result_json'].encode()).hexdigest(),
                 'scope':'prompt_only','legacy_strings_reused':(parent/'strings.jsonl').is_file()})
            with closing(sqlite3.connect(working)) as con:
                con.execute('UPDATE samples SET result_json=?,artifact_path=?,updated_at=? WHERE sha256=?',
                            (json_text(new),str(artifact.resolve()),utc_now(),sha))
                con.commit()
    run=SampleSimilarityService(Repository(Database(working))).rebuild()
    after=fingerprints(working)
    protected=lambda x:{k:v for k,v in x.items() if k not in DERIVED|{'samples'}}
    if protected(before)!=protected(after):
        raise ValueError('Preview changed non-sample evidence')
    if fingerprints(settings.database_path)!=before:
        raise ValueError('Production changed during preview; retain audit and use a fresh batch')
    manifest={'version':VERSION,'source':str(settings.database_path),'code_sha256':code_hashes(settings),
              'before':before,'after':after,'scope':sorted(scope),'reviewed':reviewed,
              'new_run':run,'production_applied':False,'protected_records_unchanged':True,
              'summary':{'reviewed':len(rows),'scoped':len(scope),
                         'scoped_with_added':sum(r['in_apply_scope'] and r['added_count']>0 for r in reviewed),
                         'scoped_added_candidates':sum(r['added_count'] for r in reviewed if r['in_apply_scope']),
                         'other_samples_with_additions':sum(not r['in_apply_scope'] and r['added_count']>0 for r in reviewed)}}
    save(output/'manifest.json',manifest)
    print(json.dumps(manifest['summary'],ensure_ascii=False))
    for r in reviewed:
        if r['in_apply_scope']:
            print(json.dumps({k:r[k] for k in ('sha256','family','before_count','after_count','exact_boundary_added','uncertain_boundary_added')},ensure_ascii=False))


def apply(settings,output):
    manifest=json.loads((output/'manifest.json').read_text(encoding='utf-8'))
    if (output/'applied.json').exists():
        raise ValueError('Already applied')
    if manifest['source']!=str(settings.database_path) or manifest['code_sha256']!=code_hashes(settings):
        raise ValueError('Source/code changed; create new preview')
    working=output/'knowledge.preview.db'
    if fingerprints(working)!=manifest['after']:
        raise ValueError('Preview database changed')
    with closing(readonly(working)) as source:
        updates=[dict(r) for r in source.execute('SELECT * FROM samples') if r['sha256'] in manifest['scope']]
        derived={t:[dict(r) for r in source.execute('SELECT * FROM '+t)] for t in DERIVED}
    for row in updates:
        path=Path(row['artifact_path'])/'result.json'
        if json.loads(path.read_text(encoding='utf-8'))!=json.loads(row['result_json']):
            raise ValueError('Artifact was changed after review')
    # Lock before the final fingerprint check: atomic prompt and derived-table
    # replacement, with no window where new prompts retain old associations.
    with closing(sqlite3.connect(settings.database_path)) as con:
        con.execute('BEGIN IMMEDIATE')
        try:
            if fingerprints(settings.database_path)!=manifest['before']:
                raise ValueError('Production changed; create a fresh preview')
            for row in updates:
                con.execute('UPDATE samples SET result_json=?,artifact_path=?,updated_at=? WHERE sha256=?',
                            (row['result_json'],row['artifact_path'],row['updated_at'],row['sha256']))
            for table in ('sample_relations','sample_clusters','sample_cluster_runs'):
                con.execute('DELETE FROM '+table)
            for table in ('sample_cluster_runs','sample_clusters','sample_relations'):
                for row in derived[table]:
                    columns=','.join('"'+name+'"' for name in row)
                    con.execute('INSERT INTO '+table+' ('+columns+') VALUES ('+','.join('?' for _ in row)+')',tuple(row.values()))
            con.commit()
        except Exception:
            con.rollback()
            raise
    after=fingerprints(settings.database_path)
    save(output/'applied.json',{'applied_at':utc_now(),'backup':str(output/'knowledge.before.db'),
                              'scope':manifest['scope'],'after':after,'matches_preview':after==manifest['after']})
    if after!=manifest['after']:
        raise RuntimeError('Concurrent change after commit; inspect audit, do not overwrite')
    print(json.dumps({'applied':len(updates),'matches_preview':True,'backup':str(output/'knowledge.before.db')},ensure_ascii=False))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=['preview','apply'])
    parser.add_argument('--batch',required=True)
    args=parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_-]+',args.batch):
        raise ValueError('Batch must be a single directory name')
    settings=Settings()
    {'preview':preview,'apply':apply}[args.mode](settings,settings.data_dir/'evaluations'/args.batch)
