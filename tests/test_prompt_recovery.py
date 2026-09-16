from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import struct
import zipfile
import zlib

import pytest

from ai_signal_hub.prompt_recovery import (
    MAX_MEMBER, MAX_SOURCE, PythonInputs, _bounded_inflate, _dex_strings,
    _natural, _pyinstaller_members, recover_prompt_features,
)
from ai_signal_hub.similarity import sample_profile
from test_sample_rules import base


def source_result(text):
    data = text.encode('utf-8')
    result = base(data, language='python', recoverability='original_source')
    return data, result


def prompts(text):
    data, result = source_result(text)
    return recover_prompt_features(result, data)['features']['prompt']['embedded_prompts']


WRAPPED = '''import openai
instructions = []
menu = input("Choose one action from the menu.")
if menu == '1':
    instructions.append("""Hello ChatGPT, from now on you are going to act as a book critic.
        请概括这本书的主要内容，不要捏造事实。
        Use plain text, not a bullet list.""")
instructions.append("Describe the setting in two sentences.")
def prefix(item):
    header = "Read the description carefully before responding. "
    return header + item
def send_prompt(value):
    return openai.ChatCompletion.create(model='gpt-4', messages=[{'role':'user','content':value}])
def wrapper(value):
    return send_prompt(value)
def process(items):
    for value in items:
        answer = wrapper(prefix(value))
process(instructions)
def unused():
    value = "You are an assistant. Generate a poem about rain."
    return value
'''


def test_multiline_unicode_wrapper_list_loop_and_scope():
    found = prompts(WRAPPED)
    assert len(found) == 3
    assert any('请概括' in p['text'] for p in found)
    assert any(p['text'].startswith('Read the description') for p in found)
    assert all('Choose one' not in p['text'] and 'poem about rain' not in p['text'] for p in found)
    assert all(p['call_sites'][0]['callee'] == 'openai.ChatCompletion.create' for p in found)
    assert all(p['completeness'] == 'static_component' for p in found)


def test_evidence_offsets_hashes_idempotency_and_original_groups_preserved():
    data, original = source_result(WRAPPED)
    before = copy.deepcopy(original)
    recovered = recover_prompt_features(original, data)
    assert original == before
    for key in ('toolchain', 'code_style', 'recovery'):
        assert recovered['features'][key] == original['features'][key]
    assert recovered['classification'] == original['classification']
    for prompt in recovered['features']['prompt']['embedded_prompts']:
        origin = prompt['recovery_origin']
        raw = data[origin['offset']:origin['offset']+origin['byte_length']]
        assert origin['source_span_hash'] == 'sha256:'+hashlib.sha256(raw).hexdigest()
        assert prompt['text_hash'] == 'sha256:'+hashlib.sha256(prompt['text'].encode()).hexdigest()
    assert recover_prompt_features(recovered, data) == recovered


def test_base64_model_parameter_decodes_two_constant_components():
    first = 'Make a list of commands to display current date. Return only commands.'
    second = '请用中文总结这篇文章并注明不确定的信息。'
    script = f'''import base64, requests
first = {base64.b64encode(first.encode()).decode()!r}
second = {base64.b64encode(second.encode()).decode()!r}
def query(body):
    return requests.post('https://api.openai.com/v1/chat/completions', json=body)
query({{'messages':[{{'role':'user', 'content':base64.b64decode(first).decode('utf-8')}}]}})
query({{'messages':[{{'role':'user', 'content':base64.b64decode(second).decode('utf-8')}}]}})
'''
    found = prompts(script)
    assert {p['text'] for p in found} == {first, second}
    assert all(p['recovery_origin']['transform'] == 'base64_utf8' for p in found)


def test_fstring_retains_parts_without_inventing_runtime_value():
    found = prompts('''from openai import OpenAI
client=OpenAI()
name=input("Type your name here:")
value=f"Please greet this reader: {name}. Use a friendly tone."
client.chat.completions.create(messages=[{'role':'user','content':value}])
''')
    assert len(found) == 2
    assert all('Type your name' not in p['text'] and 'Alice' not in p['text'] for p in found)
    assert all(p['completeness'] == 'static_component' for p in found)


@pytest.mark.parametrize('text', [
    'CREATE TABLE events (_id INTEGER PRIMARY KEY, payload TEXT, code INTEGER)',
    'No enum corresponding to given code: ',
    'Creating a literal unquoted value of null is forbidden; create JSON null instead.',
    'Could not generate a response from the HTTP server.',
    'Choose one action from the menu: 1. Generate a script 2. Exit',
])
def test_unbound_library_messages_sql_and_menu_are_not_prompts(text):
    assert not _natural(text)


@pytest.mark.parametrize('text', [
    'You are an Android automation assistant. Use the screen XML to respond with an action.',
    'The previous action has been executed. Please determine if the task is complete.',
    'Make a list of commands to display date. Return only commands.',
])
def test_unbound_instruction_requires_explicit_request_and_task(text):
    assert _natural(text)


@pytest.mark.parametrize('script', [
    'x="You are an assistant. Generate a poem about rain."\nprint(x)',
    'import openai\nprint("You are an assistant. Generate a poem about rain.")',
    'import requests\nrequests.post("https://example.org",json={"prompt":"Generate a poem about rain."})',
    'import openai\np=input("You are an assistant. Generate a poem about rain.")\nopenai.ChatCompletion.create(messages=[{"role":"user","content":p}])',
])
def test_source_not_in_known_model_argument_is_excluded(script):
    assert not prompts(script)


def dex_blob(strings):
    header = bytearray(112+4*len(strings))
    header[:8] = b'dex\n035\0'
    struct.pack_into('<I', header, 40, 0x12345678)
    struct.pack_into('<II', header, 56, len(strings), 112)
    for i, text in enumerate(strings):
        struct.pack_into('<I', header, 112+i*4, len(header))
        length = len(text.encode('utf-16-le'))//2
        while length >= 128:
            header.append((length & 127) | 128)
            length >>= 7
        header.append(length)
        # Include an astral character to test DEX MUTF-8 surrogate decoding.
        encoded = text.encode('utf-16-le')
        mutf = ''.join(chr(struct.unpack_from('<H', encoded, j)[0]) for j in range(0,len(encoded),2)).encode('utf-8','surrogatepass')
        header.extend(mutf.replace(b'\0', b'\xc0\x80')+b'\0')
    struct.pack_into('<II',header,32,len(header),112)
    return bytes(header)


def binary_result(data):
    result = base(data, recoverability='strings_only')
    result['features']['toolchain']['evidence'] = [{'type':'model_identifier','normalized':{'family':'Test'},'value':'test-model'}]
    return result


def test_dex_all_strings_unicode_newlines_and_no_library_noise():
    text = 'You are an Android automation assistant.\n请分析屏幕内容，再返回 JSON。🙂'
    data = dex_blob(['irrelevant']*5200+[text, 'CREATE TABLE code (response TEXT)'])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('classes.dex', data)
    payload = buf.getvalue()
    out = recover_prompt_features(binary_result(payload), payload)
    found = out['features']['prompt']['embedded_prompts']
    assert [p['text'] for p in found] == [text]
    assert found[0]['recovery_origin']['string_index'] == 5200
    assert found[0]['recovery_origin']['member'] == 'classes.dex'
    assert out['features']['prompt']['recovery_diagnostics']['stages'][-1]['strings'] == 5202


def carchive(payload):
    compressed = zlib.compress(payload)
    name = b'entry\0'
    toc = struct.pack('!IIIIBc',18+len(name),0,len(compressed),len(payload),1,b's')+name
    cookie = struct.pack('!8sIIII64s',b'MEI\x0c\x0b\x0a\x0b\x0e',len(compressed)+len(toc)+88,len(compressed),len(toc),310,b'python310.dll')
    return b'MZ'+b'\0'*100+compressed+toc+cookie


def test_carchive_prompt_constants_without_python_decompiler():
    text = 'Make a list of commands to show the time. Return only commands.'
    payload = b'\0'+base64.b64encode(text.encode())+b'\0'
    data = carchive(payload)
    assert next(_pyinstaller_members(data))[2] == payload
    found = recover_prompt_features(binary_result(data), data)['features']['prompt']['embedded_prompts']
    assert len(found) == 1 and found[0]['text'] == text
    assert found[0]['recovery_origin']['layer'] == 'pyinstaller_script'
    without_toolchain = base(data, recoverability='strings_only')
    assert recover_prompt_features(without_toolchain, data)['features']['prompt']['embedded_prompts'][0]['text'] == text


def test_length_prefixed_base64_is_not_joined_to_next_marshal_tag():
    text='Make a list of commands to show the time. Return only commands.'
    while len(text.encode()) % 3:
        text += ' '
    encoded=base64.b64encode(text.encode())
    data=b'\xc1'+struct.pack('<I',len(encoded))+encoded+b'a4\0\0\0next'
    found=recover_prompt_features(binary_result(data),data)['features']['prompt']['embedded_prompts']
    assert len(found)==1 and found[0]['text']==text
    assert found[0]['boundary']=='length_prefixed_constant'


def test_go_pool_window_cannot_be_used_as_full_prompt_hash():
    data = b'MZ Go build\0'+b'You are a Lua code generator. Generate clean Lua code.'+b'A'*2500
    found = recover_prompt_features(binary_result(data), data)['features']['prompt']['embedded_prompts']
    assert found and not found[0]['comparison_eligible']
    assert 'text_hash' not in found[0] and 'fuzzy_hash' not in found[0]
    result = binary_result(data)
    result['features']['prompt']['embedded_prompts'] = found
    assert not sample_profile(result)['prompt']['records']


def test_go_descriptor_extracts_exact_length_not_adjacent_pool():
    text = b'You are a Lua code generator. Generate clean Lua code.'
    data = bytearray(2048)
    data[:2]=b'MZ'
    data[80:88]=b'Go build'
    struct.pack_into('<I',data,60,128)
    data[128:132]=b'PE\0\0'
    struct.pack_into('<H',data,134,1)
    struct.pack_into('<H',data,148,112)
    struct.pack_into('<H',data,152,0x20b)
    struct.pack_into('<Q',data,176,0x140000000)
    struct.pack_into('<III',data,276,0x1000,1024,512)
    data[600:600+len(text)]=text
    data[600+len(text):600+len(text)+4]=b'NOPE'
    struct.pack_into('<QQ',data,800,0x140001000+88,len(text))
    result=recover_prompt_features(binary_result(bytes(data)),bytes(data))
    found=result['features']['prompt']['embedded_prompts']
    assert len(found)==1 and found[0]['text']==text.decode()
    assert found[0]['boundary']=='pointer_length_descriptor'


@pytest.mark.parametrize('data',[b'dex\n035\0',b'PKbad',b'MZMEI\x0c\x0b\x0a\x0b\x0e'])
def test_malformed_binary_yields_diagnostic_not_execution(data):
    result=recover_prompt_features(binary_result(data),data)
    assert not result['features']['prompt']['embedded_prompts']
    assert 'recovery_diagnostics' in result['features']['prompt']


def test_limits_hash_guard_and_parse_errors():
    data,result=source_result('(')
    assert recover_prompt_features(result,data)['features']['prompt']['recovery_diagnostics']['stages'][0]['status']=='parse_unavailable'
    with pytest.raises(ValueError,match='SHA-256'):
        recover_prompt_features(result,b'other')
    with pytest.raises(ValueError):
        _bounded_inflate(zlib.compress(b'A'*1000),10)
    with pytest.raises(ValueError):
        _bounded_inflate(b'bad',MAX_MEMBER+1)
    data,result=source_result(' '* (MAX_SOURCE+1))
    assert recover_prompt_features(result,data)['features']['prompt']['recovery_diagnostics']['stages'][0]['status']=='source_size_limit'


def test_secrets_never_become_prompt_evidence():
    fake_secret = 'sk-' + 'abcdefghijklmn123456'
    script=f'import openai\nopenai.ChatCompletion.create(messages=[{{"role":"user","content":"{fake_secret}"}}])'
    assert not prompts(script)


def test_no_sample_execution_or_network(monkeypatch):
    import builtins
    import socket
    import subprocess
    def fail(*args,**kwargs):
        raise AssertionError('execution/network prohibited')
    monkeypatch.setattr(builtins,'eval',fail)
    monkeypatch.setattr(subprocess,'Popen',fail)
    monkeypatch.setattr(socket,'create_connection',fail)
    assert len(prompts(WRAPPED))==3


def test_api_adapter_saves_new_prompt_fields(platform):
    service,repo=platform
    saved=service.analyze_sample(io.BytesIO(WRAPPED.encode()),'input.py','Fixture')
    stored=repo.get_sample(saved['sha256'])
    from pathlib import Path
    artifact=Path(stored['artifact_path'])
    on_disk=json.loads((artifact/'result.json').read_text(encoding='utf-8'))
    assert on_disk==stored['result_json']
    found=on_disk['features']['prompt']['embedded_prompts']
    assert len([p for p in found if p.get('source')=='python_static_input'])==3
    assert json.loads((artifact/'prompt_features.json').read_text(encoding='utf-8'))==on_disk['features']['prompt']


def test_uniform_container_markers_do_not_require_decompiler(platform, monkeypatch):
    service,_=platform
    import shutil
    monkeypatch.setattr(shutil,'which',lambda name:None)
    text='Make a list of commands to show the time. Return only commands.'
    payload=b'\0gpt-3.5-turbo\0'+base64.b64encode(text.encode())+b'\0'
    data=carchive(payload)
    saved=service.analyze_sample(io.BytesIO(data),'fixture.exe','Fixture')
    result=service.repository.get_sample(saved['sha256'])['result_json']
    assert result['features']['prompt']['embedded_prompts']
    assert result['features']['toolchain']['evidence']
    assert result['features']['recovery']['static_toolchain']['decompiler_required'] is False
    assert not result['features']['code_style']['metrics']
