"""Official GeoCatalog compatibility without relaxing cache path safety."""
import io
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from agent.runtime import Core
from panel.routing import GEO_CATALOG


def rule_set(tag):
    return {'type': 'remote', 'tag': tag, 'format': 'binary',
            'url': 'https://rules.example/' + str(tag) + '.srs'}


@pytest.fixture
def core(tmp_path, monkeypatch):
    monkeypatch.setattr('agent.runtime.subprocess.run', lambda *a, **k:
                        SimpleNamespace(returncode=0, stdout='sing-box version test'))
    return Core({'data_dir': str(tmp_path), 'binary': '/does-not-run'})


def test_every_official_geo_catalog_tag_is_a_safe_cache_filename(core, monkeypatch):
    tags = [kind + '-' + value for kind, values in GEO_CATALOG.items() for value in values]
    assert 'geosite-category-ai-!cn' in tags
    assert any('@' in tag for tag in tags)
    actual_exists = Path.exists
    # Already-cached sets isolate tag validation from network availability.
    cache = core.directory / 'rule-sets'
    monkeypatch.setattr(Path, 'exists', lambda path:
                        True if path.parent == cache and path.suffix == '.srs' else actual_exists(path))
    monkeypatch.setattr('agent.runtime.urlopen', lambda *a, **k: pytest.fail('Cached catalog should not download'))
    prepared = core.prepare({'inbounds': [], 'route': {'rule_set': [rule_set(tag) for tag in tags]}})
    entries = prepared['route']['rule_set']
    assert len(entries) == len(tags)
    for entry, tag in zip(entries, tags):
        path = Path(entry['initial_path'])
        assert path.parent == cache
        assert path.name == tag + '.srs'


@pytest.mark.parametrize('tag', [
    '../outside', '..', '/tmp/outside', 'a/b', 'a\\b', 'a\0b', 'a\nb',
    'geosite-category-ai-!cn/../../outside', 'name@cn/child', 'name.srs',
    '%2e%2e%2foutside', '', 'a' * 161, None, 42, ['geosite-cn'],
])
def test_invalid_tag_is_rejected_before_any_download_or_file_write(core, monkeypatch, tag):
    monkeypatch.setattr('agent.runtime.urlopen', lambda *a, **k: pytest.fail('Unsafe tag reached network'))
    with pytest.raises(ValueError, match='Unsupported rule-set source'):
        core.prepare({'inbounds': [], 'route': {'rule_set': [rule_set(tag)]}})
    assert not list((core.directory / 'rule-sets').iterdir())
    assert not (core.directory.parent / 'outside.srs').exists()


@pytest.mark.skipif(not os.environ.get('SING_BOX'), reason='SING_BOX required for real core validation')
def test_real_core_accepts_prepared_ai_exclusion_and_attribute_sets(tmp_path, monkeypatch):
    binary = os.environ['SING_BOX']
    source = tmp_path / 'rules.json'
    source.write_text(json.dumps({'version': 3, 'rules': [{'domain_suffix': ['openai.com']}]}))
    compiled = tmp_path / 'rules.srs'
    subprocess.run([binary, 'rule-set', 'compile', str(source), '-o', str(compiled)],
                   cwd=tmp_path, check=True, capture_output=True, timeout=10)
    downloads = []

    def download(url, **kwargs):
        downloads.append(url)
        return io.BytesIO(compiled.read_bytes())

    monkeypatch.setattr('agent.runtime.urlopen', download)
    core = Core({'data_dir': str(tmp_path / 'agent-state'), 'binary': binary})
    tags = ['geosite-category-ai-!cn', 'geosite-google@cn']
    document = {'log': {'level': 'error'}, 'inbounds': [],
                'outbounds': [{'type': 'direct', 'tag': 'direct'}],
                'route': {'final': 'direct', 'rule_set': [rule_set(tag) for tag in tags],
                          'rules': [{'rule_set': tags, 'action': 'route', 'outbound': 'direct'}]}}
    prepared = core.prepare(document)
    assert len(downloads) == 2
    for entry in prepared['route']['rule_set']:
        assert Path(entry['initial_path']).read_bytes() == compiled.read_bytes()
    candidate = tmp_path / 'candidate.json'
    candidate.write_text(json.dumps(prepared))
    subprocess.run([binary, 'check', '-c', str(candidate)], cwd=tmp_path,
                   check=True, capture_output=True, timeout=10)
    assert core.prepare(document) == prepared
    assert len(downloads) == 2  # Second preparation uses the validated cache.
