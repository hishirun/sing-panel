"""Automatic asset invalidation and reusable, scoped browser initializers."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from panel import assets


def test_asset_hash_changes_with_content_even_when_size_and_mtime_match(tmp_path, monkeypatch):
    monkeypatch.setattr(assets, 'STATIC_DIR', tmp_path)
    asset = tmp_path / 'app.js'
    asset.write_text('first')
    before = asset.stat()
    first = assets.asset_url('app.js')
    assert assets.asset_is_versioned('/static/app.js', first.split('=')[1])
    asset.write_text('other')
    os.utime(asset, ns=(before.st_atime_ns, before.st_mtime_ns))
    second = assets.asset_url('app.js')
    assert second != first
    assert not assets.asset_is_versioned('app.js', first.split('=')[1])
    assert assets.asset_url('app.js') == second


@pytest.mark.parametrize('path', ['../secret', '/etc/passwd', 'a/../../secret', './app.js'])
def test_asset_paths_cannot_escape_static_directory(path):
    with pytest.raises(ValueError):
        assets.asset_url(path)
    assert not assets.asset_is_versioned(path, 'invalid')


def test_asset_symlinks_cannot_escape_static_directory(tmp_path, monkeypatch):
    static = tmp_path / 'static'
    static.mkdir()
    secret = tmp_path / 'secret'
    secret.write_text('private')
    (static / 'link.js').symlink_to(secret)
    monkeypatch.setattr(assets, 'STATIC_DIR', static)
    with pytest.raises(ValueError):
        assets.asset_url('link.js')
    assert not assets.asset_is_versioned('missing.js', '123')


def test_page_script_lifecycle():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node.js is required for frontend lifecycle checks')
    result = subprocess.run(
        [node, str(Path(__file__).parent / 'frontend/page_scripts.cjs')],
        cwd=Path(__file__).resolve().parent.parent,
        text=True, capture_output=True, timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
