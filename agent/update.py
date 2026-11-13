"""Self-update only from the already-enrolled controller's verified release."""
import ast
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from . import __version__
from .connection import request
from .storage import atomic_json, read_json


def version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d+\.\d+\.\d+', value):
        raise ValueError('Invalid release version')
    return tuple(map(int, value.split('.')))


def validate_archive(contents, expected_version, existing_requirements):
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(contents), mode='r:gz') as archive:
        for member in archive.getmembers():
            name = member.name.removeprefix('./')
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts or '\\' in name or not name:
                raise ValueError('Unsafe release archive path')
            allowed = path.parts[0] == 'agent' or name in ('deploy', 'deploy/sing-panel-agent.service')
            if not allowed or not (member.isdir() or member.isfile()):
                raise ValueError('Release contains an unsupported file or link')
            if member.isdir():
                continue
            total += member.size
            if member.size > 4 * 1024 * 1024 or total > 16 * 1024 * 1024:
                raise ValueError('Expanded release is too large')
            if name in files:
                raise ValueError('Duplicate archive path')
            stream = archive.extractfile(member)
            files[name] = stream.read() if stream else b''
    for required in ('agent/__init__.py', 'agent/__main__.py', 'agent/requirements.txt'):
        if required not in files:
            raise ValueError('Release is incomplete')
    module = ast.parse(files['agent/__init__.py'].decode())
    release_version = next((node.value.value for node in module.body if isinstance(node, ast.Assign)
                            and any(isinstance(target, ast.Name) and target.id == '__version__' for target in node.targets)
                            and isinstance(node.value, ast.Constant)), None)
    if release_version != expected_version:
        raise ValueError('Release version does not match the manifest')
    if files['agent/requirements.txt'].strip() != existing_requirements.strip():
        raise ValueError('此版本需要更新运行依赖，请使用服务器安装命令升级')
    for name, data in files.items():
        if name.startswith('agent/') and name.endswith('.py'):
            compile(data, name, 'exec')
    return files


def stage(config, state_path):
    """Switch the release symlink; caller persists command result then re-execs."""
    panel = config['panel']
    allow_local = bool(config.get('allow_insecure_local'))
    manifest = json.loads(request(panel, '/agent/manifest.json', maximum=65536, allow_local=allow_local))
    version = manifest.get('version')
    if version_tuple(version) < version_tuple(__version__):
        raise ValueError('拒绝安装较旧的 Agent 版本')
    bundle = manifest.get('bundle', {})
    if bundle.get('url') != '/agent/bundle.tar.gz' or not re.fullmatch(r'[a-f0-9]{64}', str(bundle.get('sha256', ''))):
        raise ValueError('Invalid release manifest')
    contents = request(panel, '/agent/bundle.tar.gz', maximum=8 * 1024 * 1024, allow_local=allow_local)
    digest = hashlib.sha256(contents).hexdigest()
    if digest != bundle['sha256']:
        raise ValueError('Agent 下载校验失败')
    package = Path(__file__).resolve().parent
    requirements = (package / 'requirements.txt').read_bytes()
    files = validate_archive(contents, version, requirements)
    releases = Path(config.get('install_dir', '/opt/sing-panel-agent')) / 'releases'
    current = releases / 'current'
    if not current.is_symlink() or not releases.is_dir():
        raise ValueError('当前 Agent 不支持在线更新，请用安装命令安装正式服务')
    old_target = os.readlink(current)
    if Path(old_target).is_absolute() or len(Path(old_target).parts) != 1:
        raise ValueError('Invalid existing release layout')
    name = version + '-' + digest[:16]
    destination = releases / name
    if current.resolve() == destination.resolve():
        return False
    temporary = Path(tempfile.mkdtemp(prefix='.update-', dir=releases))
    try:
        for path, data in files.items():
            if not path.startswith('agent/'):
                continue
            target = temporary / path
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o644)
        check = subprocess.run([sys.executable, '-m', 'agent', '--version'], cwd=temporary,
                               env={**os.environ, 'PYTHONPATH': str(temporary)},
                               capture_output=True, text=True, timeout=15)
        if check.returncode or check.stdout.strip() != version:
            raise ValueError('新版 Agent 启动检查失败，已保留当前版本')
        if destination.exists():
            # Immutable hash-named releases cannot be silently overwritten.
            for path, data in files.items():
                if path.startswith('agent/') and (destination / path).read_bytes() != data:
                    raise ValueError('Existing release content mismatch')
        else:
            temporary.rename(destination)
        marker = {'previous': old_target, 'next': name, 'attempted': False}
        atomic_json(Path(state_path).parent / 'pending-update.json', marker)
        link = releases / '.next-release'
        link.unlink(missing_ok=True)
        link.symlink_to(name)
        os.replace(link, current)
        return True
    except Exception:
        # Marker is created only after package validation, before the symlink swap.
        if current.is_symlink() and os.readlink(current) != old_target:
            link = releases / '.rollback-release'
            link.unlink(missing_ok=True)
            link.symlink_to(old_target)
            os.replace(link, current)
        (Path(state_path).parent / 'pending-update.json').unlink(missing_ok=True)
        raise
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def begin_boot(config):
    """Return true when a failed update was rolled back and needs another exec."""
    marker_path = Path(config['data_dir']) / 'pending-update.json'
    marker = read_json(marker_path)
    if not marker:
        return False
    releases = Path(config.get('install_dir', '/opt/sing-panel-agent')) / 'releases'
    for key in ('previous', 'next'):
        if not re.fullmatch(r'[A-Za-z0-9._-]{1,160}', str(marker.get(key, ''))):
            raise ValueError('Invalid update recovery marker')
    if not marker.get('attempted'):
        marker['attempted'] = True
        atomic_json(marker_path, marker)
        return False
    current = releases / 'current'
    link = releases / '.rollback-release'
    link.unlink(missing_ok=True)
    link.symlink_to(marker['previous'])
    os.replace(link, current)
    # A rollback must not later acknowledge the failed release as successful.
    state_path = Path(config['data_dir']) / 'runtime.json'
    state = read_json(state_path, {})
    command_id = marker.get('command_id')
    if command_id:
        for result in state.get('command_results', []):
            if result.get('id') == command_id:
                result.update(ok=False, error='新版 Agent 未能正常接入，已回滚到之前的版本')
        atomic_json(state_path, state)
    marker_path.unlink()
    return True


def healthy(config):
    (Path(config['data_dir']) / 'pending-update.json').unlink(missing_ok=True)
