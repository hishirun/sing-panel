import copy
import io
import json
import os
import socket
import subprocess
import tarfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent import __version__
from agent.connection import origin
from agent.machine import interfaces
from agent.runtime import Core
from agent.storage import Spool, atomic_json, read_json
from agent.update import validate_archive, begin_boot, healthy


def test_installer_repairs_readable_venv_without_exposing_state_or_following_symlinks(tmp_path):
    script = (Path(__file__).resolve().parents[1] / 'deploy' / 'install-agent.sh').read_text()
    repair = '\n'.join(line for line in script.splitlines()
                       if line.startswith('find -P "$venv_root" -type '))
    assert repair.count('\n') == 1
    assert 'umask 022\n    python3 -m venv "$venv_root"' in script
    assert 'find -P "$venv_root" ! -user root -print -quit' in script
    assert '[[ ! -L "$venv_root" ]]' in script
    runtime = tmp_path / 'venv'
    library = runtime / 'lib'
    library.mkdir(parents=True)
    runtime.chmod(0o700)
    library.chmod(0o700)
    package = library / 'module.py'
    package.write_text('value = 1\n')
    package.chmod(0o600)
    executable = runtime / 'python'
    executable.write_text('#!/bin/sh\n')
    executable.chmod(0o700)
    state = tmp_path / 'private-state'
    state.mkdir(mode=0o700)
    identity = state / 'config.json'
    atomic_json(identity, {'credential': 'private'})
    (runtime / 'external-link').symlink_to(identity)
    subprocess.run(['bash', '-c', repair], env={**os.environ, 'venv_root': str(runtime)}, check=True)
    assert runtime.stat().st_mode & 0o777 == 0o755
    assert library.stat().st_mode & 0o777 == 0o755
    assert package.stat().st_mode & 0o777 == 0o644
    assert executable.stat().st_mode & 0o777 == 0o755
    assert state.stat().st_mode & 0o777 == 0o700
    assert identity.stat().st_mode & 0o777 == 0o600


def counter(value):
    return {'user>>>node:user>>>traffic>>>uplink': value}


def test_spool_ack_cannot_delete_newer_snapshot_and_survives_restart(tmp_path):
    queue = Spool(tmp_path)
    first = queue.store('epoch-old', counter(10))
    second = queue.store('epoch-old', counter(20))
    assert first != second
    queue.acknowledge(first)
    assert queue.oldest()['counters'] == counter(20)
    queue.store('epoch-new', counter(3))
    restored = Spool(tmp_path)
    assert restored.oldest()['report_id'] == second
    restored.acknowledge(second)
    assert restored.oldest()['epoch'] == 'epoch-new'
    with pytest.raises(ValueError, match='regressed'):
        restored.store('epoch-new', counter(2))
    assert restored.oldest()['counters'] == counter(3)


class FakeProcess:
    def __init__(self):
        self.stopped = False

    def poll(self):
        return 0 if self.stopped else None

    def terminate(self):
        self.stopped = True

    def wait(self, timeout):
        return 0


@pytest.fixture
def core(tmp_path, monkeypatch):
    monkeypatch.setattr('agent.runtime.subprocess.run', lambda *a, **k: SimpleNamespace(returncode=0, stdout='sing-box version test', stderr=''))
    result = Core({'data_dir': str(tmp_path), 'binary': '/does-not-run', 'panel': 'https://panel.example'})
    result.state.update(revision='old', desired_state='running')
    result.renew_lease(90)
    atomic_json(result.target, {'inbounds': [], 'outbounds': [{'type': 'direct', 'tag': 'direct'}]})
    result.process = FakeProcess()
    monkeypatch.setattr(result, 'sample', lambda strict=False: result.spool.store(result.epoch, counter(42)))
    return result


def test_bad_candidate_does_not_interrupt_last_good_core(core, monkeypatch):
    previous = core.target.read_bytes()
    process = core.process
    monkeypatch.setattr('agent.runtime.subprocess.run', lambda *a, **k: SimpleNamespace(returncode=1, stderr='invalid inbound'))
    with pytest.raises(ValueError, match='配置检查失败'):
        core.apply({'inbounds': []}, 'new')
    assert core.running() and core.process is process and not process.stopped
    assert core.target.read_bytes() == previous
    assert core.state['revision'] == 'old'


def test_failed_launch_rolls_back_and_persists_final_old_epoch(core, monkeypatch):
    previous = core.target.read_bytes()
    old_epoch = core.epoch
    calls = []

    def launch():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError('bind failure')
        core.process = FakeProcess()
        core.epoch = 'rollback-epoch'

    monkeypatch.setattr(core, 'launch', launch)
    with pytest.raises(RuntimeError, match='bind failure'):
        core.apply({'inbounds': [], 'outbounds': [{'type': 'direct', 'tag': 'new'}]}, 'new')
    assert read_json(core.target) == json.loads(previous)
    assert core.state['revision'] == 'old' and core.running()
    assert core.spool.oldest()['epoch'] == old_epoch
    assert core.spool.oldest()['counters'] == counter(42)


def test_lease_expiry_stops_forwarding_without_losing_spooled_counters(core):
    core.lease_deadline = 0
    core.tick()
    assert not core.running()
    assert core.spool.oldest()['counters'] == counter(42)
    assert core.state['revision'] == 'old'


def test_controller_zero_lease_stops_immediately(core):
    core.desired({'type': 'desired', 'protocol': 1, 'state': 'stopped', 'lease_seconds': 0,
                  'revision': 'old', 'commands': [], 'error': 'quota reached'})
    assert not core.running() and not core.lease_alive()
    assert core.error == 'quota reached'
    with pytest.raises(ValueError, match='zero lease'):
        core.desired({'type': 'desired', 'protocol': 1, 'state': 'running', 'lease_seconds': 0})


def test_commands_are_allowlisted_and_deduplicated(core, monkeypatch):
    restarts = []
    monkeypatch.setattr(core, 'restart', lambda: restarts.append(1))
    core.command({'id': 'one', 'action': 'restart'})
    core.command({'id': 'one', 'action': 'restart'})
    core.command({'id': 'two', 'action': 'shell', 'command': 'touch /tmp/unwanted'})
    assert restarts == [1]
    assert core.state['command_results'] == [
        {'id': 'one', 'ok': True, 'error': ''},
        {'id': 'two', 'ok': False, 'error': 'Unsupported management command'},
    ]
    assert read_json(core.state_path)['command_acks'] == ['one', 'two']


def test_prepare_reserves_loopback_management_ports_and_rewrites_cache(core):
    config = core.prepare({'inbounds': [], 'experimental': {'cache_file': {'enabled': True, 'path': '/main/cache.db'},
                           'clash_api': {'external_controller': '0.0.0.0:9999'}}})
    assert config['experimental']['clash_api']['external_controller'] == '127.0.0.1:19191'
    assert config['experimental']['v2ray_api']['listen'] == '127.0.0.1:19190'
    assert config['experimental']['cache_file']['path'] == str(core.directory / 'routing-cache.db')
    with pytest.raises(ValueError, match='conflicts'):
        core.prepare({'inbounds': [{'listen_port': 19190}]})


def test_https_origin_and_local_development_exceptions():
    assert origin('https://panel.example/') == 'https://panel.example'
    assert origin('http://127.0.0.1:18889', True) == 'http://127.0.0.1:18889'
    for bad in ['http://panel.example', 'https://user:pass@panel.example', 'https://panel.example/agent',
                'https://panel.example?secret=x', 'https://panel.example#x']:
        with pytest.raises(ValueError):
            origin(bad)
    with pytest.raises(ValueError):
        origin('http://198.51.100.1', True)


def test_enrollment_retry_reuses_pending_identity_and_rejects_redirect(tmp_path, monkeypatch):
    from agent.client import enroll
    config = tmp_path / 'config.json'
    calls = []

    def request(panel, path, payload, **kwargs):
        calls.append(payload.copy())
        if len(calls) == 1:
            raise TimeoutError('response lost')
        return json.dumps({'server_id': 'server-a', 'protocol': 1, 'ws_url': 'wss://panel.example/agent/v1/ws'}).encode()

    monkeypatch.setattr('agent.client.request', request)
    with pytest.raises(TimeoutError):
        enroll(config, 'https://panel.example', 'x' * 40)
    assert not config.exists()
    assert read_json(tmp_path / '.enrollment-pending.json')['credential']
    assert enroll(config, 'https://panel.example', 'x' * 40) == 'server-a'
    assert calls[0]['credential'] == calls[1]['credential']
    assert config.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match='已经接入'):
        enroll(config, 'https://different.example', 'x' * 40)


def test_reenrollment_preserves_old_identity_until_same_server_is_confirmed(tmp_path, monkeypatch):
    from agent.client import enroll
    config = tmp_path / 'config.json'
    previous = {'panel': 'https://panel.example', 'server_id': 'same-server', 'credential': 'a' * 64}
    atomic_json(config, previous)
    calls = []

    def request(panel, path, payload, **kwargs):
        calls.append(payload.copy())
        if len(calls) == 1:
            raise TimeoutError('response lost')
        return json.dumps({'server_id': 'same-server', 'protocol': 1, 'ws_url': '/agent/v1/ws'}).encode()

    monkeypatch.setattr('agent.client.request', request)
    with pytest.raises(TimeoutError):
        enroll(config, 'https://panel.example', 'x' * 40)
    assert read_json(config) == previous
    enroll(config, 'https://panel.example', 'x' * 40)
    assert calls[0] == calls[1]
    assert calls[0]['expected_server_id'] == 'same-server'
    assert read_json(config)['credential'] != previous['credential']


def test_machine_billing_excludes_bridges_and_ignores_negative_resets():
    text = 'header\nheader\n' + '\n'.join([
        'ens3: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0',
        'veth123: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0',
        'docker0: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0',
        'lo: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0',
    ])
    rows = interfaces(text, {'ens3'}, {'ens3', 'docker0'}, {'ens3': (120, 180)}, 2)
    assert len(rows) == 3
    assert [r['name'] for r in rows if r['billable']] == ['ens3']
    assert rows[0]['rx'] == 0 and rows[0]['tx'] == 10


def archive(files, extra=None):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        if extra:
            tar.addfile(extra)
    return buffer.getvalue()


def release_files():
    return {'agent/__init__.py': b"__version__ = '0.1.0'\n", 'agent/__main__.py': b'pass\n',
            'agent/requirements.txt': b'websockets==15.0.1\n'}


def test_update_archive_rejects_escape_links_dependency_drift_and_wrong_version():
    files = release_files()
    assert validate_archive(archive(files), '0.1.0', files['agent/requirements.txt'])
    link = tarfile.TarInfo('agent/escape')
    link.type, link.linkname = tarfile.SYMTYPE, '/etc/shadow'
    for payload in [archive({**files, '../bad': b'oops'}), archive(files, link),
                    archive({**files, 'etc/systemd/system/evil.service': b'oops'})]:
        with pytest.raises(ValueError):
            validate_archive(payload, '0.1.0', files['agent/requirements.txt'])
    with pytest.raises(ValueError, match='依赖'):
        validate_archive(archive(files), '0.1.0', b'changed-dependency')
    with pytest.raises(ValueError, match='version'):
        validate_archive(archive(files), '9.9.9', files['agent/requirements.txt'])


def test_failed_update_boot_rolls_back_release_without_touching_identity(tmp_path):
    releases = tmp_path / 'install' / 'releases'
    releases.mkdir(parents=True)
    (releases / 'old').mkdir()
    (releases / 'new').mkdir()
    (releases / 'current').symlink_to('new')
    data = tmp_path / 'data'
    data.mkdir()
    config = {'install_dir': str(tmp_path / 'install'), 'data_dir': str(data)}
    atomic_json(data / 'config.json', {'server_id': 'keep', 'credential': 'keep'})
    atomic_json(data / 'runtime.json', {'command_results': [{'id': 'update-one', 'ok': True, 'error': ''}]})
    atomic_json(data / 'pending-update.json', {'previous': 'old', 'next': 'new', 'attempted': False, 'command_id': 'update-one'})
    assert not begin_boot(config)
    assert begin_boot(config)
    assert os.readlink(releases / 'current') == 'old'
    assert read_json(data / 'config.json') == {'server_id': 'keep', 'credential': 'keep'}
    assert read_json(data / 'runtime.json')['command_results'][0]['ok'] is False
    assert not (data / 'pending-update.json').exists()


def test_update_hash_failure_and_failed_start_preserve_current_release(tmp_path, monkeypatch):
    import hashlib
    from agent import update
    releases = tmp_path / 'install' / 'releases'
    (releases / 'old').mkdir(parents=True)
    (releases / 'current').symlink_to('old')
    data = tmp_path / 'data'
    data.mkdir()
    config = {'install_dir': str(tmp_path / 'install'), 'data_dir': str(data), 'panel': 'https://panel.example'}
    requirements = (Path(update.__file__).parent / 'requirements.txt').read_bytes()
    bundle = archive({'agent/__init__.py': b"__version__ = '0.2.0'\n", 'agent/__main__.py': b'raise SystemExit(1)\n',
                      'agent/requirements.txt': requirements})
    manifest = {'version': '0.2.0', 'bundle': {'url': '/agent/bundle.tar.gz', 'sha256': '0' * 64}}
    monkeypatch.setattr(update, 'request', lambda panel, path, **kwargs: json.dumps(manifest).encode() if path.endswith('manifest.json') else bundle)
    with pytest.raises(ValueError, match='校验失败'):
        update.stage(config, data / 'runtime.json')
    manifest['bundle']['sha256'] = hashlib.sha256(bundle).hexdigest()
    with pytest.raises(ValueError, match='启动检查失败'):
        update.stage(config, data / 'runtime.json')
    assert os.readlink(releases / 'current') == 'old'
    assert not (data / 'pending-update.json').exists()


def test_update_release_switch_is_scoped_and_commits_after_controller_health(tmp_path, monkeypatch):
    import hashlib
    from agent import update
    releases = tmp_path / 'install' / 'releases'
    (releases / 'old').mkdir(parents=True)
    (releases / 'current').symlink_to('old')
    data = tmp_path / 'data'
    data.mkdir()
    atomic_json(data / 'config.json', {'credential': 'unchanged'})
    queue = Spool(data)
    queue.store('surviving-epoch', counter(99))
    config = {'install_dir': str(tmp_path / 'install'), 'data_dir': str(data), 'panel': 'https://panel.example'}
    requirements = (Path(update.__file__).parent / 'requirements.txt').read_bytes()
    bundle = archive({'agent/__init__.py': b"__version__ = '0.2.0'\n", 'agent/__main__.py': b"print('0.2.0')\n",
                      'agent/requirements.txt': requirements, 'deploy/sing-panel-agent.service': b'ignored'})
    manifest = {'version': '0.2.0', 'bundle': {'url': '/agent/bundle.tar.gz', 'sha256': hashlib.sha256(bundle).hexdigest()}}
    monkeypatch.setattr(update, 'request', lambda panel, path, **kwargs: json.dumps(manifest).encode() if path.endswith('manifest.json') else bundle)
    assert update.stage(config, data / 'runtime.json')
    assert os.readlink(releases / 'current').startswith('0.2.0-')
    assert read_json(data / 'config.json') == {'credential': 'unchanged'}
    assert Spool(data).oldest()['counters'] == counter(99)
    assert not (tmp_path / 'install' / 'deploy').exists()
    assert not begin_boot(config)
    healthy(config)
    assert not begin_boot(config)


def test_interrupted_or_mismatched_websocket_ack_keeps_durable_report(tmp_path, monkeypatch):
    from agent.client import Agent
    path = tmp_path / 'config.json'
    atomic_json(path, {'panel': 'https://panel.example', 'server_id': 'server-a', 'credential': 'a' * 64,
                       'data_dir': str(tmp_path), 'binary': '/missing-test-core'})
    instance = Agent(path)
    instance.core.spool.store('old-core', counter(123))
    original = instance.core.spool.oldest()

    class Interrupted:
        def send(self, payload):
            self.payload = payload

        def recv(self, timeout):
            raise TimeoutError()

    with pytest.raises(TimeoutError):
        instance.exchange(Interrupted())
    assert instance.core.spool.oldest() == original

    class Mismatched(Interrupted):
        def recv(self, timeout):
            return json.dumps({'type': 'desired', 'protocol': 1, 'ack_report_id': 'wrong'})

    with pytest.raises(ValueError, match='acknowledgement'):
        instance.exchange(Mismatched())
    assert instance.core.spool.oldest() == original


def test_unsolicited_revocation_stops_core_without_discarding_unacked_report(core, monkeypatch):
    from agent.client import Agent
    instance = Agent.__new__(Agent)
    instance.core = core
    instance.config = core.config
    core.spool.store('older-epoch', counter(11))
    original = core.spool.oldest()

    class Revoked:
        def send(self, payload):
            pass

        def recv(self, timeout):
            return json.dumps({'type': 'desired', 'protocol': 1, 'revoked': True,
                               'state': 'stopped', 'lease_seconds': 0, 'commands': []})

    with pytest.raises(PermissionError, match='revoked'):
        instance.exchange(Revoked())
    assert not core.running() and not core.lease_alive()
    assert core.spool.oldest() == original


def test_ip_limits_keep_oldest_ips_and_reject_cross_user_or_invalid_ip_commands(core, monkeypatch):
    closed = []
    rows = [
        {'id': 'first', 'start': '1', 'metadata': {'inboundUser': 'node:user', 'sourceIP': '192.0.2.1'}},
        {'id': 'second', 'start': '2', 'metadata': {'inboundUser': 'node:user', 'sourceIP': '192.0.2.1'}},
        {'id': 'extra', 'start': '3', 'metadata': {'inboundUser': 'node:user', 'sourceIP': '192.0.2.2'}},
        {'id': 'unknown', 'start': '4', 'metadata': {'inboundUser': 'node:another', 'sourceIP': '192.0.2.3'}},
        {'id': 'bad-ip', 'start': '5', 'metadata': {'inboundUser': 'node:user', 'sourceIP': '../bad'}},
        {'id': '../path', 'start': '6', 'metadata': {'inboundUser': 'node:user', 'sourceIP': '192.0.2.4'}},
    ]

    def control(path='/connections', method='GET'):
        if method == 'DELETE':
            closed.append(path)
            return {}
        return {'connections': rows}

    monkeypatch.setattr(core, 'control', control)
    core.set_policy({'max_ips': {'user': 1}})
    allowed, online, truncated = core.connections(enforce=True)
    assert [row['id'] for row in allowed] == ['first', 'second']
    assert closed == ['/connections/extra'] and online == 1 and not truncated
    for identity, user, ip in [('bad-user', 'another', '192.0.2.3'), ('bad-ip', 'user', 'invalid')]:
        core.command({'id': identity, 'action': 'disconnect_ip', 'user_id': user, 'source_ip': ip})
        assert core.state['command_results'][-1]['ok'] is False
    assert closed == ['/connections/extra']
    core.command({'id': 'kick-one-ip', 'action': 'disconnect_ip', 'user_id': 'user', 'source_ip': '192.0.2.1'})
    assert closed[-2:] == ['/connections/first', '/connections/second']
    assert core.state['command_results'][-1]['ok'] is True
    with pytest.raises(ValueError, match='IP limit'):
        core.set_policy({'max_ips': {'user': True}})


def test_connection_reports_are_bounded_but_limits_cover_all_connections(core, monkeypatch):
    rows = [{'id': f'id-{i}', 'start': str(i), 'metadata': {'inboundUser': 'node:user', 'sourceIP': '192.0.2.1'}}
            for i in range(1005)]
    monkeypatch.setattr(core, 'control', lambda *a, **k: {'connections': rows})
    core.set_policy({'max_ips': {'user': 0}})
    connections, online, truncated = core.connections()
    assert len(connections) == 1000 and online == 1 and truncated
    assert len(core.connections(maximum=None)[0]) == 1005


def test_new_update_marker_survives_current_exchange(tmp_path, monkeypatch):
    from agent.client import Agent
    atomic_json(tmp_path / 'config.json', {'panel': 'https://panel.example', 'server_id': 'server-a',
                'credential': 'a' * 64, 'data_dir': str(tmp_path), 'binary': '/missing-test-core'})
    instance = Agent(tmp_path / 'config.json')
    instance.core.spool.store('epoch', counter(1))
    marker = tmp_path / 'pending-update.json'
    monkeypatch.setattr(instance.core, 'desired', lambda message: atomic_json(marker, {'attempted': False}))

    class Updating:
        def send(self, value):
            self.report = json.loads(value)

        def recv(self, timeout):
            return json.dumps({'type': 'desired', 'protocol': 1, 'ack_report_id': self.report['report_id']})

    instance.exchange(Updating())
    assert read_json(marker) == {'attempted': False}


def test_slow_update_cannot_block_lease_expiry(core, monkeypatch):
    entered, release, expired = threading.Event(), threading.Event(), threading.Event()

    def slow_stage(*args):
        entered.set()
        release.wait(3)
        return False

    monkeypatch.setattr('agent.update.stage', slow_stage)
    thread = threading.Thread(target=lambda: core.desired({'type': 'desired', 'protocol': 1,
        'state': 'running', 'revision': 'old', 'lease_seconds': 90,
        'commands': [{'id': 'slow-update', 'action': 'update_agent'}]}))
    thread.start()
    assert entered.wait(1)
    core.lease_deadline = 0

    def expire():
        core.tick()
        expired.set()

    guard = threading.Thread(target=expire)
    guard.start()
    try:
        assert expired.wait(1), 'Update download blocked the lease supervisor'
        assert not core.running()
    finally:
        release.set()
        guard.join(3)
        thread.join(3)


def test_actual_websocket_exchange_authenticates_and_acknowledges(tmp_path):
    from websockets.sync.client import connect
    from websockets.sync.server import serve
    from agent.client import Agent
    atomic_json(tmp_path / 'config.json', {'panel': 'http://127.0.0.1', 'allow_insecure_local': True,
                'server_id': 'server-a', 'credential': 'a' * 64, 'data_dir': str(tmp_path), 'binary': '/missing-test-core'})
    instance = Agent(tmp_path / 'config.json')
    instance.core.spool.store('old-core', counter(123))
    seen = []

    def handle(socket):
        seen.append(socket.request.headers['Authorization'])
        report = json.loads(socket.recv())
        seen.append(report['counters'])
        socket.send(json.dumps({'type': 'desired', 'protocol': 1, 'ack_report_id': report['report_id'],
                               'state': 'stopped', 'lease_seconds': 0, 'revision': 'none', 'commands': []}))

    with serve(handle, '127.0.0.1', 0) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.socket.getsockname()[1]
        with connect(f'ws://127.0.0.1:{port}', additional_headers={'Authorization': instance.authorization}, proxy=None) as socket:
            instance.exchange(socket)
        server.shutdown()
        thread.join(timeout=5)
    assert seen == ['Bearer server-a.' + 'a' * 64, counter(123)]
    assert not instance.core.spool.oldest()


@pytest.mark.skipif(not os.environ.get('SING_BOX'), reason='requires a real statistics-enabled sing-box binary')
def test_real_core_counts_payload_and_keeps_epoch_across_restart(tmp_path):
    def free_port():
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            return listener.getsockname()[1]

    upstream = socket.socket()
    upstream.bind(('127.0.0.1', 0))
    upstream.listen()
    request, response = b'x' * 65536, b'y' * 131072

    def echo():
        connection, _ = upstream.accept()
        with connection:
            remaining = len(request)
            while remaining:
                remaining -= len(connection.recv(remaining))
            connection.sendall(response)

    thread = threading.Thread(target=echo, daemon=True)
    thread.start()
    ports = []
    while len(set(ports)) < 3:
        ports = [free_port(), free_port(), free_port()]
    stats, control, inbound = ports
    core = Core({'data_dir': str(tmp_path), 'binary': os.environ['SING_BOX'], 'stats_port': stats, 'control_port': control})
    core.state['desired_state'] = 'running'
    core.renew_lease(90)
    config = {'inbounds': [{'type': 'direct', 'tag': 'node:user', 'listen': '127.0.0.1', 'listen_port': inbound,
                           'override_address': '127.0.0.1', 'override_port': upstream.getsockname()[1]}],
              'outbounds': [{'type': 'direct', 'tag': 'direct'}],
              'experimental': {'v2ray_api': {'stats': {'enabled': True, 'inbounds': ['node:user']}}}}
    try:
        core.apply(config, 'first')
        first_epoch = core.epoch
        with socket.create_connection(('127.0.0.1', inbound), timeout=5) as connection:
            connection.sendall(request)
            received = bytearray()
            while len(received) < len(response):
                chunk = connection.recv(65536)
                assert chunk
                received.extend(chunk)
        assert bytes(received) == response
        thread.join(timeout=5)
        core.sample(strict=True)
        snapshot = core.spool.oldest()
        assert snapshot['counters']['inbound>>>node:user>>>traffic>>>uplink'] == len(request)
        assert snapshot['counters']['inbound>>>node:user>>>traffic>>>downlink'] == len(response)
        core.apply(config, 'second')
        assert core.epoch != first_epoch
        assert core.spool.oldest()['epoch'] == first_epoch
        assert core.spool.oldest()['counters'] == snapshot['counters']
        core.spool.acknowledge(core.spool.oldest()['report_id'])
        assert core.spool.oldest()['epoch'] == core.epoch
    finally:
        core.stop()
        upstream.close()


def test_configuration_receipt_survives_unrelated_command_and_restart(core, monkeypatch):
    message = {'type': 'desired', 'protocol': 1, 'state': 'running', 'lease_seconds': 90,
               'revision': 'candidate-one', 'config': {'inbounds': []}}
    def reject(*args):
        raise ValueError('private-secret-from-core')
    monkeypatch.setattr(core, 'apply', reject)
    core.desired(message)
    receipt = core.state['apply_result']
    assert receipt == {'revision': 'candidate-one', 'ok': False, 'error': '节点配置校验或启动失败'}
    core.command({'id': 'unrelated', 'action': 'resync'})
    assert core.error == '' and core.state['apply_result'] == receipt
    restored = Core(core.config)
    assert restored.state['apply_result'] == receipt
    def accept(document, revision):
        core.state['revision'] = revision
    monkeypatch.setattr(core, 'apply', accept)
    core.desired(message)
    assert core.state['apply_result'] == {'revision': 'candidate-one', 'ok': True, 'error': ''}
