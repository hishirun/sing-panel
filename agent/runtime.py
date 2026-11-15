"""A single local core, last-good rollback, leases, and durable traffic snapshots."""
import copy
import ipaddress
import json
import logging
import os
import re
import secrets
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from . import __version__
from .machine import snapshot
from .stats import query
from .storage import Spool, atomic_json, read_json

log = logging.getLogger(__name__)


class Core:
    def __init__(self, config):
        self.config = dict(config)
        self.directory = Path(config.get('data_dir', '/var/lib/sing-panel-agent')).resolve()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.binary = config.get('binary', '/opt/sing-panel-agent/sing-box')
        self.stats_port = int(config.get('stats_port', 19190))
        self.control_port = int(config.get('control_port', self.stats_port + 1))
        if not (1024 <= self.stats_port <= 65534 and 1024 <= self.control_port <= 65535 and self.stats_port != self.control_port):
            raise ValueError('Invalid agent statistics ports')
        self.state_path = self.directory / 'runtime.json'
        self.target = self.directory / 'sing-box.json'
        self.state = read_json(self.state_path, {})
        self.state.setdefault('command_acks', [])
        self.state.setdefault('command_results', [])
        self.state.setdefault('desired_state', 'stopped')
        self.state.setdefault('revision', '')
        self.state.setdefault('apply_result', {})
        self.state.setdefault('control_secret', secrets.token_urlsafe(32))
        self.state.setdefault('policy', {'max_ips': {}})
        self.spool = Spool(self.directory)
        self.lock = threading.RLock()
        self.process = None
        self.epoch = uuid.uuid4().hex
        self.error = ''
        self.stop_event = threading.Event()
        self.thread = None
        self.connected = False
        self.reexec_requested = False
        self.lease_deadline = 0.0
        # Do not extend a lease across a clock rollback or a prolonged outage.
        previous = self.state.get('lease_received', 0)
        duration = self.state.get('lease_seconds', 0)
        elapsed = time.time() - previous
        if 0 <= elapsed < duration <= 90:
            self.lease_deadline = time.monotonic() + duration - elapsed
        try:
            version = subprocess.run([self.binary, 'version'], capture_output=True, text=True, timeout=5, check=True).stdout
            self.version = version.splitlines()[0].removeprefix('sing-box version ')[:120]
        except (OSError, subprocess.SubprocessError, IndexError):
            self.version = 'unknown'

    def persist(self):
        atomic_json(self.state_path, self.state)

    def running(self):
        return self.process is not None and self.process.poll() is None

    def lease_alive(self):
        return time.monotonic() < self.lease_deadline

    def renew_lease(self, seconds):
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not 0 <= seconds <= 90:
            raise ValueError('Invalid controller lease')
        with self.lock:
            self.lease_deadline = time.monotonic() + seconds
            self.state.update(lease_received=time.time(), lease_seconds=seconds)
            self.persist()

    def revoke(self):
        with self.lock:
            self.lease_deadline = 0
            self.state.update(lease_received=0, lease_seconds=0)
            self.persist()
            self.stop_core()
            self.error = '主控授权已失效，核心已停止'

    def sample(self, strict=False):
        if not self.running():
            return
        try:
            self.spool.store(self.epoch, query(self.stats_port))
        except Exception:
            if strict:
                raise RuntimeError('无法保存最终流量采样，已取消核心变更') from None
            raise

    def control(self, path='/connections', method='GET'):
        request = Request(f'http://127.0.0.1:{self.control_port}' + path, method=method,
                          headers={'Authorization': 'Bearer ' + self.state['control_secret']})
        with urlopen(request, timeout=3) as response:
            payload = response.read(4 * 1024 * 1024)
        return json.loads(payload) if payload else {}

    def connections(self, enforce=False, maximum=1000):
        """Only return authorized users, and never accept controller-supplied IDs as paths."""
        if not self.running():
            return [], 0, False
        raw = self.control().get('connections', [])
        if not isinstance(raw, list):
            raise ValueError('Invalid local connection response')
        limits = self.state['policy']['max_ips']
        result, seen, online, truncated = [], {}, set(), False
        for item in sorted(raw, key=lambda value: str(value.get('start', ''))):
            metadata = item.get('metadata', {})
            identity = metadata.get('inboundUser', '') or metadata.get('inboundTag', '')
            if not isinstance(identity, str) or ':' not in identity:
                continue
            node, user = identity.rsplit(':', 1)
            if user not in limits or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', node):
                continue
            connection_id = item.get('id', '')
            if not isinstance(connection_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', connection_id):
                continue
            try:
                address = str(ipaddress.ip_address(metadata.get('sourceIP', '')))
            except ValueError:
                continue
            ips = seen.setdefault(user, set())
            if enforce and limits[user] and address not in ips and len(ips) >= limits[user]:
                self.control('/connections/' + connection_id, 'DELETE')
                continue
            ips.add(address)
            online.add(user)
            if maximum is not None and len(result) >= maximum:
                truncated = True
                continue
            result.append({'id': connection_id, 'user_id': user, 'node_id': node,
                           'source_ip': address, 'start': str(item.get('start', ''))[:80]})
        return result, len(online), truncated

    def set_policy(self, policy):
        if not isinstance(policy, dict) or not isinstance(policy.get('max_ips'), dict) or len(policy['max_ips']) > 20000:
            raise ValueError('Invalid agent access policy')
        limits = policy['max_ips']
        if any(not isinstance(user, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', user) or
               isinstance(limit, bool) or not isinstance(limit, int) or not 0 <= limit <= 1000
               for user, limit in limits.items()):
            raise ValueError('Invalid user IP limit')
        self.state['policy'] = {'max_ips': dict(limits)}

    def prepare(self, document):
        document = copy.deepcopy(document)
        if not isinstance(document, dict) or not isinstance(document.get('inbounds', []), list):
            raise ValueError('Invalid core document')
        for inbound in document.get('inbounds', []):
            port = inbound.get('listen_port')
            if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
                raise ValueError('Agent nodes require an unprivileged listen port')
            if port in (self.stats_port, self.control_port):
                raise ValueError('Node port conflicts with the agent statistics API')
        experimental = document.setdefault('experimental', {})
        stats = experimental.setdefault('v2ray_api', {})
        stats['listen'] = f'127.0.0.1:{self.stats_port}'
        stats.setdefault('stats', {})['enabled'] = True
        experimental['clash_api'] = {'external_controller': f'127.0.0.1:{self.control_port}',
                                     'secret': self.state['control_secret']}
        sets = document.get('route', {}).get('rule_set', [])
        if sets:
            directory = self.directory / 'rule-sets'
            directory.mkdir(mode=0o700, exist_ok=True)
            experimental.setdefault('cache_file', {}).update(enabled=True, path=str(self.directory / 'routing-cache.db'))
            deadline = time.monotonic() + 25
            for entry in sets:
                tag = entry.get('tag', '')
                # Official geosite categories include both exclusions (!cn)
                # and attributes (@cn). These are safe literal filename
                # characters; dots, separators and control bytes remain barred.
                if (entry.get('type') != 'remote' or not isinstance(tag, str)
                        or not re.fullmatch(r'[A-Za-z0-9_!@-]{1,160}', tag)):
                    raise ValueError('Unsupported rule-set source')
                parsed = urlsplit(entry.get('url', ''))
                if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
                    raise ValueError('Rule-set downloads require HTTPS')
                target = directory / (tag + '.srs')
                entry['initial_path'] = str(target)
                if target.exists():
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('Rule-set download deadline exceeded')
                temporary = None
                try:
                    with urlopen(entry['url'], timeout=min(5, remaining)) as response:
                        contents = bytearray()
                        while True:
                            chunk = response.read(65536)
                            if not chunk:
                                break
                            contents.extend(chunk)
                            if len(contents) > 32 * 1024 * 1024 or time.monotonic() > deadline:
                                raise ValueError('Rule-set download exceeded its limit')
                    fd, name = tempfile.mkstemp(dir=directory, prefix='.download-')
                    temporary = Path(name)
                    with os.fdopen(fd, 'wb') as output:
                        output.write(contents)
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError('Rule-set download deadline exceeded')
                    check = subprocess.run([self.binary, 'rule-set', 'decompile', str(temporary), '-o', os.devnull],
                                           capture_output=True, timeout=min(5, remaining))
                    if check.returncode:
                        raise ValueError('Downloaded rule set is invalid: ' + tag)
                    temporary.replace(target)
                finally:
                    if temporary and temporary.exists():
                        temporary.unlink()
        # A controller-side local cache path is never valid on another server.
        if experimental.get('cache_file', {}).get('enabled'):
            experimental['cache_file']['path'] = str(self.directory / 'routing-cache.db')
        return document

    def launch(self):
        self.epoch = uuid.uuid4().hex
        core_log = self.directory / 'core.log'
        if core_log.exists() and core_log.stat().st_size > 10 * 1024 * 1024:
            core_log.replace(self.directory / 'core.log.1')
        with core_log.open('a') as output:
            self.process = subprocess.Popen([self.binary, 'run', '-c', str(self.target)],
                                            cwd=self.directory, stdout=output, stderr=output)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError('sing-box 启动失败，请查看 Agent core.log')
            try:
                self.spool.store(self.epoch, query(self.stats_port))
                return
            except Exception:
                time.sleep(.1)
        self.terminate()
        raise RuntimeError('sing-box 流量统计 API 未就绪')

    def terminate(self):
        if self.running():
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process = None

    def stop_core(self):
        try:
            self.sample(strict=True)
        except Exception:
            log.warning('Final traffic sample unavailable; retaining previously queued counters')
        finally:
            self.terminate()

    def apply(self, document, revision, force=False):
        if not isinstance(revision, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', revision):
            raise ValueError('Invalid configuration revision')
        prepared = self.prepare(document)
        candidate = self.directory / 'candidate.json'
        atomic_json(candidate, prepared)
        result = subprocess.run([self.binary, 'check', '-c', str(candidate)],
                                capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise ValueError('配置检查失败：' + result.stderr[-1000:])
        with self.lock:
            if not self.lease_alive():
                raise ValueError('主控连接已超时，等待重新授权')
            if revision == self.state['revision'] and self.running() and not force:
                return
            old_document = read_json(self.target)
            old_revision = self.state['revision']
            self.sample(strict=True)
            self.terminate()
            atomic_json(self.target, prepared)
            try:
                self.launch()
                self.state['revision'] = revision
                self.persist()
                self.error = ''
            except Exception:
                self.stop_core()
                if old_document is not None:
                    atomic_json(self.target, old_document)
                    self.state['revision'] = old_revision
                    self.persist()
                    if self.lease_alive() and self.state['desired_state'] == 'running':
                        self.launch()
                raise

    def restart(self):
        with self.lock:
            if self.state['desired_state'] != 'running' or not self.lease_alive():
                raise ValueError('核心已停止或授权已过期')
            if not self.target.exists():
                raise ValueError('尚未收到有效节点配置')
            self.sample(strict=True)
            self.terminate()
            self.launch()

    def command(self, item):
        if not isinstance(item, dict) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', str(item.get('id', ''))):
            raise ValueError('Invalid management command')
        identity, action = item['id'], item.get('action')
        if identity in self.state['command_acks']:
            return
        result = {'id': identity, 'ok': True, 'error': ''}
        try:
            if action == 'restart':
                self.restart()
            elif action == 'resync':
                # The controller also sends the current configuration revision.
                pass
            elif action == 'update_agent':
                from .update import stage
                self.reexec_requested = stage(self.config, self.state_path)
                if self.reexec_requested:
                    marker_path = self.directory / 'pending-update.json'
                    marker = read_json(marker_path)
                    marker['command_id'] = identity
                    atomic_json(marker_path, marker)
            elif action in ('disconnect_user', 'disconnect_ip'):
                user = item.get('user_id', '')
                if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', user) or user not in self.state['policy']['max_ips']:
                    raise ValueError('Invalid user identity')
                address = str(ipaddress.ip_address(item.get('source_ip', ''))) if action == 'disconnect_ip' else None
                if self.running():
                    connections, _, _ = self.connections(maximum=None)
                    for row in connections:
                        if row['user_id'] == user and (address is None or row['source_ip'] == address):
                            self.control('/connections/' + row['id'], 'DELETE')
            else:
                raise ValueError('Unsupported management command')
            self.error = ''
        except Exception as error:
            result.update(ok=False, error=str(error)[:1000])
            self.error = result['error']
        with self.lock:
            self.state['command_results'] = (self.state['command_results'] + [result])[-128:]
            self.state['command_acks'] = (self.state['command_acks'] + [identity])[-1024:]
            self.persist()

    def desired(self, message):
        if not isinstance(message, dict) or message.get('type') != 'desired' or message.get('protocol') != 1:
            raise ValueError('Invalid controller message')
        state = message.get('state')
        if state not in ('running', 'stopped'):
            raise ValueError('Invalid requested core state')
        lease = message.get('lease_seconds')
        if lease == 0 and state != 'stopped':
            raise ValueError('A zero lease must stop the core')
        self.renew_lease(lease)
        with self.lock:
            if 'policy' in message:
                self.set_policy(message['policy'])
            self.state['desired_state'] = state
            self.persist()
            if state == 'stopped':
                self.stop_core()
                self.error = str(message.get('error') or message.get('reason') or '')[:1200]
        try:
            if state == 'running':
                if message.get('config') is not None:
                    revision = message.get('revision', '')
                    try:
                        self.apply(message['config'], revision)
                    except Exception:
                        if isinstance(revision, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', revision):
                            with self.lock:
                                self.state['apply_result'] = {'revision': revision, 'ok': False,
                                                              'error': '节点配置校验或启动失败'}
                                self.persist()
                        raise
                    with self.lock:
                        self.state['apply_result'] = {'revision': revision, 'ok': True, 'error': ''}
                        self.persist()
                elif not self.running() and self.target.exists() and self.state['revision'] == message.get('revision'):
                    with self.lock:
                        self.launch()
                        self.error = ''
                elif self.state['revision'] != message.get('revision'):
                    raise ValueError('等待主控发送新的配置版本')
            commands = message.get('commands', [])
            if not isinstance(commands, list) or len(commands) > 32:
                raise ValueError('Too many management commands')
            for item in commands:
                # Downloads must not block the supervisor's lease check.
                # Individual process/state mutations take their own lock.
                self.command(item)
        except Exception as error:
            self.error = str(error)[:1200]
            log.warning('Core reconciliation failed: %s', self.error)

    def report(self):
        with self.lock:
            queued = self.spool.oldest()
            report = queued or {'report_id': uuid.uuid4().hex, 'epoch': self.epoch, 'counters': {}}
            machine = snapshot(self.directory)
            machine.update(agent_version=__version__, core_version=self.version, running=self.running(),
                           connection_count=0, online_users=0)
            connections, truncated = [], False
            if self.running():
                try:
                    connections, users, truncated = self.connections(enforce=True)
                    machine.update(connection_count=len(connections), online_users=users)
                except Exception:
                    machine.update(connection_count=None, online_users=None)
            return {'type': 'report', 'protocol': 1, **report, 'metrics': machine,
                    'applied_revision': self.state['revision'], 'error': self.error,
                    'apply_result': dict(self.state['apply_result']) or None,
                    'connections': connections, 'connections_truncated': truncated,
                    'command_acks': list(self.state['command_acks'][-100:]),
                    'command_results': list(self.state['command_results'][-100:])}

    def tick(self):
        with self.lock:
            if not self.lease_alive():
                if self.running():
                    self.stop_core()
                if self.state['desired_state'] == 'running':
                    self.error = '主控连接超过 90 秒，核心已暂停，重连后自动恢复'
                return
            if self.state['desired_state'] != 'running':
                return
            if not self.running() and self.target.exists():
                self.launch()
                self.error = ''
            self.sample()
            self.connections(enforce=True)

    def loop(self):
        while not self.stop_event.wait(2):
            try:
                self.tick()
            except Exception as error:
                self.error = str(error)[:1200]
                log.warning('Agent sampling failed: %s', self.error)

    def start(self):
        try:
            self.tick()
        except Exception as error:
            self.error = str(error)[:1200]
        self.thread = threading.Thread(target=self.loop, name='core-supervisor', daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=8)
        with self.lock:
            self.stop_core()
