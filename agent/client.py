"""Authenticated WSS reconciliation, bounded reconnects, and one-time enrollment."""
import json
import logging
import os
import random
import re
import secrets
import signal
import sys
import threading
import time
from pathlib import Path
from urllib.error import HTTPError

from websockets.exceptions import ConnectionClosed
from websockets.sync.client import connect

from .connection import origin, request
from .runtime import Core
from .storage import atomic_json, read_json
from . import update

log = logging.getLogger(__name__)


def enroll(path, panel, token, binary='/opt/sing-panel-agent/sing-box', stats_port=19190,
           allow_insecure_local=False, install_dir='/opt/sing-panel-agent'):
    panel = origin(panel, allow_insecure_local)
    path = Path(path).resolve()
    existing = read_json(path, {})
    if existing and existing.get('panel') != panel:
        raise ValueError('这台机器已经接入另一主控，拒绝覆盖现有身份')
    pending_path = path.parent / '.enrollment-pending.json'
    pending = read_json(pending_path, {})
    expected_server = existing.get('server_id')
    if pending and (pending.get('panel') != panel or
                    pending.get('expected_server_id') != expected_server and pending.get('credential') != existing.get('credential')):
        raise ValueError('发现不同服务器的未完成接入，拒绝覆盖')
    credential = pending.get('credential') or secrets.token_urlsafe(48)
    if not re.fullmatch(r'[A-Za-z0-9_-]{40,128}', credential):
        raise ValueError('Invalid existing agent credential')
    if not isinstance(token, str) or not 20 <= len(token) <= 256:
        raise ValueError('接入令牌格式无效')
    settings = dict(panel=panel, credential=credential, data_dir=str(path.parent), binary=binary,
                    stats_port=int(stats_port), control_port=int(stats_port) + 1,
                    allow_insecure_local=bool(allow_insecure_local), install_dir=install_dir)
    # Keep the generated identity before spending the one-time token. Retrying
    # after a lost response uses exactly the same credential.
    atomic_json(pending_path, {'panel': panel, 'credential': credential, 'expected_server_id': expected_server})
    payload = {'token': token, 'credential': credential}
    if expected_server:
        payload['expected_server_id'] = expected_server
    try:
        result = json.loads(request(panel, '/agent/v1/enroll', payload,
                                    maximum=65536, allow_local=allow_insecure_local))
    except HTTPError as error:
        raise ValueError(f'主控拒绝接入（HTTP {error.code}），请检查令牌是否有效') from None
    identity = result.get('server_id', '')
    if result.get('protocol') != 1 or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', identity):
        raise ValueError('主控返回了无效的 Agent 身份')
    if expected_server and identity != expected_server:
        raise ValueError('接入令牌属于另一台服务器，已保留现有身份')
    expected_ws = ('wss' if panel.startswith('https:') else 'ws') + panel[panel.index(':'):] + '/agent/v1/ws'
    if result.get('ws_url') not in (expected_ws, '/agent/v1/ws'):
        raise ValueError('主控返回的 WSS 地址不属于已确认的主控')
    settings.update(server_id=identity, ws_url=expected_ws)
    atomic_json(path, settings)
    pending_path.unlink(missing_ok=True)
    return identity


class Agent:
    def __init__(self, config_path):
        self.path = Path(config_path).resolve()
        self.config = read_json(self.path)
        if not self.config or not self.config.get('server_id'):
            raise ValueError('请先使用安装命令接入主控')
        self.config['panel'] = origin(self.config['panel'], bool(self.config.get('allow_insecure_local')))
        identity, credential = self.config['server_id'], self.config['credential']
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', identity) or not re.fullmatch(r'[A-Za-z0-9_-]{40,128}', credential):
            raise ValueError('Agent 身份配置无效')
        panel = self.config['panel']
        self.url = ('wss' if panel.startswith('https:') else 'ws') + panel[panel.index(':'):] + '/agent/v1/ws'
        self.authorization = 'Bearer ' + identity + '.' + credential
        self.core = Core(self.config)
        self.stopped = threading.Event()
        self.socket = None
        self.boot_started = time.monotonic()

    def stop(self, *_):
        self.stopped.set()
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass

    def reexec(self):
        self.core.stop()
        os.execv(sys.executable, [sys.executable, '-m', 'agent', 'run', '--config', str(self.path)])

    def exchange(self, socket):
        report = self.core.report()
        socket.send(json.dumps(report, ensure_ascii=False, separators=(',', ':')))
        response = socket.recv(timeout=30)
        if not isinstance(response, str) or len(response.encode()) > 4 * 1024 * 1024:
            raise ValueError('Invalid controller response')
        desired = json.loads(response)
        if not isinstance(desired, dict) or desired.get('type') != 'desired' or desired.get('protocol') != 1:
            raise ValueError('Unsupported controller protocol')
        # Revocation can arrive asynchronously while a report is in flight.
        # It must stop forwarding immediately without acknowledging that report.
        if desired.get('revoked') is True:
            if desired.get('state') != 'stopped' or desired.get('lease_seconds') != 0:
                raise ValueError('Invalid controller revocation')
            self.core.revoke()
            raise PermissionError('Controller authorization revoked')
        if desired.get('ack_report_id') != report['report_id']:
            raise ValueError('Controller acknowledgement does not match the report')
        self.core.spool.acknowledge(report['report_id'])
        # Confirm the release currently running, before a new update command
        # can create the next release's recovery marker.
        update.healthy(self.config)
        self.core.desired(desired)

    def run(self):
        self.core.start()
        backoff = 1
        try:
            while not self.stopped.is_set():
                if (Path(self.config['data_dir']) / 'pending-update.json').exists() and time.monotonic() - self.boot_started > 90:
                    if update.begin_boot(self.config):
                        log.warning('New agent could not reconnect; rolling back its release')
                        self.reexec()
                try:
                    with connect(self.url, additional_headers={'Authorization': self.authorization}, proxy=None,
                                 open_timeout=15, close_timeout=3, ping_interval=20, ping_timeout=20,
                                 max_size=4 * 1024 * 1024, max_queue=4, compression=None) as socket:
                        self.socket = socket
                        self.core.connected = True
                        backoff = 1
                        log.info('Connected to controller')
                        while not self.stopped.is_set():
                            self.exchange(socket)
                            if self.core.reexec_requested:
                                socket.close()
                                self.reexec()
                            # Replay outstanding epochs promptly. At most one
                            # cumulative snapshot per epoch lives in the queue.
                            if self.core.spool.count() == 0:
                                self.stopped.wait(5)
                            else:
                                # Leave headroom below the controller's ten
                                # reports/second replay limit.
                                self.stopped.wait(.15)
                except ConnectionClosed as error:
                    code = error.rcvd.code if error.rcvd else None
                    if code in (4003, 4401, 4403):
                        self.core.revoke()
                    log.warning('Controller connection closed (code %s); reconnecting', code)
                except Exception as error:
                    # Never log a URL containing credentials, HTTP headers, or
                    # the controller response body.
                    log.warning('Controller connection unavailable (%s); reconnecting', type(error).__name__)
                finally:
                    self.socket = None
                    self.core.connected = False
                if self.stopped.wait(min(backoff, 30) + random.random()):
                    break
                backoff = min(backoff * 2, 30)
        finally:
            self.core.stop()


def run(path):
    config = read_json(path)
    if config and update.begin_boot(config):
        os.execv(sys.executable, [sys.executable, '-m', 'agent', 'run', '--config', str(Path(path).resolve())])
    agent = Agent(path)
    signal.signal(signal.SIGTERM, agent.stop)
    signal.signal(signal.SIGINT, agent.stop)
    agent.run()
