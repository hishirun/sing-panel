"""Authenticated server management and the public, credential-bound Agent API."""
import asyncio
import collections
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import threading
import time
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import RedirectResponse
from starlette.concurrency import run_in_threadpool

from . import fleet
from .core import account, connect
from .management import audit
from .sharing import read_settings


def install(app, m):
    # This process owns the live connections. A process restart must not leave
    # stale persisted flags looking like connected Agents in the UI.
    fleet.reset_connections(m.DB)
    live = {}
    shutting_down = False
    enrollment_attempts = collections.deque(maxlen=4096)
    version_cache = {'key': None, 'value': '核心版本不可读取'}
    version_lock = threading.Lock()

    def local_core_version():
        # Status polling must not launch a process on every request. Resolve
        # symlinks and fingerprint the executable so upgrades invalidate it.
        with version_lock:
            binary = str(m.runtime.binary)
            executable = shutil.which(binary)
            try:
                resolved = Path(executable).resolve() if executable else None
                stat = resolved.stat() if resolved else None
                key = (binary, str(resolved), stat.st_dev, stat.st_ino, stat.st_size,
                       stat.st_mtime_ns, stat.st_mode) if stat else (binary, None)
            except OSError:
                key, resolved = (binary, None), None
            if key != version_cache['key']:
                version_cache.update(key=key, value='核心版本不可读取' if resolved else '核心未安装')
                if resolved:
                    try:
                        result = subprocess.run([str(resolved), 'version'], capture_output=True,
                                                text=True, timeout=3, check=True)
                        lines = result.stdout.strip().splitlines()
                        if lines:
                            version = lines[0].removeprefix('sing-box version ').strip()[:120]
                            version_cache['value'] = ''.join(c for c in version if ord(c) >= 32) or '核心版本不可读取'
                    except (OSError, subprocess.SubprocessError, UnicodeError):
                        pass
            return version_cache['value']

    def log(action, detail):
        with connect(m.DB) as db:
            audit(db, action, detail)

    def local_row():
        from .machine import snapshot
        from .server_traffic import summary
        metrics = snapshot(m.DIRECTORY)
        running = bool(m.runtime.process and m.runtime.process.poll() is None)
        metrics['running'] = running
        metrics['core_version'] = local_core_version()
        with connect(m.DB) as db:
            count = fleet._counts(db).get('local', 0)
        return {'id': 'local', 'name': '主面板本机', 'host': m.PUBLIC_HOST or '127.0.0.1',
                'is_local': True, 'enabled': True, 'online': True, 'enrolled': True,
                'enrollment_pending': False, 'enrollment_consumed': False, 'enroll_expires': 0,
                'last_seen': int(time.time()), 'metrics': metrics,
                'nodes_count': count, 'agent_version': '内置', 'core_version': metrics['core_version'],
                'desired_revision': '', 'applied_revision': '', 'desired_state': 'running',
                'error': m.runtime.error, 'traffic': summary(m.DB, 'local'), 'last_command': None,
                **fleet.local_policy(m.DB)}

    def rows_and_summary():
        rows = [local_row(), *fleet.list_servers(m.DB)]
        # A local controller and an isolated Agent may observe the same Linux
        # host. Keep both management entries, but count its physical traffic
        # only once. Without a boot ID, separate servers must stay separate.
        machines = {}
        def priority(item):
            return (bool(item.get('is_local')), bool(item['online']), item.get('last_seen') or 0)

        for row in rows:
            boot = row['metrics'].get('boot_id')
            key = ('boot', boot) if isinstance(boot, str) and boot else ('server', row['id'])
            old = machines.get(key)
            if old is None or priority(row) > priority(old):
                machines[key] = row

        def metric(row, name):
            value = row['metrics'].get(name)
            return value if fleet._number(value) else 0

        unique = list(machines.values())
        rates = {name: [row['metrics'][name] for row in unique if row['online'] and fleet._number(row['metrics'].get(name))]
                 for name in ('rx', 'tx')}
        busy = [row for row in unique if row['online'] and fleet._number(row['metrics'].get('cpu'), 100)]
        busiest = max(busy, key=lambda row: row['metrics']['cpu']) if busy else None
        summary = {'total': len(rows), 'online': sum(row['online'] for row in rows),
                   'offline': sum(not row['online'] for row in rows),
                   'rx': sum(rates['rx']) if rates['rx'] else None,
                   'tx': sum(rates['tx']) if rates['tx'] else None,
                   'rates_available': bool(rates['rx'] or rates['tx']),
                   'rx_total': sum(metric(row, 'rx_total') for row in unique),
                   'tx_total': sum(metric(row, 'tx_total') for row in unique),
                   'monthly_used': sum(row['traffic'].get('used') or 0 for row in unique),
                   'monthly_rx': sum(row['traffic'].get('rx') or 0 for row in unique),
                   'monthly_tx': sum(row['traffic'].get('tx') or 0 for row in unique),
                   'busy_name': busiest['name'] if busiest else '',
                   'busy_cpu': busiest['metrics']['cpu'] if busiest else None,
                   'nodes': sum(row['nodes_count'] for row in rows)}
        return rows, summary

    def page(request, error='', notice=''):
        rows, summary = rows_and_summary()
        return m.render(request, 'servers.html', servers=rows, summary=summary, error=error, notice=notice)

    def find(identity):
        if identity == 'local':
            return local_row()
        try:
            return fleet.get_server(m.DB, identity)
        except ValueError as error:
            raise HTTPException(404, str(error)) from None

    def editor(request, row=None, values=None, error='', status=200):
        defaults = {'name': '', 'host': '', 'monthly_quota_gib': 0,
                    'traffic_direction': 'both', 'reset_day': 1}
        if row:
            defaults.update(row)
            defaults['monthly_quota_gib'] = row.get('monthly_quota', 0) / 1024**3
        if values:
            defaults.update(values)
        response = m.render(request, 'server_editor.html', row=row, values=defaults, error=error)
        response.status_code = status
        return response

    def origin(request):
        result = (read_settings(m.DB)['public_url'] or str(request.base_url).rstrip('/')).rstrip('/')
        parsed = urlsplit(result)
        if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost', '::1')):
            raise ValueError('请先在系统设置中填写 HTTPS 公开访问地址')
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path:
            raise ValueError('主面板公开地址无效')
        return result

    async def form(request):
        m.authenticated(request)
        raw = await request.form()
        m.csrf(request, str(raw.get('token', '')))
        return raw

    def enrollment_view(request, identity, panel):
        token, expires = fleet.issue_enrollment(m.DB, identity)
        command = ('curl -fsSL ' + shlex.quote(panel + '/agent/install.sh') +
                   ' | $(if [ "$(id -u)" -ne 0 ]; then printf sudo; fi) bash -s -- --panel ' + shlex.quote(panel) + ' --token ' + shlex.quote(token))
        server = find(identity)
        log('生成 Agent 接入命令', server['name'])
        return m.render(request, 'server_enroll.html', server=server, command=command, token_expires=expires)

    @app.get('/servers')
    def index(request: Request):
        m.authenticated(request)
        return page(request, notice=request.session.pop('fleet_notice', ''))

    @app.get('/servers/status')
    def status(request: Request):
        m.authenticated(request)
        rows, summary = rows_and_summary()
        return {'servers': rows, 'summary': summary}

    @app.get('/servers/live')
    async def live_status(request: Request):
        from starlette.concurrency import run_in_threadpool
        from .diagnostics import stream
        await run_in_threadpool(m.authenticated,request)
        def produce():
            m.authenticated(request)
            rows,summary=rows_and_summary()
            return {'servers':rows,'summary':summary}
        return stream(request,produce,m)

    @app.get('/servers/new')
    def new_server(request: Request):
        m.authenticated(request)
        return editor(request)

    @app.get('/servers/{identity}/edit')
    def edit_server(request: Request, identity: str):
        m.authenticated(request)
        return editor(request, find(identity))

    @app.post('/servers/save')
    async def save(request: Request):
        raw = await form(request)
        identity = str(raw.get('id', '')) or None
        old = find(identity) if identity else None
        try:
            panel = origin(request) if not identity else None
            quota = Decimal(str(raw.get('monthly_quota_gib', (old or {}).get('monthly_quota', 0) / 1024**3)))
            if not quota.is_finite() or not 0 <= quota <= 10_000_000:
                raise ValueError('月流量额度须为 0–10,000,000 GiB')
            row = await run_in_threadpool(fleet.save_server, m.DB, raw.get('name', ''), raw.get('host', ''), identity,
                                         monthly_quota=int(quota * 1024**3),
                                         traffic_direction=str(raw.get('traffic_direction', (old or {}).get('traffic_direction', 'both'))),
                                         reset_day=raw.get('reset_day', (old or {}).get('reset_day', 1)))
            log('保存服务器', (old or row).get('name', '主面板本机'))
            if not identity:
                return enrollment_view(request, row['id'], panel)
            return RedirectResponse('/servers', 303)
        except (InvalidOperation, ValueError, TypeError) as error:
            return editor(request, old, dict(raw), str(error) or '服务器设置无效', 422)

    @app.post('/servers/{identity}/enroll')
    async def enrollment_command(request: Request, identity: str):
        await form(request)
        row = find(identity)
        if identity == 'local':
            raise HTTPException(422, '主面板本机无需安装 Agent')
        try:
            panel = origin(request)
            return enrollment_view(request, identity, panel)
        except ValueError as error:
            return page(request, error=str(error))

    @app.post('/servers/{identity}/action')
    async def action(request: Request, identity: str):
        raw = await form(request)
        row = find(identity)
        chosen = str(raw.get('action', ''))
        try:
            await run_in_threadpool(fleet.set_action, m.DB, identity, chosen)
            if chosen in ('revoke', 'delete'):
                current = live.get(identity)
                if current:
                    try:
                        await current['ws'].send_json({'type': 'desired', 'protocol': fleet.PROTOCOL,
                                                      'state': 'stopped', 'lease_seconds': 0, 'revoked': True,
                                                      'revision': '', 'commands': []})
                        await current['ws'].close(code=4403, reason='Agent authorization revoked')
                    except (RuntimeError, WebSocketDisconnect):
                        pass
            log('服务器操作 ' + chosen, row['name'])
            labels = {'restart': '重启命令已下发', 'resync': '同步命令已下发', 'start': '启动指令已保存，等待 Agent 确认',
                      'stop': '停止指令已保存，等待 Agent 确认', 'revoke': '已撤销 Agent 接入', 'delete': '服务器已删除',
                      'update_agent': 'Agent 更新命令已下发'}
            request.session['fleet_notice'] = labels.get(chosen, '操作已保存')
            return RedirectResponse('/servers', 303)
        except ValueError as error:
            return page(request, error=str(error))

    @app.post('/agent/v1/enroll')
    async def agent_enroll(request: Request):
        now = time.monotonic()
        address = request.client.host if request.client else ''
        while enrollment_attempts and now - enrollment_attempts[0][1] > 60:
            enrollment_attempts.popleft()
        if sum(ip == address for ip, stamp in enrollment_attempts) >= 30:
            raise HTTPException(429, '接入尝试过多，请稍后重试')
        enrollment_attempts.append((address, now))
        chunks = bytearray()
        async for chunk in request.stream():
            chunks.extend(chunk)
            if len(chunks) > 8192:
                raise HTTPException(413, '接入请求过大')
        try:
            raw = json.loads(chunks)
            if not isinstance(raw, dict):
                raise ValueError('接入请求格式无效')
            panel = origin(request)
            identity = await run_in_threadpool(fleet.enroll, m.DB, raw.get('token'), raw.get('credential'),
                                               expected_server_id=raw.get('expected_server_id'))
            log('Agent 已接入', fleet.get_server(m.DB, identity)['name'])
            return {'server_id': identity, 'ws_url': ('wss' if panel.startswith('https:') else 'ws') + panel[panel.index(':'):] + '/agent/v1/ws',
                    'protocol': fleet.PROTOCOL}
        except fleet.AuthenticationError as error:
            raise HTTPException(403, str(error)) from None
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            raise HTTPException(422, str(error)) from None

    def reconcile(identity, report, credential_generation, connection_generation):
        from .fleet_config import configuration
        with m.runtime.lock:
            return fleet.process_report(m.DB, identity, report, configuration, account, stats_port=19190,
                                        credential_generation=credential_generation, connection_generation=connection_generation)

    @app.websocket('/agent/v1/ws')
    async def agent_socket(websocket: WebSocket):
        identity = None
        connection_generation = None
        if shutting_down:
            await websocket.close(code=1012)
            return
        try:
            identity, credential_generation = await run_in_threadpool(fleet.authenticate, m.DB, websocket.headers.get('authorization', ''))
            connection_generation = await run_in_threadpool(fleet.open_connection, m.DB, identity, credential_generation)
        except (ValueError, fleet.AuthenticationError):
            await websocket.close(code=4403)
            return
        if shutting_down:
            await run_in_threadpool(fleet.close_connection, m.DB, identity, connection_generation)
            await websocket.close(code=1012)
            return
        await websocket.accept()
        if shutting_down:
            await run_in_threadpool(fleet.close_connection, m.DB, identity, connection_generation)
            await websocket.close(code=1012)
            return
        old = live.get(identity)
        current = {'ws': websocket, 'generation': connection_generation}
        live[identity] = current
        if old:
            try:
                await old['ws'].close(code=4403, reason='Agent connection replaced')
            except (RuntimeError, WebSocketDisconnect):
                pass
        arrivals = collections.deque()
        try:
            while True:
                payload = await asyncio.wait_for(websocket.receive_text(), timeout=45)
                if len(payload.encode()) > fleet.MAX_MESSAGE:
                    await websocket.close(code=1009, reason='Agent report too large')
                    break
                now = time.monotonic()
                while arrivals and now - arrivals[0] >= 1:
                    arrivals.popleft()
                if len(arrivals) >= 10:
                    await websocket.close(code=1008, reason='Agent report rate exceeded')
                    break
                arrivals.append(now)
                report = json.loads(payload)
                desired = await run_in_threadpool(reconcile, identity, report, credential_generation, connection_generation)
                await websocket.send_json(desired)
        except fleet.AuthenticationError:
            try:
                await websocket.send_json({'type': 'desired', 'protocol': fleet.PROTOCOL, 'state': 'stopped',
                                           'revision': '', 'lease_seconds': 0, 'revoked': True, 'commands': []})
                await websocket.close(code=4403, reason='Agent authorization revoked')
            except (RuntimeError, WebSocketDisconnect):
                pass
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            try:
                await websocket.close(code=1008, reason='Invalid Agent report')
            except (RuntimeError, WebSocketDisconnect):
                pass
        except (asyncio.TimeoutError, WebSocketDisconnect, RuntimeError):
            pass
        finally:
            if live.get(identity) is current:
                live.pop(identity, None)
            await run_in_threadpool(fleet.close_connection, m.DB, identity, connection_generation)

    # Expose bounded internal hooks to runtime shutdown and tests without ever
    # serializing authenticated websocket objects into an HTTP response.
    m.fleet_connections = live

    async def shutdown():
        nonlocal shutting_down
        shutting_down = True
        entries = list(live.items())
        live.clear()

        async def close(identity, current):
            try:
                await asyncio.wait_for(current['ws'].close(code=1012, reason='Controller restarting'), timeout=5)
            except (asyncio.TimeoutError, RuntimeError, WebSocketDisconnect):
                pass
            finally:
                await run_in_threadpool(fleet.close_connection, m.DB, identity, current['generation'])

        await asyncio.gather(*(close(identity, current) for identity, current in entries), return_exceptions=True)

    m.fleet_shutdown = shutdown
    # The legacy /{kind}/{identity}/action endpoint predates these routes and
    # accepts only users/nodes. Put this more specific route ahead of it.
    route = next(route for route in app.router.routes if getattr(route, 'path', None) == '/servers/{identity}/action')
    app.router.routes.remove(route)
    before = next((i for i, item in enumerate(app.router.routes)
                   if getattr(item, 'path', None) == '/{kind}/{identity}/action'), len(app.router.routes))
    app.router.routes.insert(before, route)
