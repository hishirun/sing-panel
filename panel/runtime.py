import json
import logging
import subprocess
import threading
import time
import uuid
import secrets
from urllib.request import Request, urlopen
from .management import maintain, presence
from pathlib import Path
from .core import account, current_config
from .stats import query

log = logging.getLogger(__name__)

class Runtime:
    """Own the core process and its counter epoch; serialize config changes."""
    def __init__(self, binary, directory, stats_port):
        self.binary, self.directory, self.port = binary, Path(directory), stats_port
        self.db = self.directory / 'panel.db'
        self.process = None
        self.epoch = None
        self.signature = None
        self.rejected = None
        self.error = ''
        self.control_secret=secrets.token_urlsafe(32)
        self.online={}
        self.connections=[]
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.thread = None

    def sample(self):
        if self.process and self.process.poll() is None:
            account(self.db, self.epoch, query(self.port), server_id='local')

    def launch(self, path):
        self.epoch = uuid.uuid4().hex
        with (self.directory / 'core.log').open('a') as output:
            self.process = subprocess.Popen([self.binary, 'run', '-c', str(path)],
                                            stdout=output, stderr=output)
        deadline = time.monotonic()+8
        while time.monotonic()<deadline:
            if self.process.poll() is not None:
                raise RuntimeError('sing-box 启动失败，请检查 core.log')
            try:
                query(self.port)
                return
            except Exception:
                time.sleep(.1)
        self.terminate()
        raise RuntimeError('sing-box 统计 API 未就绪；需要 with_v2ray_api 构建')

    def terminate(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    def apply(self):
        with self.lock:
            document = current_config(self.db, self.port)
            document['experimental']['clash_api']={'external_controller':f'127.0.0.1:{self.port+1}','secret':self.control_secret}
            signature = json.dumps(document, sort_keys=True)
            if self.process and self.process.poll() is None and signature == self.signature:
                from .routing_rollout import confirm_local
                confirm_local(self.db)
                return
            if self.rejected and self.rejected[0]==signature and self.process and self.process.poll() is None:
                raise RuntimeError(self.rejected[1])
            candidate = self.directory / 'candidate.json'
            candidate.write_text(json.dumps(document, indent=2))
            candidate.chmod(0o600)
            check = subprocess.run([self.binary, 'check', '-c', str(candidate)],
                                   capture_output=True, text=True, timeout=15)
            if check.returncode:
                raise RuntimeError(check.stderr[-2000:])
            target = self.directory / 'sing-box.json'
            old_signature = self.signature
            old_config = target.read_bytes() if target.exists() and old_signature else None
            if self.process and self.process.poll() is None:
                # Do not knowingly discard live counters if collection is down.
                self.sample()
                self.terminate()
            candidate.replace(target)
            try:
                self.launch(target)
            except Exception as error:
                self.rejected = (signature,str(error))
                self.terminate()
                if old_config is not None:
                    target.write_bytes(old_config)
                    self.launch(target)
                    self.signature = old_signature
                raise
            self.signature = signature
            self.rejected = None
            from .routing_rollout import confirm_local
            confirm_local(self.db)

    def control(self,path='/connections',method='GET'):
        request=Request(f'http://127.0.0.1:{self.port+1}'+path,method=method,
                        headers={'Authorization':'Bearer '+self.control_secret})
        with urlopen(request,timeout=3) as response:
            payload=response.read()
        return json.loads(payload) if payload else {}

    def track(self):
        from .fleet import presence_connections, enqueue_command
        try:
            local=self.control().get('connections',[])
        except Exception:
            local=[]
        remote=presence_connections(self.db)
        remote_by_id={item['id']:item for item in remote}
        denied=[]
        def close(identity):
            item=remote_by_id.get(identity)
            if item:
                meta=item['metadata']
                enqueue_command(self.db,item['server_id'],'disconnect_ip',
                                user_id=meta['inboundUser'].rsplit(':',1)[-1],source_ip=meta['sourceIP'])
            else:
                self.control('/connections/'+identity,'DELETE')
        self.connections=local+remote
        self.online=presence(self.db,self.connections,denied.append)
        failures=[]
        for identity in denied:
            try:close(identity)
            except Exception as error:failures.append(error)
        if failures:raise failures[0]

    def disconnect(self,identity):
        failures=[]
        try:
            local=self.control().get('connections',[])
        except Exception:
            local=[]
        for item in local:
            metadata=item.get('metadata',{})
            if metadata.get('inboundUser','').rsplit(':',1)[-1]==identity or metadata.get('inboundTag','').endswith(':'+identity):
                try:self.control('/connections/'+item['id'],'DELETE')
                except Exception:failures.append('local')
        from .fleet import enqueue_command
        from .core import connect
        with connect(self.db) as db:
            servers=[r[0] for r in db.execute("SELECT DISTINCT n.server_id FROM nodes n JOIN memberships m ON m.node_id=n.id WHERE m.user_id=? AND n.server_id<>'local'",(identity,))]
        for server in servers:
            try:enqueue_command(self.db,server,'disconnect_user',user_id=identity)
            except Exception:failures.append(server)
        if failures:raise ValueError('部分连接未能断开，其余服务器已下发断开指令，请检查运行状态后重试')

    def tick(self):
        with self.lock:
            core_error=None
            try:self.sample()
            except Exception as error:core_error=error
            maintain(self.db)
            from .machine import snapshot
            from .server_traffic import record
            record(self.db,'local',snapshot(self.directory))
            if core_error is None:
                try:self.apply()
                except Exception as error:core_error=error
            # Global presence and IP enforcement must survive a failed local
            # core; remote Agents can remain healthy and continue reporting.
            try:
                self.track()
            except Exception:
                if core_error is None:raise
                log.exception('presence reconciliation failed')
            if core_error is not None:raise core_error
            self.error = ''

    def loop(self):
        while not self.stop_event.wait(2):
            try:
                self.tick()
            except Exception as e:
                self.error = str(e)
                log.exception('core reconciliation failed')

    def start(self):
        try:
            self.apply()
        except Exception as e:
            self.error = str(e)
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=25)
        with self.lock:
            try:
                self.sample()
            except Exception:
                log.exception('final sample failed')
            finally:
                self.terminate()
