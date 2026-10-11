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
            account(self.db, self.epoch, query(self.port))

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

    def control(self,path='/connections',method='GET'):
        request=Request(f'http://127.0.0.1:{self.port+1}'+path,method=method,
                        headers={'Authorization':'Bearer '+self.control_secret})
        with urlopen(request,timeout=3) as response:
            payload=response.read()
        return json.loads(payload) if payload else {}

    def track(self):
        self.connections=self.control().get('connections',[])
        self.online=presence(self.db,self.connections,lambda identity:self.control('/connections/'+identity,'DELETE'))

    def disconnect(self,identity):
        for item in self.control().get('connections',[]):
            metadata=item.get('metadata',{})
            if metadata.get('inboundUser')==identity or metadata.get('inboundTag','').endswith(':'+identity):
                self.control('/connections/'+item['id'],'DELETE')

    def tick(self):
        with self.lock:
            self.sample()
            maintain(self.db)
            self.apply()
            self.track()
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
