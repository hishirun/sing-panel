"""Per-machine coalescing and validation outside the shared accounting lock."""
import copy
import hashlib
import json
import sqlite3
import tempfile
import threading
import time
from pathlib import Path
from .core import connect,reason

class Pending(ValueError):pass

def migrate(db):
    db.executescript('''CREATE TABLE IF NOT EXISTS server_publications (
        server_id TEXT PRIMARY KEY,status TEXT NOT NULL,revision TEXT NOT NULL DEFAULT '',message TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS user_accounting_windows (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,since INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS server_report_sequences (server_id TEXT NOT NULL,epoch TEXT NOT NULL,sequence INTEGER NOT NULL,observed_at INTEGER NOT NULL,fingerprint TEXT NOT NULL,PRIMARY KEY(server_id,epoch));''')

def input_signature(path,sid):
    # Exclude telemetry/counters except changes in actual account availability.
    with connect(path) as db:
        db.execute('BEGIN')
        nodes=[dict(r) for r in db.execute('SELECT * FROM nodes WHERE server_id=? ORDER BY id',(sid,))]
        members=[dict(r) for r in db.execute('SELECT m.* FROM memberships m JOIN nodes n ON m.node_id=n.id WHERE n.server_id=? ORDER BY m.user_id,m.node_id',(sid,))]
        users=[]
        owned_users={r['user_id'] for r in members}
        for r in db.execute('SELECT * FROM users ORDER BY id'):
            row=dict(r)
            if row['id'] not in owned_users:continue
            users.append({k:row[k] for k in ('id','secret','uuid','group_name')}|{'inactive':reason(row)})
        policies=[tuple(r) for r in db.execute('SELECT user_id,allowed,applied,applied_revision FROM user_routing ORDER BY user_id') if r['user_id'] in owned_users]
        routing=db.execute("SELECT value FROM settings WHERE key='server_routing'").fetchone()
        server=db.execute('SELECT enabled,desired_state FROM servers WHERE id=?',(sid,)).fetchone()
    certificates=[]
    for node in nodes:
        options=json.loads(node['options'])
        for key in ('certificate_path','key_path'):
            if options.get(key):
                try:
                    stat=Path(options[key]).stat();certificates.append((options[key],stat.st_mtime_ns,stat.st_ctime_ns,stat.st_size))
                except OSError:certificates.append((options[key],'unavailable'))
    payload=[nodes,members,users,policies,list(routing) if routing else [],list(server) if server else [],certificates]
    return hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def status(path,sid):
    with connect(path) as db:
        row=db.execute('SELECT status,revision,message,updated_at FROM server_publications WHERE server_id=?',(sid,)).fetchone()
        server=db.execute('SELECT applied_revision,metrics FROM servers WHERE id=?',(sid,)).fetchone()
    result=dict(row) if row else {'status':'waiting','revision':'','message':'等待机器接入','updated_at':0}
    if row and server and result['status']=='ready' and result['revision']==server['applied_revision'] and json.loads(server['metrics']).get('running'):
        result.update(status='applied',message='此机器已确认配置')
    return result

class Coordinator:
    def __init__(self,m):
        self.m=m;self.guard=threading.Lock();self.locks={};self.cache={};self.failures={}

    def mark(self,sid,state,message='',revision=''):
        with connect(self.m.DB) as db:
            db.execute('INSERT OR REPLACE INTO server_publications VALUES(?,?,?,?,?)',(sid,state,revision,message,int(time.time())))

    def reconcile(self,sid,report,credential_generation,connection_generation):
        from . import fleet
        from .core import account
        from .fleet_config import configuration
        from .routing import prepare_rule_sets,set_rule_paths
        with self.guard:lock=self.locks.setdefault(sid,threading.Lock())
        # Only another request for this server can wait on this lock.
        with lock:
            def cached(*args):
                signature=input_signature(self.m.DB,sid)
                cached=self.cache.get(sid)
                if not cached or cached[0]!=signature:raise Pending('配置准备中')
                return copy.deepcopy(cached[1])
            def exchange():
                return fleet.process_report(self.m.DB,sid,report,cached,account,stats_port=19190,
                    credential_generation=credential_generation,connection_generation=connection_generation)
            with self.m.runtime.lock:
                # Accounts first: exhausting a quota invalidates the cached document.
                result=exchange()
                signature=input_signature(self.m.DB,sid)
                if self.cache.get(sid,(None,))[0]==signature:return result
                with connect(self.m.DB) as db:
                    retries=tuple(r[0] for r in db.execute("SELECT id FROM server_commands WHERE server_id=? AND action='resync' ORDER BY id",(sid,)))
                failed=self.failures.get(sid)
                if failed and failed[0]==signature and failed[2]==retries and time.monotonic()-failed[1]<30:return result
                self.mark(sid,'preparing','正在校验本机配置')
                folder=tempfile.mkdtemp(prefix='publish-',dir=self.m.DIRECTORY)
                snapshot=Path(folder)/'panel.db'
                with connect(self.m.DB) as source,sqlite3.connect(snapshot) as target:source.backup(target)
                snapshot.chmod(0o600)
            try:
                document=configuration(snapshot,sid,19190)
                prepare_rule_sets(document,self.m.DIRECTORY,self.m.BINARY,15)
                self.m.check_document(document)
                # Remote paths are relative to the agent's own data directory.
                if document.get('experimental',{}).get('cache_file'):document['experimental']['cache_file']['path']='routing-cache.db'
                for entry in document.get('route',{}).get('rule_set',[]):entry.pop('initial_path',None)
                with self.m.runtime.lock:
                    if input_signature(self.m.DB,sid)!=signature:
                        self.mark(sid,'queued','配置已变化，等待合并后重新发布')
                        return result
                    self.failures.pop(sid,None)
                    self.cache[sid]=(signature,copy.deepcopy(document))
                    digest=hashlib.sha256(json.dumps(document,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                    self.mark(sid,'ready','已校验，等待机器确认',digest)
                    return exchange()
            except fleet.AuthenticationError:raise
            except Exception:
                self.failures[sid]=(signature,time.monotonic(),retries)
                self.mark(sid,'failed','此机器配置校验失败，请检查节点、证书或规则集')
                return result
            finally:
                import shutil
                shutil.rmtree(snapshot.parent,ignore_errors=True)
