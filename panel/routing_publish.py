"""Coalesced, durable publication of customer routing drafts.

Only this worker promotes a customer draft to the runtime configuration. The
small journal restores the previous applied documents after an interrupted
publication; browser requests never spawn a separate sing-box process.
"""
import json
from concurrent.futures import ThreadPoolExecutor
import logging
import threading
import time

from .core import connect, records, config, reason
from . import routing, user_routing, routing_rollout
from .management import audit

log = logging.getLogger(__name__)


class Publisher:
    def __init__(self, module):
        self.m = module
        self.wake = threading.Event()
        self.stopped = threading.Event()
        self.thread = None
        self.last_batch = 0.0
        self.last_request = {}
        with connect(module.DB) as db:
            routing_rollout.migrate(db)
            db.execute('CREATE TABLE IF NOT EXISTS routing_publish_journal (id INTEGER PRIMARY KEY, previous TEXT NOT NULL)')

    def documents(self, servers, overrides):
        """Validate each machine's own listeners and TLS material separately."""
        result = {}
        for server in sorted(servers):
            if server == 'local':
                nodes = [node for node in records(self.m.DB, 'nodes') if node.get('server_id', 'local') == 'local']
                owned = {node['id'] for node in nodes}
                members = [member for member in records(self.m.DB, 'memberships') if member['node_id'] in owned]
                result[server] = user_routing.compose(config(nodes, records(self.m.DB, 'users'), members, self.m.STATS_PORT),
                                                     self.m.DB, policy_overrides=overrides)
            else:
                # Desired policies are committed once. Each remote machine
                # compiles and validates independently when it reconnects.
                from .server_publish import input_signature
                with connect(self.m.DB) as db:
                    if not db.execute('SELECT 1 FROM servers WHERE id=?',(server,)).fetchone():continue
                result[server]={'_remote':server,'_inputs':input_signature(self.m.DB,server),'_overrides':overrides}
        return result

    def targets(self, candidates):
        return {uid: routing_rollout.target_servers(self.m.DB, uid,
                    user_routing.get_policy(self.m.DB, uid)['applied'], document)
                for uid, document in candidates.items()}

    def validate_documents(self, documents):
        for document in documents.values():
            if document.get('_remote'):continue
            routing.set_rule_paths(document, self.m.DIRECTORY)
            try:
                self.m.check_document(document)
            except Exception as error:
                raise ValueError('核心校验未通过，原策略保持不变，请联系管理员') from error

    def signatures(self, documents):
        for document in documents.values():
            routing.set_rule_paths(document, self.m.DIRECTORY)
        return json.dumps(documents, sort_keys=True, separators=(',', ':'))

    def local_confirmed(self, documents):
        from .server_traffic import summary
        return 'local' in documents and not summary(self.m.DB, 'local')['blocked']

    def recover(self):
        with self.m.runtime.lock, connect(self.m.DB) as db:
            row = db.execute('SELECT previous FROM routing_publish_journal WHERE id=1').fetchone()
            if row:
                for old in json.loads(row[0]):
                    db.execute('UPDATE user_routing SET applied=?,applied_revision=?,applied_at=? WHERE user_id=?',
                               (old['applied'], old['applied_revision'], old['applied_at'], old['user_id']))
                db.execute('DELETE FROM routing_publish_journal')
            db.execute("UPDATE user_routing SET status='failed',error=? WHERE status IN ('queued','applying')",
                       ('上次应用被中断，已保留原策略，请重新应用',))

    def start(self):
        self.stopped.clear()
        self.thread = threading.Thread(target=self.loop, name='routing-publisher', daemon=True)
        self.thread.start()

    def stop(self):
        self.stopped.set()
        self.wake.set()
        if self.thread:
            self.thread.join(timeout=45)

    def enqueue(self, uid, revision):
        with self.m.runtime.lock:
            with connect(self.m.DB) as db:
                if db.execute('SELECT 1 FROM routing_publish_journal').fetchone():
                    raise ValueError('上次应用仍在恢复，请联系管理员检查核心状态')
            user = self.user(uid)
            if reason(user):
                raise ValueError('当前账户不可用，无法应用分流')
            policy = user_routing.get_policy(self.m.DB, uid)
            if policy['revision'] != revision:
                raise user_routing.RevisionConflict('规则已在其他页面更新，请刷新后重试')
            if policy['status'] in ('queued', 'applying'):
                return policy
            user_routing.validate_draft(self.m.DB, uid, policy['draft'])
            now = time.monotonic()
            if now-self.last_request.get(uid, -1000) < 20:
                raise ValueError('应用过于频繁，请稍后再试')
            with connect(self.m.DB) as db:
                db.execute("UPDATE user_routing SET status='queued',error='',updated_at=? WHERE user_id=?", (int(time.time()), uid))
            self.last_request[uid] = now
        self.wake.set()
        return user_routing.get_policy(self.m.DB, uid)

    def user(self, uid):
        with connect(self.m.DB) as db:
            row = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
        if row is None:
            raise ValueError('用户不存在')
        return dict(row)

    def loop(self):
        while not self.stopped.is_set():
            self.wake.wait(1)
            if not self.wake.is_set():
                continue
            self.wake.clear()
            # Gather near-simultaneous edits and cap whole-core restarts.
            delay = max(2, 15-(time.monotonic()-self.last_batch))
            if self.stopped.wait(delay):
                break
            try:
                self.publish_pending()
            except Exception:
                log.exception('customer routing publication failed')

    def fail(self, ids, message):
        with connect(self.m.DB) as db:
            db.executemany("UPDATE user_routing SET status='failed',error=? WHERE user_id=?", [(message, uid) for uid in ids])

    def publish_pending(self):
        m = self.m
        # Snapshot queued drafts. They cannot be edited until publication ends.
        with m.runtime.lock, connect(m.DB) as db:
            if db.execute('SELECT 1 FROM routing_publish_journal').fetchone():
                db.execute("UPDATE user_routing SET status='failed',error=? WHERE status='queued'",
                           ('上次应用仍在恢复，请联系管理员检查核心状态',))
                return
            queued = [dict(row) for row in db.execute("SELECT * FROM user_routing WHERE status='queued'")]
            db.execute("UPDATE user_routing SET status='applying' WHERE status='queued'")
        if not queued:
            return
        candidates = {}
        for row in queued:
            try:
                if reason(self.user(row['user_id'])):
                    raise ValueError('当前账户不可用')
                candidates[row['user_id']] = user_routing.validate_draft(m.DB, row['user_id'], json.loads(row['draft']))
            except ValueError as error:
                self.fail([row['user_id']], str(error))
        if not candidates:
            return
        # Disjoint machines publish independently; shared machines coalesce.
        groups=[]
        for uid,document in candidates.items():
            servers=self.targets({uid:document})[uid]
            overlap=[g for g in groups if g[0]&servers]
            combined={uid:document};selected=set(servers)
            for old_servers,old_candidates in overlap:
                groups.remove((old_servers,old_candidates));selected.update(old_servers);combined.update(old_candidates)
            groups.append((selected,combined))
        with ThreadPoolExecutor(max_workers=min(4,len(groups))) as pool:
            list(pool.map(self._publish,[group[1] for group in groups]))

    def _publish(self,candidates):
        m=self.m
        previous = []
        promoted = False
        try:
            # Network downloads happen outside the core lock. Do not pause
            # accounting or administrator operations while GitHub is slow.
            targets = self.targets(candidates)
            documents = self.documents(set().union(*targets.values()), candidates)
            for document in documents.values():
                if document.get('_remote'):continue
                routing.prepare_rule_sets(document, m.DIRECTORY, m.BINARY, 30)
            self.validate_documents(documents)
            validated = self.signatures(documents)
            if self.stopped.is_set():
                raise ValueError('服务正在停止，原策略与草稿已保留')
            with m.runtime.lock:
                if self.stopped.is_set():
                    raise ValueError('服务正在停止，原策略与草稿已保留')
                # Re-read authorization, memberships and admin routing after I/O.
                for uid, document in candidates.items():
                    if reason(self.user(uid)):
                        raise ValueError('账户状态已变化，请刷新后重新应用')
                    user_routing.validate_draft(m.DB, uid, document)
                targets = self.targets(candidates)
                documents = self.documents(set().union(*targets.values()), candidates)
                if self.signatures(documents) != validated:
                    raise ValueError('节点或分流配置已变化，请刷新后重新应用')
                with connect(m.DB) as db:
                    db.execute('BEGIN IMMEDIATE')
                    if db.execute('SELECT 1 FROM routing_publish_journal').fetchone():
                        raise ValueError('上次应用仍在恢复，请稍后重试')
                    for uid, document in candidates.items():
                        row = dict(db.execute('SELECT * FROM user_routing WHERE user_id=?', (uid,)).fetchone())
                        if row['status'] != 'applying':
                            raise ValueError('应用状态已变化，请重试')
                        previous.append({k:row[k] for k in ('user_id','applied','applied_revision','applied_at')})
                        db.execute('UPDATE user_routing SET applied=?,applied_revision=revision WHERE user_id=?', (json.dumps(document), uid))
                    db.execute('INSERT OR REPLACE INTO routing_publish_journal VALUES(1,?)', (json.dumps(previous),))
                promoted = True
                self.last_batch = time.monotonic()
                local_affected = 'local' in documents
                if local_affected:
                    m.runtime.apply()
                with connect(m.DB) as db:
                    for uid in candidates:
                        db.execute("UPDATE user_routing SET error='',applied_at=? WHERE user_id=?", (int(time.time()), uid))
                        revision = db.execute('SELECT applied_revision FROM user_routing WHERE user_id=?', (uid,)).fetchone()[0]
                        routing_rollout.publish(db, uid, revision, targets[uid], local_confirmed=self.local_confirmed(documents))
                        audit(db, '用户应用分流', uid)
                    db.execute('DELETE FROM routing_publish_journal')
        except Exception as error:
            # Core diagnostics can include upstream addresses/credentials.
            safe = str(error) if isinstance(error, ValueError) else '校验或应用失败，原策略保持不变，请联系管理员'
            if promoted:
                safe = '应用失败，原策略已恢复；草稿保留，可稍后重试'
                try:
                    with m.runtime.lock:
                        with connect(m.DB) as db:
                            for old in previous:
                                db.execute('UPDATE user_routing SET applied=?,applied_revision=?,applied_at=? WHERE user_id=?', (old['applied'],old['applied_revision'],old['applied_at'],old['user_id']))
                        if 'local' in documents:
                            m.runtime.apply()
                        with connect(m.DB) as db:
                            db.execute('DELETE FROM routing_publish_journal')
                except Exception:
                    # Preserve recovery evidence until both persistence and
                    # runtime restoration succeed, including audit/commit errors.
                    safe = '应用未完成，恢复记录已保留；请联系管理员检查核心状态'
                    m.runtime.error = safe
                    log.exception('failed to restore customer routing publication')
            self.fail(candidates, safe)
            log.warning('customer routing draft was not published', exc_info=True)

    def reset_user(self, uid, authorize=None):
        with self.m.runtime.lock:
            if authorize:
                authorize()
            with connect(self.m.DB) as db:
                if db.execute('SELECT 1 FROM routing_publish_journal').fetchone():
                    raise ValueError('上次应用仍在恢复，请联系管理员检查核心状态')
            old = user_routing.get_policy(self.m.DB, uid)
            if old['status'] in ('queued','applying'):
                raise ValueError('正在应用，请稍后重试')
            document = {'enabled':True,'rules':[]}
            empty = json.dumps(document)
            targets = routing_rollout.target_servers(self.m.DB, uid, old['applied'], document)
            documents = self.documents(targets, {uid: document})
        self.validate_documents(documents)
        validated = self.signatures(documents)
        with self.m.runtime.lock:
            if authorize:
                authorize()
            if user_routing.get_policy(self.m.DB, uid) != old:
                raise ValueError('用户策略已变化，请刷新后重试')
            with connect(self.m.DB) as db:
                if db.execute('SELECT 1 FROM routing_publish_journal').fetchone():
                    raise ValueError('上次应用仍在恢复，请联系管理员检查核心状态')
            current_targets = routing_rollout.target_servers(self.m.DB, uid, old['applied'], document)
            documents = self.documents(current_targets, {uid: document})
            if current_targets != targets or self.signatures(documents) != validated:
                raise ValueError('节点或分流配置已变化，请刷新后重试')
            previous = [{key: json.dumps(old[key]) if key == 'applied' else old[key]
                         for key in ('user_id', 'applied', 'applied_revision', 'applied_at')}]
            with connect(self.m.DB) as db:
                db.execute("UPDATE user_routing SET draft=?,applied=?,revision=revision+1,applied_revision=revision+1,status='applying',error='',updated_at=?,applied_at=? WHERE user_id=?", (empty,empty,int(time.time()),int(time.time()),uid))
                db.execute('INSERT OR REPLACE INTO routing_publish_journal VALUES(1,?)', (json.dumps(previous),))
            try:
                if 'local' in documents:
                    self.m.runtime.apply()
                with connect(self.m.DB) as db:
                    routing_rollout.publish(db, uid, old['revision'] + 1, targets, local_confirmed=self.local_confirmed(documents))
                    db.execute('DELETE FROM routing_publish_journal')
            except Exception:
                try:
                    user_routing.restore_policy(self.m.DB, uid, old)
                    if 'local' in documents:
                        self.m.runtime.apply()
                    with connect(self.m.DB) as db:
                        db.execute('DELETE FROM routing_publish_journal')
                except Exception:
                    self.m.runtime.error = '恢复默认未完成，请检查核心状态'
                    raise ValueError('恢复未完成，请检查核心状态后重试') from None
                raise ValueError('恢复失败，原策略已保留') from None
        return user_routing.get_policy(self.m.DB, uid)
