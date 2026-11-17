import copy
import json
import os
import pytest

from panel.core import connect, init_db, current_config, records, set_memberships, config
from panel import routing as r
from panel import user_routing as ur
from loopback_fixture import LoopbackFixtureRuntime, unprotected_fixture,statistics_port

@pytest.fixture
def policy_db(tmp_path):
    path = tmp_path / 'panel.db'
    init_db(path)
    with connect(path) as db:
        for index, uid in enumerate(('alice', 'bob')):
            db.execute('INSERT INTO users(id,name,secret,uuid,token,group_name) VALUES(?,?,?,?,?,?)',
                       (uid, uid.title(), uid+'-secret-123', uid+'-uuid', uid+'-token', 'premium' if index == 0 else 'basic'))
        for index, mode in enumerate(('shared', 'compat')):
            db.execute('INSERT INTO nodes(id,name,protocol,port,secret,mode) VALUES(?,?,?,?,?,?)',
                       (mode, mode, 'snell6', 25000+index, 'node-secret-123', mode))
        for uid in ('alice', 'bob'):
            set_memberships(db, uid, ['shared', 'compat'])
    data = copy.deepcopy(r.DEFAULT)
    data['outbounds'] = [
        {'id': 'exit1', 'name': 'Private internal name', 'enabled': True,
         'public': {'visible': True, 'name': 'Seattle', 'audience': 'all', 'allow_use': True},
         'settings': {'type': 'socks', 'server': 'secret.internal', 'server_port': 1080, 'username': 'private-user', 'password': 'private-password'}},
        {'id': 'exit2', 'name': 'Japan', 'enabled': True,
         'public': {'visible': True, 'audience': 'selected', 'groups': ['premium'], 'user_ids': [], 'allow_use': True},
         'settings': {'type': 'socks', 'server': 'second.internal', 'server_port': 1080}},
        {'id': 'hidden', 'name': 'Hidden', 'enabled': True, 'settings': {'type': 'socks', 'server': 'hidden.internal', 'server_port': 1080}},
    ]
    r.write(path, data)
    for uid in ('alice', 'bob'):
        ur.configure_user(path, uid, True, 20)
    return path


def draft(target='exit1', kind='domain_suffix', values=None, node_ids=None, identity='rule1'):
    return {'enabled': True, 'rules': [{'id': identity, 'name': 'Custom', 'enabled': True, 'kind': kind,
            'values': values or ['example.com'], 'target': target, 'node_ids': node_ids or []}]}


def publish_for_test(path, uid, document):
    policy = ur.save_draft(path, uid, document, ur.get_policy(path, uid)['revision'])
    with connect(path) as db:
        db.execute('UPDATE user_routing SET applied=?,applied_revision=revision,status=? WHERE user_id=?',
                   (json.dumps(policy['draft']), 'applied', uid))


def terminal_rules(document):
    return [rule for rule in unprotected_fixture(document)['route']['rules'] if rule['action'] in ('route', 'reject')]


def test_migration_draft_revision_and_runtime_separation(policy_db):
    before = current_config(policy_db)
    policy = ur.save_draft(policy_db, 'alice', draft(), 0)
    assert policy['revision'] == 1 and policy['status'] == 'draft'
    assert policy['applied'] == {'enabled': False, 'rules': []}
    assert current_config(policy_db) == before
    with pytest.raises(ur.RevisionConflict):
        ur.save_draft(policy_db, 'alice', draft(), 0)
    with connect(policy_db) as db:
        db.execute("UPDATE user_routing SET status='queued' WHERE user_id='alice'")
    with pytest.raises(ur.RevisionConflict):
        ur.save_draft(policy_db, 'alice', draft(), 1)
    init_db(policy_db)
    assert ur.get_policy(policy_db, 'alice')['revision'] == 1


def test_customer_projection_never_exposes_upstream_settings(policy_db):
    alice, bob = records(policy_db, 'users')
    choices = ur.public_outbounds(policy_db, alice)
    assert [row['id'] for row in choices] == ['exit1', 'exit2']
    assert choices[0]['name'] == 'Seattle'
    serialized = json.dumps(choices)
    for value in ('secret.internal', 'private-password', 'private-user', 'server_port', 'Private internal name', 'fingerprint'):
        assert value not in serialized
    assert [row['id'] for row in ur.public_outbounds(policy_db, bob)] == ['exit1']
    settings = r.load(policy_db)
    settings['outbounds'][0]['public']['allow_use'] = False
    choices = ur.public_outbounds(policy_db, alice, settings)
    assert not choices[0]['selectable'] and choices[0]['enabled']


@pytest.mark.parametrize('target', ['hidden', 'direct', 'bogus', 'exit2'])
def test_user_cannot_choose_unauthorized_exit(policy_db, target):
    with pytest.raises(ValueError, match='出口'):
        ur.save_draft(policy_db, 'bob', draft(target), 0)


def test_draft_strict_validation(policy_db):
    for change in ({'kind': 'auth_user'}, {'values': []}, {'values': ['https://example.com']},
                   {'node_ids': ['ungranted']}, {'enabled': 'true'}, {'name': 'bad\nname'}):
        doc = draft()
        doc['rules'][0].update(change)
        with pytest.raises(ValueError):
            ur.validate_draft(policy_db, 'alice', doc)
    normalized = ur.validate_draft(policy_db, 'alice', draft(kind='ip_cidr', values=['1.1.1.9/24', '1.1.1.0/24']))
    assert normalized['rules'][0]['values'] == ['1.1.1.0/24']
    normalized = ur.validate_draft(policy_db, 'alice', draft(kind='geosite', values=['openai', 'netflix']))
    assert normalized['rules'][0]['values'] == ['openai', 'netflix']
    doc = draft();doc['rules'].append(copy.deepcopy(doc['rules'][0]))
    with pytest.raises(ValueError, match='重复'):
        ur.validate_draft(policy_db, 'alice', doc)


def test_permissions_and_restore_without_password(policy_db):
    with connect(policy_db) as db:
        db.execute("UPDATE user_routing SET password_hash='legacy-unused-hash',auth_revision=7 WHERE user_id='alice'")
    old = ur.get_policy(policy_db, 'alice')
    changed = ur.configure_user(policy_db, 'alice', False, old['max_rules'])
    assert changed['auth_revision'] == old['auth_revision']
    assert changed['password_hash'] == old['password_hash']
    with pytest.raises(ValueError, match='尚未开启'):
        ur.save_draft(policy_db, 'alice', draft(), 0)
    ur.restore_policy(policy_db, 'alice', old)
    assert ur.get_policy(policy_db, 'alice') == old
    for invalid in (0, 51, True):
        with pytest.raises(ValueError):ur.configure_user(policy_db, 'alice', True, invalid)
    with connect(policy_db) as db:
        db.execute("INSERT INTO users(id,name,secret,uuid,token) VALUES('new','New','new','new','new')")
    new = ur.get_policy(policy_db, 'new')
    assert not new['exists'] and new['max_rules'] == 6
    configured = ur.configure_user(policy_db, 'new', True)
    assert configured['allowed'] and configured['max_rules'] == 6 and not configured['password_hash']
    ur.restore_policy(policy_db, 'new', new)
    assert not ur.get_policy(policy_db, 'new')['exists']


def test_default_six_rule_limit_is_enforced(policy_db):
    ur.configure_user(policy_db, 'alice', True)
    document = {'enabled':True,'rules':[draft(identity='rule'+str(i))['rules'][0] for i in range(6)]}
    saved = ur.save_draft(policy_db, 'alice', document, 0)
    assert saved['max_rules'] == 6 and len(saved['draft']['rules']) == 6
    document['rules'].append(draft(identity='rule6')['rules'][0])
    with pytest.raises(ValueError, match='6 条'):
        ur.save_draft(policy_db, 'alice', document, 1)
    assert ur.get_policy(policy_db, 'alice')['revision'] == 1


def test_legacy_schema_default_does_not_override_new_default_or_existing_limits(tmp_path):
    path = tmp_path/'panel.db'
    init_db(path)
    with connect(path) as db:
        schema = db.execute("SELECT sql FROM sqlite_master WHERE name='user_routing'").fetchone()[0]
        db.execute('DROP TABLE user_routing')
        db.execute(schema.replace('DEFAULT 6','DEFAULT 20'))
        for uid in ('old','new'):
            db.execute('INSERT INTO users(id,name,secret,uuid,token) VALUES(?,?,?,?,?)',(uid,uid,uid,uid,uid))
        db.execute("INSERT INTO user_routing(user_id,max_rules,password_hash,auth_revision) VALUES('old',20,'legacy-hash',9)")
    init_db(path)
    old = ur.get_policy(path, 'old')
    assert old['max_rules'] == 20 and old['password_hash'] == 'legacy-hash' and old['auth_revision'] == 9
    new = ur.configure_user(path, 'new', True)
    assert new['max_rules'] == 6 and new['allowed']
    assert ur.get_policy(path, 'old') == old


def test_shared_and_compat_identity_scopes_never_affect_other_user(policy_db):
    publish_for_test(policy_db, 'alice', draft('exit1'))
    publish_for_test(policy_db, 'bob', draft('exit1', values=['other.example']))
    document = current_config(policy_db)
    personal = terminal_rules(document)
    assert len(personal) == 2
    assert personal[0]['rules'][0] == {'type': 'logical', 'mode': 'or', 'rules': [
        {'auth_user': ['shared:alice']}, {'inbound': ['compat:alice']}]}
    assert personal[1]['rules'][0] == {'type': 'logical', 'mode': 'or', 'rules': [
        {'auth_user': ['shared:bob']}, {'inbound': ['compat:bob']}]}
    assert len([rule for rule in document['route']['rules'] if rule['action'] == 'sniff']) == 2
    assert 'bob' not in json.dumps(personal[0])
    assert 'alice' not in json.dumps(personal[1])


@pytest.mark.parametrize('kind', ['snell', 'vless', 'hysteria2', 'anytls'])
def test_all_shared_protocols_use_auth_user_not_node_alone(policy_db, kind):
    publish_for_test(policy_db, 'alice', draft(kind='ip_cidr', values=['1.1.1.1']))
    document = {'inbounds': [{'tag': 'shared', 'type': kind, 'users': [{'name': 'shared:alice'}, {'name': 'shared:bob'}]}], 'outbounds': []}
    compiled = ur.compose(document, policy_db)
    assert terminal_rules(compiled)[0]['rules'][0] == {'auth_user': ['shared:alice']}


def test_scopes_disappear_without_becoming_global(policy_db):
    publish_for_test(policy_db, 'alice', draft(node_ids=['shared']))
    with connect(policy_db) as db:
        db.execute("DELETE FROM memberships WHERE user_id='alice' AND node_id='shared'")
    assert terminal_rules(current_config(policy_db)) == []
    assert ur.identity_scope({'inbounds': [{'tag': 'shared', 'users': [{'name': 'shared:bob'}]}]}, 'alice') is None


def test_legacy_forced_rules_and_explicit_default_priority(policy_db):
    settings = r.load(policy_db)
    settings['rules'] = [
        {'id': 'normal', 'name': 'AI', 'enabled': True, 'match': {'domain_suffix': ['example.com']}, 'node_ids': [], 'target': 'exit2', 'priority': 'default'},
        {'id': 'legacy', 'name': 'Seattle fixed', 'enabled': True, 'match': {}, 'node_ids': ['compat'], 'target': 'exit1'},
    ]
    r.write(policy_db, settings)
    publish_for_test(policy_db, 'alice', draft('exit2'))
    rules = terminal_rules(current_config(policy_db))
    assert rules[0]['inbound'] == ['compat:alice', 'compat:bob']
    assert rules[1]['rules'][0]['rules'][0] == {'auth_user': ['shared:alice']}
    assert rules[2]['domain_suffix'] == ['example.com']


def test_revoked_exit_fails_closed_and_retained_disabled_rule_can_save(policy_db):
    publish_for_test(policy_db, 'alice', draft('exit2'))
    assert ur.applied_references(policy_db, 'exit2') == [{'id': 'alice', 'name': 'Alice'}]
    settings = r.load(policy_db)
    settings['outbounds'][1]['public']['groups'] = []
    r.write(policy_db, settings)
    rules = terminal_rules(current_config(policy_db))
    assert rules[0]['action'] == 'reject' and 'outbound' not in rules[0]
    with pytest.raises(ValueError, match='未授权'):
        ur.validate_draft(policy_db, 'alice', draft('exit2'))
    doc = draft('exit2');doc['rules'][0]['enabled'] = False
    ur.save_draft(policy_db, 'alice', doc, 1)
    doc['rules'][0]['id'] = 'new-invalid-rule'
    with pytest.raises(ValueError):ur.validate_draft(policy_db, 'alice', doc)


def test_rule_set_deduplication_and_candidate_never_persists(policy_db):
    doc = draft(kind='geosite', values=['openai'])
    publish_for_test(policy_db, 'alice', doc)
    publish_for_test(policy_db, 'bob', doc)
    document = current_config(policy_db)
    assert len(document['route']['rule_set']) == 1
    assert document['route']['rule_set'][0]['tag'] == 'geosite-openai'
    before = ur.get_policy(policy_db, 'alice')
    candidate = ur.compose(config(records(policy_db, 'nodes'), records(policy_db, 'users'), records(policy_db, 'memberships')),
                           policy_db, policy_overrides={'alice': {'enabled': False, 'rules': []}})
    assert len(terminal_rules(candidate)) == 1
    assert ur.get_policy(policy_db, 'alice') == before


def test_account_inactive_read_only_and_no_personal_routes(policy_db):
    publish_for_test(policy_db, 'alice', draft())
    with connect(policy_db) as db:db.execute("UPDATE users SET quota=1,download=1 WHERE id='alice'")
    assert terminal_rules(current_config(policy_db)) == []
    with pytest.raises(ValueError, match='只读'):
        ur.save_draft(policy_db, 'alice', draft(), 1)


@pytest.mark.skipif(not os.environ.get('SING_BOX'), reason='SING_BOX required')
@pytest.mark.parametrize('protocol,mode', [
    ('snell5', 'shared'), ('snell5', 'compat'), ('snell6', 'shared'), ('snell6', 'compat'),
    ('hysteria2', 'shared'), ('anytls', 'shared'), ('reality', 'shared'), ('tuic','shared'), ('shadowtls','compat'),
])
def test_real_two_users_choose_different_exits_tcp_and_udp(tmp_path, protocol, mode):
    """Identical destinations reach different local SS exits per authenticated user."""
    import re
    import socket
    import subprocess
    import threading
    import time
    import uuid
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from panel.subscriptions import outbounds
    from traffic_audit import socks, receive
    from test_integration import port
    binary = os.environ['SING_BOX']
    targets, packets, threads, processes, logs = [], [], [], [], []
    stop = threading.Event()
    rt = None
    try:
        for marker in (b'alice-exit', b'bob-exit'):
            class Target(BaseHTTPRequestHandler):
                body = marker
                def do_GET(self):
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(self.body)))
                    self.end_headers()
                    self.wfile.write(self.body)
                def log_message(self, *args):pass
            http = ThreadingHTTPServer(('127.0.0.1', 0), Target)
            targets.append(http)
            worker = threading.Thread(target=http.serve_forever, daemon=True);worker.start();threads.append(worker)
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(('127.0.0.1', http.server_port));udp.settimeout(.2);packets.append(udp)
            def echo(packet=udp, reply=marker):
                while not stop.is_set():
                    try:
                        payload, peer = packet.recvfrom(4096)
                        packet.sendto(reply+b':'+payload, peer)
                    except socket.timeout:continue
                    except OSError:break
            worker = threading.Thread(target=echo, daemon=True);worker.start();threads.append(worker)
        upstream_ports = [port(), port()]
        upstream = {
            'log': {'level': 'error'},
            'inbounds': [{'type': 'shadowsocks', 'tag': 'up'+str(i), 'listen': '127.0.0.1',
                          'listen_port': upstream_ports[i], 'method': 'aes-128-gcm', 'password': 'upstream-test-secret-'+str(i)} for i in range(2)],
            'outbounds': [{'type': 'direct', 'tag': 'direct'}],
            'route': {'rules': [{'inbound': ['up'+str(i)], 'action': 'route', 'outbound': 'direct',
                                 'override_address': '127.0.0.1', 'override_port': targets[i].server_port} for i in range(2)]},
        }
        def start(document, name):
            filename = tmp_path/(name+'.json');filename.write_text(json.dumps(document))
            log = (tmp_path/(name+'.log')).open('w');logs.append(log)
            proc = subprocess.Popen([binary, 'run', '-c', str(filename)], stdout=log, stderr=log);processes.append(proc)
            return proc
        start(upstream, 'upstream')
        cert, key = tmp_path/'cert.pem', tmp_path/'key.pem'
        options = {'listen': '127.0.0.1'}
        private, public, sni = '', '', 'localhost'
        if protocol in ('hysteria2', 'anytls','tuic','shadowtls'):
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                            '-keyout', str(key), '-out', str(cert)], capture_output=True, check=True)
            options.update(certificate_path=str(cert), key_path=str(key))
        if protocol=='shadowtls':
            import ssl
            class Handshake(BaseHTTPRequestHandler):
                def do_GET(self):self.send_response(200);self.end_headers()
                def log_message(self,*args):pass
                def handle(self):
                    try:super().handle()
                    except (OSError,ValueError):pass
            handshake=ThreadingHTTPServer(('127.0.0.1',0),Handshake);targets.append(handshake)
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_3;ctx.load_cert_chain(cert,key)
            handshake.socket=ctx.wrap_socket(handshake.socket,server_side=True)
            worker=threading.Thread(target=handshake.serve_forever,daemon=True);worker.start();threads.append(worker)
            options.update(handshake_host='127.0.0.1',handshake_port=handshake.server_port,ss_method='2022-blake3-aes-128-gcm')
        if protocol == 'reality':
            keys = subprocess.check_output([binary, 'generate', 'reality-keypair'], text=True)
            private = re.search(r'PrivateKey:\s*(\S+)', keys)[1]
            public = re.search(r'PublicKey:\s*(\S+)', keys)[1]
            sni = 'www.cloudflare.com'
        path = tmp_path/'panel.db';init_db(path)
        with connect(path) as db:
            db.execute('INSERT INTO nodes(id,name,protocol,port,secret,mode,options,private_key,public_key,short_id,server_name) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                       ('node', 'Node', protocol, port(), 'node-secret-123456789', mode, json.dumps(options), private, public, 'abcdef12', sni))
            for uid in ('alice', 'bob'):
                db.execute('INSERT INTO users(id,name,secret,uuid,token) VALUES(?,?,?,?,?)',
                           (uid, uid, uid+'-secret-123456789', str(uuid.uuid4()), uid+'-token'))
                set_memberships(db, uid, ['node'])
        settings = copy.deepcopy(r.DEFAULT)
        settings['outbounds'] = [{'id': 'exit'+str(i), 'name': 'Exit'+str(i), 'enabled': True,
            'public': {'visible': True, 'audience': 'all'}, 'settings': {'type': 'shadowsocks', 'server': '127.0.0.1',
            'server_port': upstream_ports[i], 'method': 'aes-128-gcm', 'password': 'upstream-test-secret-'+str(i)}} for i in range(2)]
        settings['final'] = 'exit1'
        r.write(path, settings)
        for i, uid in enumerate(('alice', 'bob')):
            ur.configure_user(path, uid, True)
            publish_for_test(path, uid, draft('exit'+str(i), kind='ip_cidr', values=['127.0.0.1/32']))
        rt = LoopbackFixtureRuntime(binary, tmp_path, statistics_port(path));rt.apply()
        clients = []
        for user in records(path, 'users'):
            outs = outbounds(user, records(path, 'nodes'), records(path, 'memberships'), '127.0.0.1')
            if protocol in ('hysteria2', 'anytls','tuic'):
                outs[0]['tls']['certificate_path'] = str(cert)
            if protocol=='shadowtls':outs[0]['_shadowtls']['tls']['certificate_path']=str(cert)
            from panel.protocols import expand_singbox_nodes
            outs=expand_singbox_nodes(outs)
            local = port();clients.append(local)
            start({'log': {'level': 'error'}, 'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': local}],
                   'outbounds': outs}, user['id']+'-client')
            deadline = time.monotonic()+5
            while time.monotonic() < deadline:
                try:
                    with socket.create_connection(('127.0.0.1', local), timeout=.1):break
                except OSError:time.sleep(.03)
        for index, local in enumerate(clients):
            expected = (b'alice-exit', b'bob-exit')[index]
            with socket.create_connection(('127.0.0.1', local), timeout=10) as stream:
                stream.settimeout(15);socks(stream, 1, 9)
                stream.sendall(b'GET / HTTP/1.1\r\nHost: local-test\r\nConnection: close\r\n\r\n')
                response = b''
                while chunk := stream.recv(4096):response += chunk
                assert response.endswith(expected), (protocol, mode, response)
            # Same IP rule must also work when the protocol carries a domain.
            # Alice's selected exit differs from the platform's default exit.
            with socket.create_connection(('127.0.0.1', local), timeout=10) as stream:
                stream.settimeout(15)
                stream.sendall(b'\x05\x01\x00');assert receive(stream, 2) == b'\x05\x00'
                host = b'localhost'
                stream.sendall(bytes([5, 1, 0, 3, len(host)])+host+(9).to_bytes(2, 'big'))
                header = receive(stream, 4);assert header[1] == 0
                if header[3] == 4:receive(stream, 18)
                elif header[3] == 1:receive(stream, 6)
                else:receive(stream, receive(stream, 1)[0]+2)
                stream.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                response = b''
                while chunk := stream.recv(4096):response += chunk
                assert response.endswith(expected), (protocol, mode, response)
            if protocol=='shadowtls':continue  # TCP-only wrapper
            with socket.create_connection(('127.0.0.1', local), timeout=10) as control:
                control.settimeout(15);_, relay = socks(control, 3)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as packet:
                    packet.settimeout(15)
                    packet.sendto(b'\0\0\0\1\x7f\0\0\1'+(9).to_bytes(2, 'big')+b'probe', ('127.0.0.1', relay))
                    result = packet.recv(4096)
                    header = 22 if result[3] == 4 else 10 if result[3] == 1 else 7+result[4]
                    assert result[header:] == expected+b':probe'
        rt.sample()
        users = records(path, 'users')
        assert all(user['upload'] > 0 and user['download'] > 0 for user in users)
    finally:
        stop.set()
        for process in reversed(processes):
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        if rt:rt.stop()
        for packet in packets:packet.close()
        for server in targets:server.shutdown();server.server_close()
        for worker in threads:worker.join(timeout=1)
        for log in logs:log.close()


def test_whole_policy_rule_set_and_value_budget(policy_db):
    values = r.GEO_CATALOG['geoip'][:33]
    doc = draft(kind='geoip', values=values)
    with pytest.raises(ValueError, match='32 个不同'):
        ur.validate_draft(policy_db, 'alice', doc)
    doc['rules'][0]['values'] = values[:32]
    duplicate = copy.deepcopy(doc['rules'][0]);duplicate['id'] = 'another'
    doc['rules'].append(duplicate)
    assert len(ur.validate_draft(policy_db, 'alice', doc)['rules']) == 2
    doc = {'enabled': True, 'rules': [draft(kind='domain_suffix', values=[f'host{index}-{n}.example' for n in range(100)], identity='rule'+str(index))['rules'][0] for index in range(3)]}
    with pytest.raises(ValueError, match='256 个匹配'):
        ur.validate_draft(policy_db, 'alice', doc)


def test_system_resolve_is_unique_and_business_rule_scopes_keep_their_order(policy_db):
    settings = r.load(policy_db)
    settings['rules'] = [{'id': 'fixed', 'name': 'Fixed', 'enabled': True, 'match': {}, 'node_ids': ['compat'], 'target': 'exit1'}]
    r.write(policy_db, settings)
    doc = draft('exit1')
    doc['rules'].append(draft('exit2', kind='geoip', values=['us'], identity='geo')['rules'][0])
    publish_for_test(policy_db, 'alice', doc)
    document = current_config(policy_db)
    assert sum(rule['action'] == 'resolve' for rule in document['route']['rules']) == 1
    rules = unprotected_fixture(document)['route']['rules']
    assert [rule['action'] for rule in rules] == ['sniff', 'route', 'route', 'route']
    assert rules[1]['inbound'] == ['compat:alice', 'compat:bob']
    assert 'bob' not in json.dumps(rules[3])
    assert rules[3]['rules'][0]['rules'] == [{'auth_user': ['shared:alice']}, {'inbound': ['compat:alice']}]
