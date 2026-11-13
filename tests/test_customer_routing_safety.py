"""Mandatory routing precedence and revoked-grant editing regressions."""
import copy
import ipaddress
import json
import os
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from panel import routing as r, user_routing as ur
from panel.core import connect
from test_user_routing import policy_db, draft, publish_for_test


def admin_rule(match, nodes=None, target='reject', identity='mandatory'):
    return {'id': identity, 'name': identity, 'enabled': True, 'priority': 'forced',
            'match': match, 'node_ids': nodes or [], 'target': target}


@pytest.mark.parametrize('condition', [{'ip_cidr': ['127.0.0.0/8']}, {'geoip': ['cn']}, {'ip_is_private': True}])
def test_admin_ip_resolve_stays_at_rule_position_with_exact_non_ip_scope(condition):
    settings = copy.deepcopy(r.DEFAULT)
    settings['rules'] = [
        admin_rule({'domain': ['early.example']}, target='direct', identity='domain-first'),
        admin_rule({}, ['fixed'], target='direct', identity='fixed-second'),
        admin_rule({**condition, 'domain_suffix': ['example'], 'network': 'tcp', 'port': [443],
                    'geosite': ['openai']}, ['restricted']),
    ]
    document = {'inbounds': [{'tag': 'restricted:alice'}, {'tag': 'restricted:bob'},
                              {'tag': 'fixed:alice'}, {'tag': 'unrelated:alice'}], 'outbounds': []}
    compiled = r.compile_into(document, settings)
    rules = compiled['route']['rules']
    assert [rule['action'] for rule in rules] == ['route', 'route', 'resolve', 'reject']
    assert rules[0]['domain'] == ['early.example']
    assert rules[1]['inbound'] == ['fixed:alice']
    resolver = rules[2]
    assert resolver['rules'] == [
        {'domain_suffix': ['example'], 'network': 'tcp', 'port': [443],
         'inbound': ['restricted:alice', 'restricted:bob']},
        {'rule_set': ['geosite-openai']},
    ]
    assert not any(key in json.dumps(resolver) for key in ('ip_cidr', 'geoip-', 'ip_is_private', 'unrelated'))
    assert len({entry['tag'] for entry in compiled['route']['rule_set']}) == len(compiled['route']['rule_set'])


def test_disabling_whole_document_can_retain_revoked_nodes_but_never_forge_them(policy_db):
    document = draft(node_ids=['shared'])
    publish_for_test(policy_db, 'alice', document)
    with connect(policy_db) as db:
        db.execute("DELETE FROM memberships WHERE user_id='alice' AND node_id='shared'")
    disabled = copy.deepcopy(document)
    disabled['enabled'] = False
    assert ur.validate_draft(policy_db, 'alice', disabled)['rules'][0]['node_ids'] == ['shared']
    with pytest.raises(ValueError, match='已授权的节点'):
        ur.validate_draft(policy_db, 'alice', document)
    forged = copy.deepcopy(disabled)
    forged['rules'][0]['id'] = 'new-ungranted-reference'
    with pytest.raises(ValueError, match='已授权的节点'):
        ur.validate_draft(policy_db, 'alice', forged)
    forged['rules'][0]['id'] = 'rule1'
    forged['rules'][0]['node_ids'].append('never-authorized')
    with pytest.raises(ValueError, match='已授权的节点'):
        ur.validate_draft(policy_db, 'alice', forged)
    disabled['rules'][0]['enabled'] = False
    disabled['enabled'] = True
    assert ur.validate_draft(policy_db, 'alice', disabled)['rules'][0]['enabled'] is False


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def exact(stream, count):
    result = b''
    while len(result) < count:
        chunk = stream.recv(count - len(result))
        if not chunk:
            raise ConnectionResetError('SOCKS stream closed')
        result += chunk
    return result


def fetch(port, host, target_port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=3) as stream:
            stream.sendall(b'\x05\x01\x00')
            assert exact(stream, 2) == b'\x05\x00'
            try:
                ip = ipaddress.ip_address(host)
                address = bytes([1 if ip.version == 4 else 4]) + ip.packed
            except ValueError:
                address = b'\x03' + bytes([len(host)]) + host.encode()
            stream.sendall(b'\x05\x01\x00' + address + target_port.to_bytes(2, 'big'))
            response = exact(stream, 4)
            if response[1] != 0:
                return b''
            length = 4 if response[3] == 1 else 16 if response[3] == 4 else exact(stream, 1)[0]
            exact(stream, length + 2)
            stream.sendall(('GET / HTTP/1.0\r\nHost: ' + host + '\r\n\r\n').encode())
            result = b''
            while True:
                chunk = stream.recv(4096)
                if not chunk:
                    return result
                result += chunk
    except (ConnectionResetError, BrokenPipeError):
        return b''


@pytest.mark.skipif(not os.environ.get('SING_BOX'), reason='requires real sing-box binary')
@pytest.mark.parametrize('condition', [{'ip_cidr': ['127.0.0.0/8']}, {'geoip': ['cn']}, {'ip_is_private': True}])
def test_real_core_forced_ip_reject_cannot_be_bypassed_by_personal_resolve(policy_db, condition):
    hits = []

    class Target(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.headers.get('Host'))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'local-fixture-only')

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Target)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    process = None
    logfile = None
    try:
        settings = copy.deepcopy(r.DEFAULT)
        settings['outbounds'] = [{'id': 'allowed', 'name': 'Allowed fixture', 'enabled': True,
            'public': {'visible': True, 'audience': 'all', 'allow_use': True}, 'settings': {'type': 'direct'}}]
        settings['rules'] = [
            admin_rule({'domain': ['early.test']}, target='direct', identity='earlier-domain'),
            admin_rule({}, ['compat'], target='direct', identity='earlier-fixed'),
            admin_rule(condition, ['shared']),
        ]
        r.write(policy_db, settings)
        publish_for_test(policy_db, 'alice', draft('allowed', kind='ip_cidr', values=['127.0.0.0/8']))
        ports = [free_port(), free_port(), free_port()]
        document = ur.compose({'inbounds': [
            {'type': 'socks', 'tag': tag, 'listen': '127.0.0.1', 'listen_port': port}
            for tag, port in zip(('shared:alice', 'compat:alice', 'unrelated:bob'), ports)],
            'outbounds': [{'type': 'direct', 'tag': 'direct'}]}, policy_db)
        # A local synthetic GeoIP set verifies the same compiled matcher without
        # downloading a changing country database or contacting an external site.
        if condition.get('geoip'):
            document['route']['rule_set'] = [{'type': 'inline', 'tag': 'geoip-cn',
                                              'rules': [{'ip_cidr': ['127.0.0.0/8']}]}]
        document['dns'] = {'servers': [{'type': 'hosts', 'tag': 'fixture-dns',
            'predefined': {'blocked.test': ['127.0.0.1'], 'early.test': ['127.0.0.1']}}]}
        document['route']['default_domain_resolver'] = 'fixture-dns'
        document['log'] = {'level': 'error'}
        config = policy_db.parent / 'safety-core.json'
        config.write_text(json.dumps(document))
        binary = os.environ['SING_BOX']
        check = subprocess.run([binary, 'check', '-c', str(config)], cwd=policy_db.parent,
                               capture_output=True, text=True, timeout=10)
        assert check.returncode == 0, check.stderr
        logfile = (policy_db.parent / 'safety-core.log').open('w+')
        process = subprocess.Popen([binary, 'run', '-c', str(config)], cwd=policy_db.parent,
                                   stdout=logfile, stderr=logfile)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if process.poll() is not None:
                logfile.seek(0)
                pytest.fail(logfile.read())
            try:
                with socket.create_connection(('127.0.0.1', ports[0]), timeout=.1):
                    break
            except OSError:
                time.sleep(.03)
        else:
            pytest.fail('Local test core did not listen')
        assert fetch(ports[0], 'blocked.test', server.server_port) == b''
        assert fetch(ports[0], '127.0.0.1', server.server_port) == b''
        assert hits == []
        for port, host in [(ports[0], 'early.test'), (ports[1], 'blocked.test'), (ports[2], 'blocked.test')]:
            assert b'local-fixture-only' in fetch(port, host, server.server_port)
        assert hits == ['early.test', 'blocked.test', 'blocked.test']
    finally:
        if process is not None:
            process.terminate()
            process.wait(timeout=5)
        if logfile:
            logfile.close()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
