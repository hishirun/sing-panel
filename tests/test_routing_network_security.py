"""Proxy users cannot reach the unauthenticated loopback statistics service."""
import copy
import json
import os
import socket
import struct
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import urlopen

import grpc
import pytest

from panel.core import connect, current_config, init_db, records
from panel import routing
from panel.fleet import save_server
from panel.fleet_config import configuration
from panel.routing_security import blocked_destination, protect, protection_rules
from panel.stats import Query, Response, query
from panel.subscriptions import outbounds


@pytest.mark.parametrize('address', [
    '0.0.0.0', '127.0.0.1', '127.16.2.3', '169.254.169.254', '10.4.3.2',
    '172.31.1.2', '192.168.1.1', '100.100.100.200', '::', '::1',
    'fc00::1', 'fe80::1', '::ffff:127.0.0.1', '::ffff:169.254.169.254',
    'localhost', 'api.localhost',
])
def test_internal_addresses_are_never_customer_destinations(address):
    assert blocked_destination(address) is True


def test_public_destinations_remain_available_and_domains_need_dns_facts():
    for address in ('1.1.1.1', '8.8.8.8', '2606:4700:4700::1111', '::ffff:8.8.8.8'):
        assert blocked_destination(address) is False
    assert blocked_destination('example.com') is None
    assert blocked_destination('example.com', 18889) is True


def test_protection_precedes_business_rules_pins_resolution_and_preserves_upstream():
    document = {'experimental': {'v2ray_api': {'listen': '127.0.0.1:29190'},
                                'clash_api': {'external_controller': '[::1]:30123'}},
                'outbounds': [{'type': 'socks', 'tag': 'private-upstream',
                               'server': '10.0.0.2', 'server_port': 1080, 'password': 'fixture-secret'}],
                'route': {'rules': [{'action': 'resolve'},
                                    {'domain_suffix': ['example.com'], 'action': 'route', 'outbound': 'private-upstream'},
                                    {'action': 'resolve', 'strategy': 'ipv4_only'},
                                    {'action': 'route', 'outbound': 'direct'}]}}
    original_outbounds = copy.deepcopy(document['outbounds'])
    protect(document)
    prefix = protection_rules(document)
    assert document['route']['rules'][:len(prefix)] == prefix
    assert prefix[0]['port'] == [18889, 29190, 29191, 30123]
    assert document['outbounds'] == original_outbounds
    assert sum(row['action'] == 'resolve' for row in document['route']['rules']) == 1
    assert document['route']['rules'][4]['domain_suffix'] == ['example.com']
    original = copy.deepcopy(document)
    assert protect(document) == original


def test_local_and_remote_configurations_always_have_system_protection(tmp_path):
    path = tmp_path / 'panel.db'
    init_db(path)
    server = save_server(path, 'Fixture', '203.0.113.1')
    for document in (current_config(path, 29090), configuration(path, server['id'], 29190)):
        prefix = protection_rules(document)
        assert document['route']['rules'][:len(prefix)] == prefix


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def stats_call(port, reset=False):
    with grpc.insecure_channel('127.0.0.1:' + str(port), options=[('grpc.enable_retries', 0)]) as channel:
        call = channel.unary_unary('/v2ray.core.app.stats.command.StatsService/QueryStats',
                                  request_serializer=Query.SerializeToString,
                                  response_deserializer=Response.FromString)
        return {stat.name: stat.value for stat in call(Query(reset=reset), timeout=1).stat}


@pytest.fixture
def certificate(tmp_path):
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                    '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
    return cert, key


@pytest.mark.skipif(not os.environ.get('SING_BOX'), reason='requires real sing-box binary')
@pytest.mark.parametrize('protocol,mode', [('snell6', 'compat'), ('snell6', 'shared'), ('hysteria2', 'shared')])
def test_real_customer_cannot_read_reset_or_dial_internal_services(tmp_path, certificate, protocol, mode):
    hits = []

    class Target(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'fixture-only-public-result' * 1024)

        def log_message(self, *args):
            pass

    target = ThreadingHTTPServer(('127.0.0.1', 0), Target)
    thread = threading.Thread(target=target.serve_forever, daemon=True)
    thread.start()
    packet_target = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packet_target.bind(('127.0.0.1', 0))
    packet_target.settimeout(10)
    packet_hits = []

    def echo():
        try:
            payload, peer = packet_target.recvfrom(4096)
            packet_hits.append(payload)
            packet_target.sendto(b'public-udp-response', peer)
        except OSError:
            pass

    packet_thread = threading.Thread(target=echo, daemon=True)
    packet_thread.start()
    dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_socket.bind(('127.0.0.1', 0))
    dns_socket.settimeout(.1)
    dns_stopped = threading.Event()
    rebind_answers = []

    def dns_responses():
        while not dns_stopped.is_set():
            try:
                packet, peer = dns_socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            offset, labels = 12, []
            while packet[offset]:
                size = packet[offset]
                labels.append(packet[offset + 1:offset + 1 + size].decode('ascii'))
                offset += size + 1
            offset += 1
            qtype = struct.unpack('!H', packet[offset:offset + 2])[0]
            name = '.'.join(labels).lower()
            address = {'blocked.test': '127.0.0.1', 'public.test': '198.51.100.9',
                       'upstream.test': '198.51.100.10'}.get(name)
            if name == 'rebind.test' and qtype == 1:
                address = '198.51.100.9' if not rebind_answers else '127.0.0.1'
                rebind_answers.append(address)
            answer = b''
            if qtype == 1 and address:
                # Zero TTL: a second resolve really would change the result.
                answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + socket.inet_aton(address)
            header = packet[:2] + struct.pack('!HHHHH', 0x8180, 1, int(bool(answer)), 0, 0)
            dns_socket.sendto(header + packet[12:offset + 4] + answer, peer)

    dns_thread = threading.Thread(target=dns_responses, daemon=True)
    dns_thread.start()
    processes, logs = [], []
    try:
        path = tmp_path / 'panel.db'
        init_db(path)
        stats_port, entry_a, entry_b = [free_port() for _ in range(3)]
        cert, key = certificate
        options = {'listen': '127.0.0.1', 'certificate_path': str(cert), 'key_path': str(key)}
        with connect(path) as db:
            db.execute("INSERT INTO nodes(id,name,protocol,port,secret,mode,options,server_name) VALUES('n','Fixture',?,?,'node-fixture-secret',?,?,'localhost')",
                       (protocol, entry_a, mode, json.dumps(options)))
            for uid, port in [('a', entry_a), ('b', entry_b)]:
                db.execute('INSERT INTO users(id,name,secret,uuid,token) VALUES(?,?,?,?,?)',
                           (uid, uid, 'user-fixture-' + uid, str(uuid.uuid4()), 'token-' + uid))
                db.execute("INSERT INTO memberships(user_id,node_id,port) VALUES(?,'n',?)", (uid, port))
        settings = copy.deepcopy(routing.DEFAULT)
        # This normal admin IP rule used to introduce another resolve. The
        # mandatory security pass must remove it to pin the checked answer.
        settings['rules'] = [{'id': 'fixture-ip-rule', 'name': 'Fixture IP rule', 'enabled': True,
                              'priority': 'forced', 'target': 'reject', 'node_ids': [],
                              'match': {'ip_cidr': ['203.0.113.0/24']}}]
        routing.write(path, settings)
        document = current_config(path, stats_port)
        document['dns'] = {'disable_cache': True, 'servers': [{'type': 'udp', 'tag': 'fixture-dns',
                          'server': '127.0.0.1', 'server_port': dns_socket.getsockname()[1]}]}
        document['route']['default_domain_resolver'] = 'fixture-dns'
        # Test-only mapping AFTER the intact system checks: accepted public
        # traffic reaches a controlled local HTTP target without Internet I/O.
        document['route']['rules'].append({'ip_cidr': ['198.51.100.9/32'], 'action': 'route',
            'outbound': 'direct', 'override_address': '127.0.0.1', 'override_port': target.server_port})
        document['route']['rules'].append({'ip_cidr': ['198.51.100.11/32'], 'action': 'route',
            'outbound': 'direct', 'override_address': '127.0.0.1', 'override_port': packet_target.getsockname()[1]})
        upstream_port = free_port()
        document['outbounds'].append({'type': 'socks', 'tag': 'private-upstream',
                                     'server': '127.0.0.1', 'server_port': upstream_port, 'version': '5'})
        document['route']['rules'].append({'ip_cidr': ['198.51.100.10/32'], 'action': 'route', 'outbound': 'private-upstream'})
        # This isolated upstream is not a panel-managed customer entry. Its
        # explicit mapping proves private upstream dialing remains supported.
        upstream = {'log': {'level': 'error'},
                    'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': upstream_port}],
                    'outbounds': [{'type': 'direct', 'tag': 'direct'}],
                    'route': {'rules': [{'action': 'route', 'outbound': 'direct',
                                        'override_address': '127.0.0.1', 'override_port': target.server_port}]}}
        specs = [('server', document, stats_port), ('upstream', upstream, upstream_port)]
        attack_ports = {}
        allowed_ports = []
        for uid in ('a', 'b'):
            user = next(row for row in records(path, 'users') if row['id'] == uid)
            outbound = outbounds(user, records(path, 'nodes'), records(path, 'memberships'), '127.0.0.1')[0]
            outbound['tag'] = 'proxy'
            if protocol == 'hysteria2':
                outbound['tls']['certificate_path'] = str(cert)
            destinations = [('stats-ip', '127.0.0.1', stats_port),
                            ('stats-host', 'blocked.test', stats_port),
                            ('private-ip', '127.0.0.1', target.server_port),
                            ('private-host', 'blocked.test', target.server_port),
                            ('rebind-host', 'rebind.test', 80)] if uid == 'a' else [
                            ('public-ip', '198.51.100.9', 80), ('public-host', 'public.test', 80),
                            ('private-upstream', 'upstream.test', 80), ('first-rebind', 'rebind.test', 80)]
            inbounds = []
            for key, host, port in destinations:
                local_port = free_port()
                inbounds.append({'type': 'direct', 'tag': key, 'listen': '127.0.0.1',
                                 'listen_port': local_port, 'override_address': host, 'override_port': port})
                if uid == 'a':
                    attack_ports[key] = local_port
                else:
                    allowed_ports.append(local_port)
            if uid == 'b':
                udp_port = free_port()
                inbounds.append({'type': 'direct', 'tag': 'public-udp', 'listen': '127.0.0.1',
                                 'listen_port': udp_port, 'network': 'udp',
                                 'override_address': '198.51.100.11', 'override_port': 53})
            specs.append((uid, {'log': {'level': 'error'}, 'inbounds': inbounds,
                                'outbounds': [outbound], 'route': {'final': 'proxy'}}, inbounds[0]['listen_port']))
        binary = os.environ['SING_BOX']
        for name, doc, port in specs:
            config_file = tmp_path / (name + '.json')
            config_file.write_text(json.dumps(doc))
            checked = subprocess.run([binary, 'check', '-c', str(config_file)],
                                     capture_output=True, text=True, timeout=5)
            assert checked.returncode == 0, checked.stderr
            logfile = (tmp_path / (name + '.log')).open('w+')
            logs.append(logfile)
            process = subprocess.Popen([binary, 'run', '-c', str(config_file)], stdout=logfile, stderr=logfile)
            processes.append(process)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    logfile.seek(0)
                    pytest.fail(logfile.read())
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.03)
            else:
                pytest.fail('Fixture core did not listen')
        for port in allowed_ports:
            with urlopen('http://127.0.0.1:' + str(port) + '/public', timeout=3) as response:
                assert b'fixture-only-public-result' in response.read()
        assert rebind_answers == ['198.51.100.9']
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as packet:
            packet.settimeout(3)
            packet.sendto(b'public-udp-query', ('127.0.0.1', udp_port))
            assert packet.recv(4096) == b'public-udp-response'
        before = {key: value for key, value in query(stats_port).items() if ':b>>>' in key}
        assert sum(before.values()) > 40000
        for key in ('stats-ip', 'stats-host'):
            for reset in (False, True):
                with pytest.raises(grpc.RpcError):
                    stats_call(attack_ports[key], reset)
        for key in ('private-ip', 'private-host', 'rebind-host'):
            with pytest.raises((OSError, TimeoutError)):
                urlopen('http://127.0.0.1:' + str(attack_ports[key]) + '/forbidden', timeout=2)
        after = query(stats_port)
        assert all(after[key] >= value for key, value in before.items())
        assert hits == ['/public', '/public', '/public', '/public']
        assert packet_hits == [b'public-udp-query']
        assert rebind_answers == ['198.51.100.9', '127.0.0.1']
    finally:
        for process in reversed(processes):
            process.terminate()
        for process in reversed(processes):
            process.wait(timeout=5)
        for logfile in logs:
            logfile.close()
        target.shutdown()
        target.server_close()
        thread.join(timeout=2)
        packet_target.close()
        packet_thread.join(timeout=.2)
        dns_stopped.set()
        dns_socket.close()
        dns_thread.join(timeout=.2)
