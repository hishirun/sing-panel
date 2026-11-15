"""Real core tests: SING_BOX=/absolute/path/to/sing-box pytest -q."""
import json
import os
import re
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import pytest
from panel.core import init_db, connect, records, set_memberships
from loopback_fixture import LoopbackFixtureRuntime
from panel.subscriptions import outbounds

BINARY=os.environ.get('SING_BOX')
pytestmark=pytest.mark.skipif(not BINARY,reason='SING_BOX not set')

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0))
        return s.getsockname()[1]

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        payload=b'z'*131072
        self.send_response(200)
        self.send_header('Content-Length',str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self,*args): pass

@pytest.fixture(params=[(auth,mode) for auth in ("shared","compat") for mode in ("default","unshaped","unsafe-raw")])
def system(tmp_path,request):
    db=tmp_path/'panel.db'
    init_db(db)
    keys=subprocess.check_output([BINARY,'generate','reality-keypair'],text=True)
    private=re.search(r'PrivateKey:\s*(\S+)',keys)[1]
    public=re.search(r'PublicKey:\s*(\S+)',keys)[1]
    with connect(db) as c:
        for proto in ['snell5','snell6','reality']:
            c.execute('INSERT INTO nodes(id,name,protocol,port,secret,private_key,public_key,short_id,server_name,mode) VALUES(?,?,?,?,?,?,?,?,?,?)',
                (proto,proto,proto,port(),'node-secret-0123456789',private,public,'abcdef12','www.cloudflare.com',request.param[0] if proto!='reality' else 'shared'))
        c.execute("UPDATE nodes SET options=? WHERE id='snell6'",(json.dumps({'snell_mode':request.param[1],'reuse':True}),))
        c.execute("UPDATE nodes SET options=? WHERE id='reality'",(json.dumps({'short_ids':'abcdef12,0123456789abcdef','max_time_difference':120,'handshake_timeout':8,'alpn':'h2,http/1.1','fingerprint':'chrome'}),))
        for uid in ['alice','bob']:
            c.execute('INSERT INTO users(id,name,secret,uuid,token) VALUES(?,?,?,?,?)',
                (uid,uid,uid+'-user-secret-0123456789','11111111-1111-4111-8111-11111111111'+('1' if uid=='alice' else '2'),uid+'-token'))
            set_memberships(c,uid,['snell5','snell6','reality'])
    rt=LoopbackFixtureRuntime(BINARY,tmp_path,port())
    rt.apply()
    yield rt,tmp_path
    rt.stop()

def exchange(socks_port,http_port):
    with socket.create_connection(('127.0.0.1',socks_port),timeout=10) as s:
        s.settimeout(15)
        s.sendall(b'\x05\x01\x00')
        assert s.recv(2)==b'\x05\x00'
        s.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+http_port.to_bytes(2,'big'))
        response=s.recv(10)
        assert response[1]==0,response
        payload=b'x'*32768
        s.sendall(f'POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {len(payload)}\r\n\r\n'.encode()+payload)
        result=b''
        while chunk:=s.recv(65536):result+=chunk
        assert result.endswith(b'z'*131072)

def test_all_protocols_and_shared_user_accounting(system):
    rt,tmp=system
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    user=records(rt.db,'users')[0]
    try:
        for outbound in outbounds(user,records(rt.db,'nodes'),records(rt.db,'memberships'),'127.0.0.1'):
            socks=port()
            path=tmp/'client.json'
            path.write_text(json.dumps({'log':{'level':'error'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':socks}], 'outbounds':[outbound]}))
            with (tmp/'client.log').open('a') as log:
                client=subprocess.Popen([BINARY,'run','-c',str(path)],stdout=log,stderr=log)
            try:
                deadline=time.monotonic()+5
                while time.monotonic()<deadline:
                    try:
                        with socket.create_connection(('127.0.0.1',socks),timeout=.2):break
                    except OSError:time.sleep(.05)
                exchange(socks,server.server_port)
            finally:
                client.terminate();client.wait(timeout=10)
        rt.sample()
        users=records(rt.db,'users')
        assert users[0]['upload']>=32768*3
        assert users[0]['download']>=131072*3
        assert users[1]['upload']==users[1]['download']==0
        with connect(rt.db) as c:
            totals=c.execute('SELECT SUM(upload),SUM(download),COUNT(DISTINCT node_id) FROM node_daily WHERE user_id=?',('alice',)).fetchone()
            assert totals[0]==users[0]['upload']
            assert totals[1]==users[0]['download']
            assert totals[2]==3
        rt.sample()
        assert records(rt.db,'users')[0]['upload']==users[0]['upload']
        with connect(rt.db) as c:c.execute('UPDATE users SET quota=1 WHERE id=?',('alice',))
        rt.apply()
        cfg=json.loads((tmp/'sing-box.json').read_text())
        assert all(('alice' not in i['tag']) and all(u['name'].rsplit(':',1)[-1]=='bob' for u in i.get('users',[])) for i in cfg['inbounds'])
        assert records(rt.db,'users')[0]['download']>=users[0]['download']
    finally:server.shutdown()

def test_failed_bind_rolls_back_running_core(system):
    rt,tmp=system
    before=rt.signature
    with socket.socket(socket.AF_INET6) as taken:
        taken.bind(('::',0));taken.listen()
        with connect(rt.db) as c:
            if records(rt.db,'nodes')[0]['mode']=='compat':
                c.execute('UPDATE memberships SET port=? WHERE node_id=? AND user_id=?',(taken.getsockname()[1],'snell5','alice'))
            else:
                c.execute('UPDATE nodes SET port=? WHERE id=?',(taken.getsockname()[1],'snell5'))
        with pytest.raises(RuntimeError):rt.apply()
        assert rt.process.poll() is None
        assert rt.signature==before
        pid=rt.process.pid
        with pytest.raises(RuntimeError):rt.apply()
        assert rt.process.pid==pid
        rt.sample()

def test_live_connection_identity_and_disconnect(system):
    rt,tmp=system
    user=records(rt.db,'users')[0]
    for outbound in outbounds(user,records(rt.db,'nodes'),records(rt.db,'memberships'),'127.0.0.1'):
        socks_port=port()
        path=tmp/'identity-client.json'
        path.write_text(json.dumps({'log':{'level':'error'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':socks_port}],'outbounds':[outbound]}))
        with (tmp/'identity.log').open('a') as log:
            client=subprocess.Popen([BINARY,'run','-c',str(path)],stdout=log,stderr=log)
        target=socket.socket();target.bind(('127.0.0.1',0));target.listen()
        try:
            for _ in range(100):
                try:
                    with socket.create_connection(('127.0.0.1',socks_port),timeout=.1):break
                except OSError:time.sleep(.02)
            with socket.create_connection(('127.0.0.1',socks_port),timeout=5) as proxy:
                proxy.sendall(b'\x05\x01\x00');assert proxy.recv(2)==b'\x05\x00'
                proxy.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+target.getsockname()[1].to_bytes(2,'big'))
                assert proxy.recv(10)[1]==0
                for _ in range(30):
                    rt.track()
                    if rt.online.get('alice',{}).get('connections'):break
                    time.sleep(.02)
                assert rt.online['alice']['connections']>=1
                assert rt.online['alice']['ips']
                rt.disconnect('alice')
                proxy.settimeout(3)
                assert proxy.recv(1)==b''
        finally:
            target.close();client.terminate();client.wait(timeout=5)
