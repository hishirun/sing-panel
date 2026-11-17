"""Two users, the same destination, independently authenticated personal proxies."""
import copy,json,os,socket,subprocess,threading,time,uuid
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from unittest.mock import patch
import pytest
from panel.core import connect,init_db,records,set_memberships,current_config
from panel import personal_outbounds as personal,user_routing as ur
from panel.protocols import new_key
from panel.runtime import Runtime
from panel.subscriptions import outbounds
from loopback_fixture import unprotected_fixture_config,statistics_port
from test_integration import port
from traffic_audit import socks,receive


@pytest.mark.skipif(not os.environ.get('SING_BOX'),reason='SING_BOX required')
@pytest.mark.parametrize('kind,method',[('http',''),('socks',''),('shadowsocks','aes-128-gcm'),('shadowsocks','2022-blake3-aes-128-gcm')])
def test_real_private_exits_tcp_udp_and_user_isolation(tmp_path,kind,method):
    binary=os.environ['SING_BOX'];targets=[];packets=[];workers=[];processes=[];logs=[];stop=threading.Event();rt=None
    def start(doc,name):
        path=tmp_path/(name+'.json');path.write_text(json.dumps(doc));log=(tmp_path/(name+'.log')).open('w');logs.append(log)
        proc=subprocess.Popen([binary,'run','-c',str(path)],stdout=log,stderr=log);processes.append(proc);return proc
    try:
        for label in (b'alice-private-exit',b'bob-private-exit'):
            class Target(BaseHTTPRequestHandler):
                marker=label
                def do_GET(self):
                    self.send_response(200);self.send_header('Content-Length',str(len(self.marker)));self.end_headers();self.wfile.write(self.marker)
                def log_message(self,*args):pass
            target=ThreadingHTTPServer(('127.0.0.1',0),Target);targets.append(target)
            worker=threading.Thread(target=target.serve_forever,daemon=True);worker.start();workers.append(worker)
            packet=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);packet.bind(('127.0.0.1',target.server_port));packet.settimeout(.1);packets.append(packet)
            def echo(udp=packet,marker=label):
                while not stop.is_set():
                    try:payload,peer=udp.recvfrom(4096);udp.sendto(marker+b':'+payload,peer)
                    except socket.timeout:continue
                    except OSError:return
            worker=threading.Thread(target=echo,daemon=True);worker.start();workers.append(worker)
        path=tmp_path/'panel.db';init_db(path)
        with connect(path) as db:
            db.execute("INSERT INTO nodes(id,name,protocol,port,secret,mode,options) VALUES('node','Fixture','snell6',?,'node-fixture-secret','shared',?)",(port(),json.dumps({'listen':'127.0.0.1'})))
            for uid in ('alice','bob'):
                db.execute('INSERT INTO users(id,name,secret,uuid,token) VALUES(?,?,?,?,?)',(uid,uid,'fixture-user-secret-'+uid,str(uuid.uuid4()),'fixture-token-'+uid));set_memberships(db,uid,['node'])
        upstreams=[];mapping={}
        for index,uid in enumerate(('alice','bob')):
            listen=port();password=new_key(method) if method.startswith('2022-') else 'private-password-'+uid
            raw={'name':uid+' personal','type':kind,'server':'1.1.1.1','server_port':listen,'username':uid,'password':password,'method':method}
            built=personal.build(raw);entry={**built,'id':'personal-'+uid,'user_id':uid,'enabled':True,'revision':1,'created_at':1,'updated_at':1};personal._put(path,entry)
            ur.configure_user(path,uid,True)
            policy={'enabled':True,'rules':[{'id':'rule','name':'Private route','enabled':True,'kind':'ip_cidr','values':['127.0.0.1/32'],'target':entry['id'],'node_ids':[]}]}
            normalized=ur.validate_draft(path,uid,policy)
            with connect(path) as db:db.execute('UPDATE user_routing SET applied=? WHERE user_id=?',(json.dumps(normalized),uid))
            inbound={'type':kind,'tag':'entry-'+uid,'listen':'127.0.0.1','listen_port':listen}
            if kind=='shadowsocks':inbound.update(method=method,password=password)
            else:inbound['users']=[{'username':uid,'password':password}]
            upstreams.append(inbound);mapping[entry['id']]=listen
        start({'log':{'level':'error'},'inbounds':upstreams,'outbounds':[{'type':'direct','tag':'direct'}],
               'route':{'rules':[{'inbound':['entry-'+uid],'action':'route','outbound':'direct','override_address':'127.0.0.1','override_port':targets[index].server_port} for index,uid in enumerate(('alice','bob'))]}},'upstreams')
        def fixture_config(*args,**kwargs):
            doc=unprotected_fixture_config(current_config,*args,**kwargs)
            # Pinning is tested at the actual API boundary. Only this isolated
            # network fixture remaps approved literals to its loopback proxies.
            for outbound in doc['outbounds']:
                if outbound['tag'].startswith('up-personal-'):
                    assert outbound['server']=='1.1.1.1';outbound['server']='127.0.0.1'
            return doc
        rt=Runtime(binary,tmp_path,statistics_port(path))
        with patch('panel.runtime.current_config',side_effect=fixture_config):rt.apply()
        for index,user in enumerate(records(path,'users')):
            local=port();outs=outbounds(user,records(path,'nodes'),records(path,'memberships'),'127.0.0.1')
            proc=start({'log':{'level':'error'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':local}],'outbounds':outs},user['id'])
            for _ in range(100):
                try:
                    with socket.create_connection(('127.0.0.1',local),timeout=.1):break
                except OSError:
                    if proc.poll() is not None:pytest.fail((tmp_path/(user['id']+'.log')).read_text())
                    time.sleep(.03)
            expected=(b'alice-private-exit',b'bob-private-exit')[index]
            with socket.create_connection(('127.0.0.1',local),timeout=5) as stream:
                stream.settimeout(5);socks(stream,1,9);stream.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                response=b''
                while chunk:=stream.recv(4096):response+=chunk
                assert response.endswith(expected)
            if kind!='http':
                with socket.create_connection(('127.0.0.1',local),timeout=5) as control:
                    _,relay=socks(control,3)
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as packet:
                        packet.settimeout(5);packet.sendto(b'\0\0\0\1\x7f\0\0\1'+(9).to_bytes(2,'big')+b'probe',('127.0.0.1',relay))
                        assert packet.recv(4096).endswith(expected+b':probe')
        rt.sample();assert all(user['upload']>0 and user['download']>0 for user in records(path,'users'))
    finally:
        stop.set()
        for proc in reversed(processes):
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
        if rt:rt.stop()
        for packet in packets:packet.close()
        for server in targets:server.shutdown();server.server_close()
        for worker in workers:worker.join(timeout=1)
        for log in logs:log.close()
