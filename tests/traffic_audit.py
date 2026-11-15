"""Byte-exact audit using isolated loopback cores; no production database changes.
Run: PYTHONPATH=. SING_BOX=/path/to/sing-box python tests/traffic_audit.py
"""
import json, os, re, socket, subprocess, tempfile, threading, time, uuid
from pathlib import Path
from panel.core import init_db, connect, records, set_memberships
from loopback_fixture import LoopbackFixtureRuntime
from panel.subscriptions import outbounds
from panel.stats import query

BINARY=os.environ.get('SING_BOX','/opt/sing-panel/sing-box')
def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0));return s.getsockname()[1]
def receive(s,n):
    data=b''
    while len(data)<n:
        chunk=s.recv(n-len(data))
        if not chunk:raise RuntimeError('unexpected EOF')
        data+=chunk
    return data
def socks(s,command,dest=0):
    s.sendall(b'\x05\x01\x00');assert receive(s,2)==b'\x05\x00'
    s.sendall(bytes([5,command,0,1,127,0,0,1])+dest.to_bytes(2,'big'))
    head=receive(s,4);assert head[1]==0,head
    if head[3]==1:address=socket.inet_ntoa(receive(s,4))
    elif head[3]==4:address=socket.inet_ntop(socket.AF_INET6,receive(s,16))
    else:address=receive(s,receive(s,1)[0]).decode()
    return address,int.from_bytes(receive(s,2),'big')
def counters(rt):
    rt.sample();u=records(rt.db,'users')[0]
    return u['upload'],u['download']

def audit(udp_reply_size=1024):
    report=[]
    with tempfile.TemporaryDirectory(prefix='sing-panel-traffic-audit-') as directory:
        directory=Path(directory);db=directory/'panel.db';init_db(db)
        key=subprocess.check_output([BINARY,'generate','reality-keypair'],text=True)
        private=re.search(r'PrivateKey:\s*(\S+)',key)[1];public=re.search(r'PublicKey:\s*(\S+)',key)[1]
        with connect(db) as c:
            for protocol,mode in [('snell5','compat'),('snell5','shared'),('snell6','compat'),('snell6','shared'),('reality','shared')]:
                identity=protocol+'-'+mode
                c.execute('INSERT INTO nodes(id,name,protocol,port,secret,private_key,public_key,short_id,server_name,mode,options) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                    (identity,identity,protocol,port(),'audit-node-secret-0123456789',private,public,'abcdef12','www.cloudflare.com',mode,json.dumps({'listen':'127.0.0.1'})))
            for uid in ('audit','untouched'):
                c.execute('INSERT INTO users(id,name,secret,uuid,token) VALUES(?,?,?,?,?)',(uid,uid,'audit-user-secret-'+uid,str(uuid.uuid4()),str(uuid.uuid4())))
                set_memberships(c,uid,[r['id'] for r in c.execute('SELECT id FROM nodes')])
        rt=LoopbackFixtureRuntime(BINARY,directory,port());rt.apply()
        try:
            outputs=outbounds(records(db,'users')[0],records(db,'nodes'),records(db,'memberships'),'127.0.0.1')
            for out in outputs:
                sp=port();cp=directory/'client.json'
                cp.write_text(json.dumps({'log':{'level':'error'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':sp}],'outbounds':[out]}))
                log=(directory/'client.log').open('a');client=subprocess.Popen([BINARY,'run','-c',str(cp)],stdout=log,stderr=log)
                try:
                    for attempt in range(100):
                        try:
                            with socket.create_connection(('127.0.0.1',sp),timeout=.1):break
                        except OSError:time.sleep(.05)
                    # Raw TCP: no HTTP or application header bytes to confuse the comparison.
                    upload=b'u'*(1024*1024);download=b'd'*(2*1024*1024)
                    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen()
                    errors=[]
                    def tcp_target():
                        try:
                            with listener.accept()[0] as peer:
                                peer.settimeout(20);assert receive(peer,len(upload))==upload
                                peer.sendall(download)
                        except Exception as e:errors.append(str(e))
                        finally:listener.close()
                    threading.Thread(target=tcp_target,daemon=True).start()
                    before=counters(rt)
                    with socket.create_connection(('127.0.0.1',sp),timeout=20) as client_socket:
                        socks(client_socket,1,listener.getsockname()[1]);client_socket.sendall(upload)
                        assert receive(client_socket,len(download))==download
                    time.sleep(.2);after=counters(rt);assert not errors,errors
                    report.append({'node':out['tag'],'transport':'TCP','sent':len(upload),'received':len(download),
                                   'counted_upload':after[0]-before[0],'counted_download':after[1]-before[1]})
                    # UDP: 4 independently identifiable packets and replies.
                    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0));udp.settimeout(10)
                    up=b'x'*512;down=b'y'*udp_reply_size;target_port=udp.getsockname()[1]
                    def udp_target():
                        try:
                            for _ in range(4):
                                data,address=udp.recvfrom(65535);assert data==up;udp.sendto(down,address)
                        except Exception as e:errors.append(str(e))
                        finally:udp.close()
                    threading.Thread(target=udp_target,daemon=True).start();before=counters(rt)
                    with socket.create_connection(('127.0.0.1',sp),timeout=15) as control:
                        _,relay_port=socks(control,3)
                        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as packet:
                            packet.settimeout(15)
                            observed=0
                            for _ in range(4):
                                packet.sendto(b'\0\0\0\1\x7f\0\0\1'+target_port.to_bytes(2,'big')+up,('127.0.0.1',relay_port))
                                response=packet.recv(65535)
                                header=22 if response[3]==4 else 10 if response[3]==1 else 7+response[4]
                                assert response[header:]==down[:len(response)-header]
                                observed+=len(response)-header
                    time.sleep(.2);after=counters(rt);assert not errors,errors
                    report.append({'node':out['tag'],'transport':'UDP','sent':len(up)*4,'expected_received':len(down)*4,'received':observed,
                                   'counted_upload':after[0]-before[0],'counted_download':after[1]-before[1]})
                finally:
                    client.terminate();client.wait(timeout=10);log.close()
            for result in report:
                assert result['sent']==result['counted_upload'],result
                assert result['received']==result['counted_download'],result
            before=counters(rt)
            for _ in range(5):rt.sample()
            assert counters(rt)==before,'duplicate sampling changed totals'
            rt.terminate();rt.apply()
            assert counters(rt)==before,'restart changed totals'
            other=records(db,'users')[1];assert other['upload']==other['download']==0
            with connect(db) as c:c.execute("UPDATE users SET quota=1 WHERE id='audit'")
            rt.apply();document=json.loads((directory/'sing-box.json').read_text())
            assert all(':audit' not in i['tag'] and all(u['name']!='audit' for u in i.get('users',[])) for i in document['inbounds'])
            assert counters(rt)==before
            return {'measurements':report,'totals':{'upload':before[0],'download':before[1]},
                    'udp_payload_intact':all(r['received']==r.get('expected_received',r['received']) for r in report),
                    'repeat_sample':'pass','core_restart':'pass','other_user_isolation':'pass','shared_quota_disable':'pass'}
        finally:rt.stop()

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--udp-reply-bytes',type=int,choices=(1024,2048),default=1024)
    args=parser.parse_args()
    print(json.dumps(audit(args.udp_reply_bytes),indent=2))
