"""Linux loopback source-IP enforcement audit; uses isolated temporary cores."""
import json, os, socket, subprocess, tempfile, time
from pathlib import Path
from panel.core import init_db, connect, records, set_memberships
from loopback_fixture import LoopbackFixtureRuntime
from panel.subscriptions import outbounds
binary=os.environ.get('SING_BOX','sing-box')
def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
with tempfile.TemporaryDirectory(prefix='sing-panel-ip-audit-') as directory:
    path=Path(directory);db=path/'panel.db';init_db(db)
    with connect(db) as c:
        c.execute("INSERT INTO nodes(id,name,protocol,port,secret,mode) VALUES('n','N','snell6',?,'test-node-secret-123456','shared')",(port(),))
        c.execute("INSERT INTO users(id,name,secret,uuid,token,max_ips) VALUES('u','U','test-user-secret-123456','uuid','token',1)")
        set_memberships(c,'u',['n'])
    rt=LoopbackFixtureRuntime(binary,path,port());rt.apply();clients=[];proxies=[];target=socket.socket();target.bind(('127.0.0.1',0));target.listen()
    try:
        out=outbounds(records(db,'users')[0],records(db,'nodes'),records(db,'memberships'),'127.0.0.1')[0]
        for index,source in enumerate(('127.0.0.2','127.0.0.3')):
            sp=port();cfg=path/f'client-{index}.json'
            cfg.write_text(json.dumps({'log':{'level':'error'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':sp}], 'outbounds':[{**out,'inet4_bind_address':source}]}))
            client=subprocess.Popen([binary,'run','-c',str(cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);clients.append(client)
            for _ in range(100):
                try:p=socket.create_connection(('127.0.0.1',sp),timeout=.1);break
                except OSError:time.sleep(.02)
            p.settimeout(5);proxies.append(p);p.sendall(b'\x05\x01\x00');assert p.recv(2)==b'\x05\x00'
            p.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+target.getsockname()[1].to_bytes(2,'big'));assert p.recv(10)[1]==0
        rt.track()
        assert rt.online['u']['ips']==['127.0.0.2'],rt.online
        assert proxies[1].recv(1)==b''
        with connect(db) as c:assert c.execute("SELECT ip FROM client_ips WHERE user_id='u'").fetchone()[0]=='127.0.0.2'
        print(json.dumps({'real_source_ips': ['127.0.0.2','127.0.0.3'],'limit':1,'retained':rt.online['u']['ips'],'excess_connection_closed':True}))
    finally:
        for p in proxies:p.close()
        for p in clients:p.terminate();p.wait(timeout=5)
        target.close();rt.stop()
