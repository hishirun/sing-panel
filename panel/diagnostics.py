"""Bounded administrator diagnostics without subscription tokens or raw user agents."""
import asyncio
import json
import logging
import re
import time
from pathlib import Path
from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import StreamingResponse
from .core import connect

log=logging.getLogger(__name__)

def migrate(db):
    db.executescript('''CREATE TABLE IF NOT EXISTS subscription_fetches (
        id INTEGER PRIMARY KEY, timestamp INTEGER NOT NULL,user_id TEXT NOT NULL,
        client TEXT NOT NULL,format TEXT NOT NULL,status INTEGER NOT NULL,nodes INTEGER NOT NULL,duration_ms INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS subscription_fetch_user ON subscription_fetches(user_id,id);
        CREATE TABLE IF NOT EXISTS server_logs (server_id TEXT PRIMARY KEY, timestamp INTEGER NOT NULL, content TEXT NOT NULL);''')

def clean_log(value):
    text=str(value)[-16384:]
    text=re.sub(r'\x1b\[[0-9;]*[A-Za-z]','',text)
    text=re.sub(r'(?:https?|ss|snell|vless|hysteria2|anytls|trojan|tuic|shadowtls)://[^\s]+','[链接已隐藏]',text,flags=re.I)
    text=re.sub(r'(?i)(password|psk|userkey|private_key|token|authorization)([\s=:"\x27]+)[^\s,;]+',r'\1\2[隐藏]',text)
    return ''.join(c for c in text if c in '\n\t' or ord(c)>=32)[-12000:]

def tail(path):
    try:
        with Path(path).open('rb') as file:
            file.seek(0,2);size=file.tell();file.seek(max(0,size-16384))
            data=file.read(16384).decode('utf-8',errors='replace')
        if size>16384:data=data.partition('\n')[2]
        return clean_log(data)
    except OSError:return ''

def record(path,uid,ua,fmt,status,nodes,started):
    from .client_profiles import FORMATS
    client=next((label for needle,label in [('shadowrocket','Shadowrocket'),('surfboard','Surfboard'),('surge','Surge'),('mihomo','Mihomo'),('clash','Clash'),('hiddify','Hiddify'),('sing-box','sing-box'),('singbox','sing-box'),('sfi/','sing-box'),('sfa/','sing-box')] if needle in ua.lower()),'其他客户端')
    try:
        with connect(path) as db:
            db.execute('INSERT INTO subscription_fetches(timestamp,user_id,client,format,status,nodes,duration_ms) VALUES(?,?,?,?,?,?,?)',
                       (int(time.time()),uid,client,fmt if fmt in FORMATS else '未知格式',status,nodes,max(0,int((time.monotonic()-started)*1000))))
            db.execute('DELETE FROM subscription_fetches WHERE timestamp<? OR id<=(SELECT COALESCE(MAX(id),0)-10000 FROM subscription_fetches)',(int(time.time())-30*86400,))
    except Exception:log.warning('Subscription diagnostics write failed',exc_info=False)

def install(app,m):
    @app.get('/system/subscriptions')
    def history(request:Request,user_id:str='',result:str='',before:int=0,window:int=0):
        m.authenticated(request)
        with connect(m.DB) as db:
            window=window if window>0 else db.execute('SELECT COALESCE(MAX(id),0) FROM subscription_fetches').fetchone()[0]
            clauses=['f.id<=?'];params=[window]
            if before>0:clauses.append('f.id<?');params.append(before)
            if user_id:clauses.append('f.user_id=?');params.append(user_id[:128])
            if result in ('success','failed'):clauses.append('f.status<400' if result=='success' else 'f.status>=400')
            rows=[dict(r) for r in db.execute('SELECT f.*,COALESCE(u.name,\'已删除用户\') name FROM subscription_fetches f LEFT JOIN users u ON u.id=f.user_id WHERE '+' AND '.join(clauses)+' ORDER BY f.id DESC LIMIT 51',params)]
            users=[dict(r) for r in db.execute('SELECT id,name FROM users ORDER BY name')]
        return m.render(request,'subscription_history.html',rows=rows[:50],next_before=rows[49]['id'] if len(rows)>50 else 0,window=window,user_id=user_id,result=result,users=users)

    @app.get('/system/diagnostics')
    def diagnostics(request:Request,server:str='local'):
        m.authenticated(request)
        # Use the same server inventory as the live monitoring endpoint.
        with connect(m.DB) as db:servers=[dict(r) for r in db.execute('SELECT id,name FROM servers ORDER BY rowid')]
        if server!='local' and server not in {s['id'] for s in servers}:raise HTTPException(404)
        return m.render(request,'diagnostics.html',servers=servers,selected=server)

    def payload(request,server,logs):
        m.authenticated(request)
        if server=='local':
            from .machine import snapshot
            metrics={**snapshot(m.DIRECTORY),'running':bool(m.runtime.process and m.runtime.process.poll() is None)}
            return {'metrics':metrics,'online':True,'timestamp':int(time.time()),'logs':tail(m.DIRECTORY/'core.log') if logs else '', 'error':clean_log(m.runtime.error)}
        from .fleet import get_server
        try:row=get_server(m.DB,server)
        except ValueError:raise HTTPException(404)
        with connect(m.DB) as db:entry=db.execute('SELECT * FROM server_logs WHERE server_id=?',(server,)).fetchone()
        return {'metrics':row['metrics'],'online':row['online'],'timestamp':entry['timestamp'] if entry else 0,'logs':entry['content'] if entry and logs else '', 'error':clean_log(row['error'])}

    @app.get('/system/live')
    async def live(request:Request,server:str='local',logs:bool=True):
        await run_in_threadpool(m.authenticated,request)
        await run_in_threadpool(payload,request,server,False)
        return stream(request,lambda:payload(request,server,logs),m)


def stream(request,producer,m):
    async def events():
        # Finite lifetime also bounds stale sessions and releases idle resources.
        for _ in range(60):
            if await request.is_disconnected():break
            try:
                data=await run_in_threadpool(producer)
            except HTTPException as error:
                yield 'event: expired\ndata: '+json.dumps({'status':error.status_code})+'\n\n';break
            yield 'event: update\ndata: '+json.dumps(data,ensure_ascii=False,separators=(',',':'))+'\n\n'
            await asyncio.sleep(3)
    return StreamingResponse(events(),media_type='text/event-stream',headers={'Cache-Control':'no-store','X-Accel-Buffering':'no'})
