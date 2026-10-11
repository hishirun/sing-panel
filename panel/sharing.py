"""User-scoped sharing views and nonblocking server-to-target TCP monitoring."""
import base64
import io
import json
import socket
import threading
import time
from datetime import datetime, timezone, timedelta
from urllib.parse import urlsplit
import qrcode
import qrcode.image.svg
from .core import connect, records, reason
from .subscriptions import outbounds, native_subscription
from .options import domain

DEFAULT_TARGETS='Cloudflare,www.cloudflare.com,443\nMicrosoft,www.microsoft.com,443\nApple,www.apple.com,443'

def read_settings(path):
    result={'brand':'SingBox面板','theme':'glass','public_url':'','support':'','monitor_targets':DEFAULT_TARGETS,'admin_path':'','share_path':'/s'}
    with connect(path) as db:
        result.update({r['key']:r['value'] for r in db.execute('SELECT * FROM settings') if r['key'] in result})
    return result

def parse_targets(text):
    targets=[]
    for line in text.splitlines():
        if not line.strip():continue
        parts=[p.strip() for p in line.split(',')]
        if len(parts)!=3 or not parts[0] or len(parts[0])>60:raise ValueError('监控目标格式：名称,域名,端口，每行一个')
        host=domain(parts[1])
        try:port=int(parts[2])
        except ValueError:raise ValueError('监控端口无效')
        if not 1<=port<=65535:raise ValueError('监控端口应为 1–65535')
        targets.append({'name':parts[0],'host':host,'port':port,'key':host+':'+str(port)})
    if len(targets)>8:raise ValueError('最多设置 8 个监控目标')
    return targets

def save_settings(path,raw):
    brand=str(raw.get('brand','')).strip()
    support=str(raw.get('support','')).strip()
    public_url=str(raw.get('public_url','')).strip().rstrip('/')
    if not brand or len(brand)>60:raise ValueError('品牌名称须为 1–60 个字符')
    if len(support)>300:raise ValueError('联系说明最多 300 字')
    if public_url:
        parsed=urlsplit(public_url)
        if parsed.scheme not in ('https','http') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path:
            raise ValueError('公开地址请填写 http(s)://域名[:端口]，不带路径、账号或查询参数')
        try:parsed.port
        except ValueError:raise ValueError('公开地址端口无效')
    theme=str(raw.get('theme','glass'))
    if theme not in ('glass','dark','retro'):raise ValueError('主题无效')
    targets=str(raw.get('monitor_targets','')).strip()
    parse_targets(targets)
    from .paths import validate_paths
    existing=read_settings(path)
    admin_path,share_path=validate_paths(raw.get('admin_path',existing['admin_path']),raw.get('share_path',existing['share_path']))
    with connect(path) as db:
        for k,v in dict(admin_path=admin_path,share_path=share_path,brand=brand,theme=theme,support=support,public_url=public_url,monitor_targets=targets).items():
            db.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',(k,v))

def share_context(path,user,host,base):
    all_nodes=records(path,'nodes'); memberships=records(path,'memberships')
    allowed={m['node_id']:m for m in memberships if m['user_id']==user['id']}
    active=outbounds(user,all_nodes,memberships,host) if host else []
    nodes=[]
    # Build each outbound separately: display names need not be unique.
    for n in all_nodes:
        if n['id'] not in allowed:continue
        outs=outbounds(user,[n],memberships,host) if host else []
        out=outs[0] if outs else None
        uri='';surge='';config=''
        if out:
            uri=base64.b64decode(native_subscription([out],'shadowrocket.txt')).decode().strip()
            if out['type']=='snell' and 'userkey' not in out:
                surge=native_subscription([out],'surge.conf').removeprefix('[Proxy]\n').strip()
            config=json.dumps(out,indent=2,ensure_ascii=False)
        nodes.append({**n,'port':allowed[n['id']]['port'] if n['mode']=='compat' else n['port'],
                      'outbound':out,'uri':uri,'surge':surge,'config':config})
    used=user['upload']+user['download']
    pending_days=json.loads(user.get('policy','{}')).get('first_use_days',0) if not user.get('activated_at') else 0
    with connect(path) as db:
        daily=[dict(r) for r in db.execute('SELECT day,upload,download,upload+download total FROM daily WHERE user_id=? ORDER BY day DESC LIMIT 30',(user['id'],))]
        today=datetime.now(timezone.utc).date()
        saved={r['day']:r for r in db.execute('SELECT day,upload,download FROM daily WHERE user_id=? AND day>=?',(user['id'],str(today-timedelta(days=29))))}
        daily=[]
        for offset in range(29,-1,-1):
            date=str(today-timedelta(days=offset));r=saved.get(date,{'upload':0,'download':0})
            daily.append(dict(day=date,label=date[5:],upload=r['upload'],download=r['download'],total=r['upload']+r['download']))
        node_usage=[dict(r) for r in db.execute('SELECT node_id,node_name,SUM(upload) upload,SUM(download) download,SUM(upload+download) total FROM node_daily WHERE user_id=? GROUP BY node_id ORDER BY total DESC',(user['id'],))]
        seen={r['node_id'] for r in node_usage}
        node_usage.extend(dict(node_id=n['id'],node_name=n['name'],upload=0,download=0,total=0) for n in nodes if n['id'] not in seen)
        historical=db.execute('SELECT COALESCE(SUM(upload+download),0) FROM daily WHERE user_id=?',(user['id'],)).fetchone()[0]
        unattributed=max(0,historical-sum(r['total'] for r in node_usage))
        maximum=max([r['total'] for r in daily],default=0) or 1
        for r in daily:r.update(up_height=r['upload']/maximum*100,down_height=r['download']/maximum*100)
        node_max=max([r['total'] for r in node_usage],default=0) or 1
        for r in node_usage:r['percent']=r['total']/node_max*100
        monitoring=[]
        for target in parse_targets(read_settings(path)['monitor_targets']):
            rows=[dict(r) for r in db.execute('SELECT timestamp,ms FROM monitor_samples WHERE target=? ORDER BY timestamp DESC LIMIT 30',(target['key'],))][::-1]
            valid=[r['ms'] for r in rows if r['ms'] is not None]
            maximum=max(valid,default=1) or 1
            for r in rows:
                r['height']=max(3,round(r['ms']/maximum*65)) if r['ms'] is not None else 4
                r['time']=datetime.fromtimestamp(r['timestamp'],timezone.utc).strftime('%H:%M UTC')
            monitoring.append({'name':target['name'],'samples':rows,'last':rows[-1]['ms'] if rows else None,
                               'average':round(sum(valid)/len(valid),1) if valid else None,
                               'online':round(100*len(valid)/len(rows)) if rows else None,
                               'stale':bool(rows and time.time()-rows[-1]['timestamp']>180)})
    return dict(user=user,nodes=nodes,host=host,pending_days=pending_days,used=used,remaining=max(0,user['quota']-used),
                percent=min(100,round(used/user['quota']*100,1)) if user['quota'] else 0,
                expires=datetime.fromtimestamp(user['expires'],timezone.utc).strftime('%Y-%m-%d %H:%M UTC') if user['expires'] else (f'首次使用后 {pending_days} 天' if pending_days else '长期有效'),
                days=max(0,int((user['expires']-time.time()+86399)//86400)) if user['expires'] else None,
                share_url=base+read_settings(path)['share_path']+'/'+user['token'],daily=daily,daily_max=max([d['total'] for d in daily],default=1) or 1,
                monitoring=monitoring,active_count=len(active),node_usage=node_usage,unattributed=unattributed,today_usage=daily[-1],month_usage=sum(d['total'] for d in daily))

def qr_image(text):
    image=qrcode.make(text,image_factory=qrcode.image.svg.SvgPathImage,border=3)
    output=io.BytesIO();image.save(output)
    return output.getvalue()

class Monitor:
    def __init__(self,path):
        self.path=path;self.event=threading.Event();self.thread=None
    def collect(self):
        for t in parse_targets(read_settings(self.path)['monitor_targets']):
            if self.event.is_set():return
            started=time.monotonic()
            try:
                with socket.create_connection((t['host'],t['port']),timeout=3):pass
                ms=round((time.monotonic()-started)*1000,1)
            except OSError:ms=None
            with connect(self.path) as db:
                db.execute('INSERT OR REPLACE INTO monitor_samples VALUES(?,?,?)',(t['key'],int(time.time()),ms))
                db.execute('DELETE FROM monitor_samples WHERE timestamp<?',(int(time.time())-86400,))
    def loop(self):
        while not self.event.is_set():
            try:self.collect()
            except Exception:
                import logging
                logging.getLogger(__name__).exception('monitor collection failed')
            if self.event.wait(60):return
    def start(self):
        self.event.clear();self.thread=threading.Thread(target=self.loop,daemon=True);self.thread.start()
    def stop(self):
        self.event.set()
        if self.thread:self.thread.join(timeout=5)
