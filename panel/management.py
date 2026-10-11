"""User lifecycle, bulk operations, and source-IP presence tracking."""
import base64
import calendar
import ipaddress
import json
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from .core import connect, set_memberships

DAY=86400
SCHEMES=('vless','vmess','trojan','ss','snell','hysteria2','hy2','wireguard')

def migrate(db):
    columns={'users':{'group_name':"TEXT NOT NULL DEFAULT ''",'comment':"TEXT NOT NULL DEFAULT ''",'policy':"TEXT NOT NULL DEFAULT '{}'",'max_ips':'INTEGER NOT NULL DEFAULT 0','last_seen':'INTEGER NOT NULL DEFAULT 0','activated_at':'INTEGER NOT NULL DEFAULT 0','external_links':"TEXT NOT NULL DEFAULT ''",'external_cache':"TEXT NOT NULL DEFAULT ''"},
             'nodes':{'group_name':"TEXT NOT NULL DEFAULT ''",'comment':"TEXT NOT NULL DEFAULT ''"}}
    for table,fields in columns.items():
        existing={r[1] for r in db.execute('PRAGMA table_info('+table+')')}
        for key,definition in fields.items():
            if key not in existing:db.execute(f'ALTER TABLE {table} ADD COLUMN {key} {definition}')
    db.execute('CREATE TABLE IF NOT EXISTS client_ips (user_id TEXT REFERENCES users(id) ON DELETE CASCADE, ip TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, PRIMARY KEY(user_id,ip))')
    db.execute('CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY, timestamp INTEGER NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL)')

def audit(db,action,detail):
    db.execute('INSERT INTO audit_log(timestamp,action,detail) VALUES(?,?,?)',(int(time.time()),action,detail[:1000]))
    db.execute('DELETE FROM audit_log WHERE id NOT IN (SELECT id FROM audit_log ORDER BY id DESC LIMIT 2000)')

def bounded(raw,key,default=0,minimum=0,maximum=100000):
    try:value=int(raw.get(key,default) or default)
    except (ValueError,TypeError):raise ValueError(key+' 必须为整数')
    if not minimum<=value<=maximum:raise ValueError(f'{key} 必须在 {minimum}–{maximum} 之间')
    return value

def policy_input(raw,old=None):
    p=dict(old or {})
    for prefix in ('renew','reset'):
        mode=str(raw.get(prefix+'_mode','none'))
        if mode not in ('none','days','weekly','monthly'):raise ValueError('周期模式无效')
        new={prefix+'_mode':mode,prefix+'_days':bounded(raw,prefix+'_days',30,1,36500),
             prefix+'_day':bounded(raw,prefix+'_day',1,1,31),prefix+'_weekday':bounded(raw,prefix+'_weekday',1,1,7)}
        if any(p.get(k)!=v for k,v in new.items()):
            if prefix=='reset':p['next_reset']=0
            if prefix=='renew':p['renew_count']=0
        p.update(new)
    p['renew_limit']=bounded(raw,'renew_limit',0,0,100000)
    p['first_use_days']=bounded(raw,'first_use_days',0,0,36500)
    return p

def next_boundary(now,mode,days=30,day=1,weekday=1):
    if mode=='days':return int(now+days*DAY)
    current=datetime.fromtimestamp(now,timezone.utc)
    midnight=current.replace(hour=0,minute=0,second=0,microsecond=0)
    if mode=='weekly':
        delta=(weekday-1-current.weekday())%7
        target=midnight+timedelta(days=delta)
        if target.timestamp()<=now:target+=timedelta(days=7)
        return int(target.timestamp())
    if mode=='monthly':
        year,month=current.year,current.month
        for _ in range(2):
            target=midnight.replace(year=year,month=month,day=min(day,calendar.monthrange(year,month)[1]))
            if target.timestamp()>now:return int(target.timestamp())
            month+=1
            if month==13:year+=1;month=1
    return 0

def maintain(path,now=None):
    now=int(time.time() if now is None else now)
    with connect(path) as db:
        db.execute('BEGIN IMMEDIATE')
        for row in db.execute('SELECT * FROM users').fetchall():
            u=dict(row);p=json.loads(u['policy']);expires=u['expires'];reset=False;changed=False
            if u['enabled'] and (u['activated_at'] or not p.get('first_use_days')) and expires and expires<=now and p.get('renew_mode','none')!='none':
                count=p.get('renew_count',0);limit=p.get('renew_limit',0)
                # Catch up a fixed interval arithmetically; calendar loops are bounded by the allowed date range.
                if p['renew_mode']=='days':
                    needed=(now-expires)//(p['renew_days']*DAY)+1
                    granted=needed if not limit else min(needed,max(0,limit-count))
                    expires+=granted*p['renew_days']*DAY;count+=granted;changed=bool(granted)
                else:
                    for _ in range(12000):
                        if expires>now or (limit and count>=limit):break
                        expires=next_boundary(expires,p['renew_mode'],p['renew_days'],p['renew_day'],p['renew_weekday']);count+=1;changed=True
                if changed:
                    p['renew_count']=count
                    reset=expires>now
                    audit(db,'自动续期',u['name']+f'，累计 {count} 次')
            mode=p.get('reset_mode','none')
            if mode!='none' and u['enabled'] and not (p.get('first_use_days') and not u['activated_at']):
                due=p.get('next_reset',0)
                if not due:
                    p['next_reset']=next_boundary(now,mode,p['reset_days'],p['reset_day'],p['reset_weekday']);changed=True
                elif due<=now:
                    reset=True;changed=True
                    p['next_reset']=(due+((now-due)//(p['reset_days']*DAY)+1)*p['reset_days']*DAY) if mode=='days' else next_boundary(now,mode,p['reset_days'],p['reset_day'],p['reset_weekday'])
                    audit(db,'周期流量重置',u['name'])
            if changed:
                db.execute('UPDATE users SET policy=?,expires=?,upload=CASE WHEN ? THEN 0 ELSE upload END,download=CASE WHEN ? THEN 0 ELSE download END WHERE id=?',
                           (json.dumps(p),expires,reset,reset,u['id']))

def external_input(text):
    text=text.strip()
    if len(text)>32768:raise ValueError('外部订阅内容不能超过 32 KiB')
    lines=[line.strip() for line in text.splitlines() if line.strip()]
    if len(lines)>100:raise ValueError('外部链接不能超过 100 条')
    for line in lines:
        parsed=urlsplit(line)
        if parsed.scheme not in (*SCHEMES,'https','http'):raise ValueError('不支持的外部链接类型')
        if parsed.scheme in ('http','https') and (not parsed.hostname or parsed.username or parsed.password):raise ValueError('远程订阅地址无效')
    if sum(urlsplit(line).scheme in ('http','https') for line in lines)>5:raise ValueError('最多 5 个远程订阅地址')
    return '\n'.join(lines)

def refresh_external(text):
    result=[]
    for line in external_input(text).splitlines():
        if urlsplit(line).scheme in SCHEMES:result.append(line);continue
        with urlopen(Request(line,headers={'User-Agent':'sing-panel/1.0'}),timeout=5) as response:
            raw=response.read(262145)
        if len(raw)>262144:raise ValueError('远程订阅超过 256 KiB')
        content=raw.decode('utf-8').strip()
        if '://' not in content:
            try:content=base64.b64decode(content+'='*(-len(content)%4),validate=True).decode()
            except Exception:raise ValueError('远程订阅不是 URI 列表或 Base64 URI 列表')
        lines=[x.strip() for x in content.splitlines() if x.strip()]
        if any(urlsplit(x).scheme not in SCHEMES for x in lines):raise ValueError('远程订阅含不支持的节点格式')
        result.extend(lines)
    return '\n'.join(dict.fromkeys(result))

def presence(path,connections,close,now=None):
    now=int(time.time() if now is None else now);online={}
    with connect(path) as db:
        users={r['id']:dict(r) for r in db.execute('SELECT * FROM users')}
        for item in sorted(connections,key=lambda c:c.get('start','')):
            meta=item.get('metadata',{});tag=meta.get('inboundTag','');uid=meta.get('inboundUser','').rsplit(':',1)[-1]
            if not uid and ':' in tag:uid=tag.rsplit(':',1)[-1]
            if uid not in users:continue
            try:ip=str(ipaddress.ip_address(meta.get('sourceIP','')))
            except ValueError:continue
            entry=online.setdefault(uid,{'ips':[],'connections':0})
            if ip not in entry['ips']:
                if users[uid]['max_ips'] and len(entry['ips'])>=users[uid]['max_ips']:
                    close(item['id']);continue
                entry['ips'].append(ip)
            entry['connections']+=1
            db.execute('UPDATE users SET last_seen=? WHERE id=?',(now,uid))
            db.execute('INSERT INTO client_ips VALUES(?,?,?,?) ON CONFLICT(user_id,ip) DO UPDATE SET last_seen=excluded.last_seen',(uid,ip,now,now))
    return online
