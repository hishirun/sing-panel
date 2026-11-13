"""Per-machine NIC traffic quotas, independent of proxy user accounting."""
import json,time
from datetime import datetime,timedelta,timezone
from .core import connect
TZ=timezone(timedelta(hours=8))


def migrate(db):
    db.execute('CREATE TABLE IF NOT EXISTS machine_counters (server_id TEXT PRIMARY KEY,boot_id TEXT NOT NULL,uptime REAL NOT NULL,sampled_at REAL NOT NULL,interfaces TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS machine_monthly (server_id TEXT NOT NULL,cycle TEXT NOT NULL,rx INTEGER NOT NULL DEFAULT 0,tx INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(server_id,cycle))')


def cycle(now,day=1):
    current=datetime.fromtimestamp(now,TZ)
    start=current.replace(day=day,hour=0,minute=0,second=0,microsecond=0)
    if start>current:
        start=(start.replace(day=1)-timedelta(days=1)).replace(day=day)
    end=(start.replace(day=28)+timedelta(days=4)).replace(day=day)
    return start.strftime('%Y-%m-%d'),int(end.timestamp())


def policy(db,server_id):
    if server_id=='local':
        row=db.execute("SELECT value FROM settings WHERE key='server_quota:local'").fetchone()
        value=json.loads(row[0]) if row else {}
    else:
        row=db.execute('SELECT monthly_quota,traffic_direction,reset_day FROM servers WHERE id=?',(server_id,)).fetchone()
        value=dict(row) if row else {}
    return {'quota':max(0,int(value.get('monthly_quota',0))), 'direction':value.get('traffic_direction','both'), 'reset_day':max(1,min(28,int(value.get('reset_day',1))))}


def summary(path,server_id,now=None):
    now=time.time() if now is None else now
    with connect(path) as db:
        p=policy(db,server_id);key,next_reset=cycle(now,p['reset_day'])
        row=db.execute('SELECT rx,tx FROM machine_monthly WHERE server_id=? AND cycle=?',(server_id,key)).fetchone()
    rx,tx=(row['rx'],row['tx']) if row else (0,0)
    used=rx if p['direction']=='rx' else tx if p['direction']=='tx' else rx+tx
    return {**p,'cycle_start':key,'next_reset':next_reset,'rx':rx,'tx':tx,'used':used,'blocked':bool(p['quota'] and used>=p['quota'])}


def record(path,server_id,metrics):
    """The first observation is a baseline, not all traffic since boot.

    Duplicate/old reports are ignored. NIC resets and machine reboots start a
    new counter epoch. Deltas spanning a cycle are assigned to the later
    sample; hence offline boundary attribution is approximate, not a billing
    provider's authoritative usage meter.
    """
    stamp=metrics.get('sampled_at');uptime=metrics.get('uptime');boot=metrics.get('boot_id')
    if not isinstance(stamp,(int,float)) or isinstance(stamp,bool) or not 0<stamp<=time.time()+120 or not isinstance(uptime,(int,float)) or not isinstance(boot,str) or not boot or len(boot)>128:
        return summary(path,server_id)
    interfaces={}
    for row in metrics.get('interfaces',[])[:128]:
        if not isinstance(row,dict) or not row.get('billable'):continue
        name=row.get('name');rx=row.get('rx_total');tx=row.get('tx_total')
        if not isinstance(name,str) or not 1<=len(name)<=64:continue
        if any(isinstance(v,bool) or not isinstance(v,int) or not 0<=v<=2**63-1 for v in (rx,tx)):continue
        interfaces[name]=[rx,tx]
    if not interfaces:return summary(path,server_id)
    with connect(path) as db:
        db.execute('BEGIN IMMEDIATE')
        old=db.execute('SELECT * FROM machine_counters WHERE server_id=?',(server_id,)).fetchone()
        if old and stamp<=old['sampled_at']:
            return summary(path,server_id)
        previous=json.loads(old['interfaces']) if old else {}
        rx=tx=0
        if old:
            for name,(received,sent) in interfaces.items():
                if old['boot_id']!=boot:
                    # New boot counters are all newer than the saved baseline.
                    rx+=received;tx+=sent
                elif name in previous:
                    a,b=previous[name]
                    rx+=received-a if received>=a else received
                    tx+=sent-b if sent>=b else sent
                # A newly discovered interface gets its own baseline.
        p=policy(db,server_id);key,_=cycle(stamp,p['reset_day'])
        db.execute('INSERT INTO machine_monthly VALUES(?,?,?,?) ON CONFLICT(server_id,cycle) DO UPDATE SET rx=rx+excluded.rx,tx=tx+excluded.tx',(server_id,key,rx,tx))
        db.execute('INSERT OR REPLACE INTO machine_counters VALUES(?,?,?,?,?)',(server_id,boot,uptime,stamp,json.dumps(interfaces)))
    return summary(path,server_id)
