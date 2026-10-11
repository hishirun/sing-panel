"""Time buckets and node series for a user's private traffic view."""
from datetime import datetime,timedelta,timezone
from .core import connect
PALETTE=['#9683ed','#4fa7b8','#da9655','#cb78a4','#6bad83','#759cd8','#c2a54e','#9d879b']
def traffic_view(path,user_id,nodes,period='7d',now=None):
    period=period if period in ('24h','7d','30d') else '7d'
    now=now or datetime.now(timezone.utc)
    hourly=period=='24h';count=24 if hourly else 7 if period=='7d' else 30
    end=now.replace(minute=0,second=0,microsecond=0) if hourly else now.replace(hour=0,minute=0,second=0,microsecond=0)
    fmt='%Y-%m-%dT%H:00' if hourly else '%Y-%m-%d'
    keys=[(end-timedelta(hours=i) if hourly else end-timedelta(days=i)).strftime(fmt) for i in range(count-1,-1,-1)]
    with connect(path) as db:
        if hourly:
            records=[dict(r) for r in db.execute('SELECT hour bucket,node_id,SUM(upload) upload,SUM(download) download FROM node_hourly WHERE user_id=? AND hour>=? AND hour<=? GROUP BY hour,node_id',(user_id,keys[0],keys[-1]))]
            totals={}
            for r in records:
                t=totals.setdefault(r['bucket'],{'upload':0,'download':0});t['upload']+=r['upload'];t['download']+=r['download']
        else:
            records=[dict(r) for r in db.execute('SELECT day bucket,node_id,upload,download FROM node_daily WHERE user_id=? AND day>=? AND day<=?',(user_id,keys[0],keys[-1]))]
            totals={r['day']:dict(r) for r in db.execute('SELECT day,upload,download FROM daily WHERE user_id=? AND day>=? AND day<=?',(user_id,keys[0],keys[-1]))}
        names={r['node_id']:r['node_name'] for r in db.execute('SELECT node_id,node_name FROM node_daily WHERE user_id=? GROUP BY node_id',(user_id,))}
    names.update({n['id']:n['name'] for n in nodes})
    series=[dict(id=nid,name=name,color=PALETTE[i%len(PALETTE)],total=0,upload=0,download=0) for i,(nid,name) in enumerate(sorted(names.items()))]
    series.append(dict(id='',name='历史未归属',color='#8993a5',total=0,upload=0,download=0))
    indexed={(r['bucket'],r['node_id']):r for r in records}
    rows=[]
    for key in keys:
        t=totals.get(key,{'upload':0,'download':0});parts=[];up=down=0
        for node in series[:-1]:
            r=indexed.get((key,node['id']),{'upload':0,'download':0});u=r['upload'];d=r['download'];up+=u;down+=d
            parts.append(dict(name=node['name'],color=node['color'],upload=u,download=d,total=u+d))
        parts.append(dict(name='历史未归属',color=series[-1]['color'],upload=max(0,t['upload']-up),download=max(0,t['download']-down),total=max(0,t['upload']-up)+max(0,t['download']-down)))
        for node,r in zip(series,parts):
            for k in ('upload','download','total'):node[k]+=r[k]
        rows.append(dict(day=key,label=key[11:13]+':00' if hourly else key[5:],upload=t['upload'],download=t['download'],total=t['upload']+t['download'],parts=parts))
    if not series[-1]['total']:
        series.pop()
        for r in rows:r['parts'].pop()
    return dict(period=period,label={'24h':'24 小时','7d':'7 天','30d':'30 天'}[period],hourly=hourly,rows=rows,series=series,maximum=max([r['total'] for r in rows],default=0) or 1,total=sum(r['total'] for r in rows))
