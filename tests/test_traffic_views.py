from datetime import datetime,timezone
from panel.core import init_db,connect
from panel.traffic import traffic_view

def test_period_buckets_node_totals_and_privacy(tmp_path):
    p=tmp_path/'db';init_db(p)
    with connect(p) as db:
        db.execute("INSERT INTO node_daily VALUES('2026-10-11','u','n','Node',100,200)")
        db.execute("INSERT INTO daily VALUES('2026-10-11','u',150,250)")
        db.execute("INSERT INTO daily VALUES('2026-10-01','u',1,2)")
        db.execute("INSERT INTO node_hourly VALUES('2026-10-11T01:00','u','n',10,20)")
        db.execute("INSERT INTO node_hourly VALUES('2026-10-10T23:00','u','n',30,40)")
        db.execute("INSERT INTO node_hourly VALUES('2026-10-09T23:00','u','n',900,900)")
        db.execute("INSERT INTO node_hourly VALUES('2026-10-11T01:00','other','n',900,900)")
    now=datetime(2026,10,11,1,30,tzinfo=timezone.utc)
    v=traffic_view(p,'u',[], '24h',now)
    assert len(v['rows'])==24 and v['total']==100
    assert v['rows'][-1]['total']==30
    assert sum(n['total'] for n in v['series'])==v['total']
    v=traffic_view(p,'u',[],'7d',now)
    assert len(v['rows'])==7 and v['total']==400
    assert v['series'][-1]['name']=='历史未归属' and v['series'][-1]['total']==100
    v=traffic_view(p,'u',[],'30d',now)
    assert len(v['rows'])==30 and v['total']==403
    assert traffic_view(p,'u',[],'invalid',now)['period']=='7d'
    assert traffic_view(p,'nobody',[],'24h',now)['total']==0
