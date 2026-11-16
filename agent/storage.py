"""Durable private files and cumulative traffic reports."""
import json
import os
import sqlite3
import tempfile
import time
import uuid
from pathlib import Path


class SpoolConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(value, output, ensure_ascii=False, separators=(',', ':'))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return default


class Spool:
    """Durable hourly cumulative snapshots with frozen in-flight batches.

    An ACK deletes only its exact report ID. Checkpoints keep each epoch's
    cumulative baseline and next sequence after acknowledged rows are removed.
    Legacy v1 rows are drained first without inventing missing sample times.
    """

    def __init__(self, directory):
        self.path = Path(directory) / 'reports.sqlite'
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS reports (epoch TEXT PRIMARY KEY, '
                       'report_id TEXT UNIQUE NOT NULL, counters TEXT NOT NULL, created REAL NOT NULL)')
            db.executescript('''CREATE TABLE IF NOT EXISTS timed_reports (report_id TEXT PRIMARY KEY,epoch TEXT NOT NULL,sequence INTEGER NOT NULL,bucket INTEGER NOT NULL,observed_at INTEGER NOT NULL,counters TEXT NOT NULL,sealed INTEGER NOT NULL DEFAULT 0, UNIQUE(epoch,sequence));
                CREATE TABLE IF NOT EXISTS checkpoints (epoch TEXT PRIMARY KEY,sequence INTEGER NOT NULL,observed_at INTEGER NOT NULL,counters TEXT NOT NULL);''')
        self.path.chmod(0o600)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=15, factory=SpoolConnection)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('PRAGMA synchronous=FULL')
        except Exception:
            db.close()
            raise
        return db

    def store(self, epoch, counters, observed_at=None):
        if not isinstance(epoch,str) or not epoch or len(epoch)>128:
            raise ValueError('Invalid statistics epoch')
        if not isinstance(counters,dict) or any(not isinstance(k,str) or isinstance(v,bool) or not isinstance(v,int) or not 0<=v<=2**63-1 for k,v in counters.items()):
            raise ValueError('Invalid traffic counters')
        observed=int(time.time() if observed_at is None else observed_at)
        bucket=observed//3600
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            checkpoint=db.execute('SELECT * FROM checkpoints WHERE epoch=?',(epoch,)).fetchone()
            legacy=db.execute('SELECT * FROM reports WHERE epoch=?',(epoch,)).fetchone()
            previous=json.loads(checkpoint['counters']) if checkpoint else json.loads(legacy['counters']) if legacy else {}
            merged={**previous,**counters}
            if any(merged[k]<v for k,v in previous.items()):raise ValueError('Statistics regressed within one epoch')
            if checkpoint and observed<checkpoint['observed_at']:
                # A wall-clock correction must not move queued traffic backwards.
                observed=checkpoint['observed_at'];bucket=observed//3600
            latest=db.execute('SELECT * FROM timed_reports WHERE epoch=? ORDER BY sequence DESC LIMIT 1',(epoch,)).fetchone()
            if checkpoint and merged==previous:
                return latest['report_id'] if latest else None
            payload=json.dumps(merged,separators=(',',':'))
            if len(payload.encode())>3*1024*1024:raise ValueError('Traffic report exceeds the supported size')
            sequence=latest['sequence'] if latest and latest['bucket']==bucket and not latest['sealed'] else (checkpoint['sequence']+1 if checkpoint else 1)
            report_id=uuid.uuid4().hex
            if latest and latest['bucket']==bucket and not latest['sealed']:
                db.execute('UPDATE timed_reports SET report_id=?,observed_at=?,counters=? WHERE report_id=?',(report_id,observed,payload,latest['report_id']))
            else:
                db.execute('INSERT INTO timed_reports(report_id,epoch,sequence,bucket,observed_at,counters) VALUES(?,?,?,?,?,?)',(report_id,epoch,sequence,bucket,observed,payload))
            db.execute('INSERT OR REPLACE INTO checkpoints VALUES(?,?,?,?)',(epoch,sequence,observed,payload))
            return report_id

    def oldest(self):
        with self.connect() as db:
            # Existing v1 snapshots must be drained before new timestamped ones.
            row=db.execute('SELECT * FROM reports ORDER BY created,epoch LIMIT 1').fetchone()
            if row:return {'report_id':row['report_id'],'epoch':row['epoch'],'counters':json.loads(row['counters'])}
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM timed_reports ORDER BY observed_at,rowid LIMIT 1').fetchone()
            if row:db.execute('UPDATE timed_reports SET sealed=1 WHERE report_id=?',(row['report_id'],))
        return {'report_id':row['report_id'],'epoch':row['epoch'],'counters':json.loads(row['counters']),
                'sequence':row['sequence'],'observed_at':row['observed_at'],'accounting_version':2} if row else None

    def acknowledge(self,report_id):
        with self.connect() as db:
            db.execute('DELETE FROM reports WHERE report_id=?',(report_id,))
            db.execute('DELETE FROM timed_reports WHERE report_id=?',(report_id,))

    def count(self):
        with self.connect() as db:return db.execute('SELECT (SELECT COUNT(*) FROM reports)+(SELECT COUNT(*) FROM timed_reports)').fetchone()[0]

    def summary(self):
        with self.connect() as db:
            row=db.execute('SELECT COUNT(*) count,MIN(observed_at) oldest FROM timed_reports').fetchone()
            legacy=db.execute('SELECT COUNT(*) FROM reports').fetchone()[0]
        return {'pending_reports':row['count']+legacy,'oldest_report_at':row['oldest'] or 0}
