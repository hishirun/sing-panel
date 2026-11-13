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
    """One durable, monotonically increasing cumulative report per core epoch.

    A sampling update replaces the report ID. An acknowledgement for an older
    in-flight snapshot therefore cannot delete newer counters from that epoch.
    Epochs survive agent restarts, and are drained oldest-first after reconnect.
    """

    def __init__(self, directory):
        self.path = Path(directory) / 'reports.sqlite'
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS reports (epoch TEXT PRIMARY KEY, '
                       'report_id TEXT UNIQUE NOT NULL, counters TEXT NOT NULL, created REAL NOT NULL)')
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

    def store(self, epoch, counters):
        if not isinstance(epoch, str) or not epoch or len(epoch) > 128:
            raise ValueError('Invalid statistics epoch')
        if not isinstance(counters, dict) or any(not isinstance(k, str) or
                isinstance(v, bool) or not isinstance(v, int) or v < 0 for k, v in counters.items()):
            raise ValueError('Invalid traffic counters')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM reports WHERE epoch=?', (epoch,)).fetchone()
            previous = json.loads(row['counters']) if row else {}
            # Statistics may omit a zero/idle key; never discard an earlier key.
            merged = {**previous, **counters}
            if any(merged[k] < v for k, v in previous.items()):
                raise ValueError('Statistics regressed within one epoch')
            if row and merged == previous:
                return row['report_id']
            payload = json.dumps(merged, separators=(',', ':'))
            if len(payload.encode()) > 3 * 1024 * 1024:
                raise ValueError('Traffic report exceeds the supported size')
            report_id = uuid.uuid4().hex
            db.execute('INSERT OR REPLACE INTO reports VALUES(?,?,?,?)',
                       (epoch, report_id, payload, row['created'] if row else time.time()))
            return report_id

    def oldest(self):
        with self.connect() as db:
            row = db.execute('SELECT * FROM reports ORDER BY created,epoch LIMIT 1').fetchone()
        return {'report_id': row['report_id'], 'epoch': row['epoch'],
                'counters': json.loads(row['counters'])} if row else None

    def acknowledge(self, report_id):
        with self.connect() as db:
            db.execute('DELETE FROM reports WHERE report_id=?', (report_id,))

    def count(self):
        with self.connect() as db:
            return db.execute('SELECT COUNT(*) FROM reports').fetchone()[0]
