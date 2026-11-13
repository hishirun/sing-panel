"""Local, online SQLite backups. Private data never enters public downloads."""
import json,os,re,sqlite3,tarfile,tempfile,threading,time
from datetime import datetime,timezone
from pathlib import Path
from contextlib import closing
from .core import connect
PATTERN=re.compile(r'^panel-\d{8}T\d{6}-[0-9a-f]{8}\.tar\.gz$')


def settings(path):
    result={'enabled':True,'interval_hours':24,'keep':7,'last_success':0,'last_error':''}
    with connect(path) as db:
        row=db.execute("SELECT value FROM settings WHERE key='automatic_backup'").fetchone()
    if row:result.update(json.loads(row[0]))
    return result


def save(path,raw):
    current=settings(path);interval=int(raw.get('interval_hours',24));keep=int(raw.get('keep',7))
    if interval not in (6,12,24) or not 1<=keep<=30:raise ValueError('备份间隔为 6、12 或 24 小时，保留 1–30 份')
    current.update(enabled=raw.get('enabled') in (True,'1','true','on'),interval_hours=interval,keep=keep)
    with connect(path) as db:db.execute("INSERT OR REPLACE INTO settings VALUES('automatic_backup',?)",(json.dumps(current),))


def listing(directory):
    folder=Path(directory)/'backups'/'automatic'
    if not folder.exists():return []
    files=[p for p in folder.glob('panel-*.tar.gz') if PATTERN.fullmatch(p.name) and p.is_file() and not p.is_symlink()]
    files.sort(key=lambda p:(p.stat().st_mtime_ns,p.name),reverse=True)
    return [{'name':p.name,'size':p.stat().st_size,'timestamp':int(p.stat().st_mtime)} for p in files]


class Manager:
    def __init__(self,path,directory):
        self.path=path;self.directory=Path(directory);self.lock=threading.Lock();self.event=threading.Event();self.thread=None

    def create(self):
        import secrets
        with self.lock:
            folder=self.directory/'backups'/'automatic';folder.mkdir(mode=0o700,parents=True,exist_ok=True)
            name=datetime.now(timezone.utc).strftime('panel-%Y%m%dT%H%M%S-')+secrets.token_hex(4)+'.tar.gz'
            target=folder/name;partial=folder/(name+'.part')
            try:
                with tempfile.TemporaryDirectory(dir=folder) as working:
                    snapshot=Path(working)/'panel.db'
                    with closing(sqlite3.connect(self.path,timeout=20)) as source, closing(sqlite3.connect(snapshot)) as dest:
                        source.backup(dest,pages=128,sleep=.01)
                    snapshot.chmod(0o600)
                    with tarfile.open(partial,'w:gz') as archive:
                        archive.add(snapshot,arcname='panel.db')
                        auth=self.directory/'auth.json'
                        if auth.is_file() and not auth.is_symlink():archive.add(auth,arcname='auth.json')
                        tls=self.directory/'tls'
                        if tls.is_dir() and not tls.is_symlink():
                            for path in tls.rglob('*'):
                                if path.is_file() and not path.is_symlink() and path.stat().st_size<=8*1024*1024:
                                    archive.add(path,arcname=str(path.relative_to(self.directory)))
                partial.chmod(0o600);partial.replace(target)
                current=settings(self.path);current.update(last_success=int(time.time()),last_error='')
                with connect(self.path) as db:db.execute("INSERT OR REPLACE INTO settings VALUES('automatic_backup',?)",(json.dumps(current),))
                # Some filesystems give rapid successive writes the same mtime.
                # Always retain the just-completed snapshot before older files.
                previous=[item for item in listing(self.directory) if item['name']!=name]
                for old in previous[max(0,current['keep']-1):]: (folder/old['name']).unlink()
                return name
            except Exception:
                partial.unlink(missing_ok=True)
                current=settings(self.path);current['last_error']='备份失败，请检查数据目录空间与权限'
                with connect(self.path) as db:db.execute("INSERT OR REPLACE INTO settings VALUES('automatic_backup',?)",(json.dumps(current),))
                raise

    def loop(self):
        while not self.event.is_set():
            try:
                s=settings(self.path)
                if s['enabled'] and time.time()-s['last_success']>=s['interval_hours']*3600:self.create()
            except Exception:
                import logging
                logging.getLogger(__name__).exception('automatic backup failed')
            self.event.wait(60)

    def start(self):
        self.event.clear();self.thread=threading.Thread(target=self.loop,daemon=True,name='local-backup');self.thread.start()

    def stop(self):
        self.event.set()
        if self.thread:self.thread.join(timeout=30)


def install(app,m):
    from fastapi import Request,HTTPException
    from fastapi.responses import FileResponse,RedirectResponse
    from starlette.concurrency import run_in_threadpool
    @app.get('/system/backups')
    def page(request:Request):
        m.authenticated(request)
        return m.render(request,'backups.html',backup=settings(m.DB),files=listing(m.DIRECTORY))
    @app.post('/system/backups/settings')
    async def configure(request:Request):
        m.authenticated(request);raw=await request.form();m.csrf(request,str(raw.get('token','')))
        try:save(m.DB,raw)
        except (ValueError,TypeError):raise HTTPException(422,'备份设置无效')
        return RedirectResponse('/system/backups',303)
    @app.post('/system/backups/create')
    async def create(request:Request):
        m.authenticated(request);raw=await request.form();m.csrf(request,str(raw.get('token','')))
        await run_in_threadpool(m.backup_manager.create)
        return RedirectResponse('/system/backups',303)
    @app.get('/system/backups/{name}/download')
    def download(request:Request,name:str):
        m.authenticated(request)
        if not PATTERN.fullmatch(name) or name not in {r['name'] for r in listing(m.DIRECTORY)}:raise HTTPException(404)
        return FileResponse(m.DIRECTORY/'backups'/'automatic'/name,filename=name,media_type='application/gzip',headers={'Cache-Control':'no-store'})
