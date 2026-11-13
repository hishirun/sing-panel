"""Public code artifacts only. Enrollment and control use separate credentials."""
import gzip,hashlib,io,json,os,tarfile,threading
from pathlib import Path
from fastapi import HTTPException
from fastapi.responses import FileResponse,Response
_lock=threading.Lock()


def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()


def install(app,m):
    root=Path(__file__).resolve().parent.parent
    cache={}
    def bundle():
        source=[p for p in (root/'agent').rglob('*') if p.is_file() and p.suffix in ('.py','.txt') and '__pycache__' not in p.parts]
        source.append(root/'deploy'/'sing-panel-agent.service')
        if not source or not all(p.is_file() for p in source):raise HTTPException(503,'Agent 安装包尚未准备完成')
        stamp=tuple((str(p),p.stat().st_mtime_ns,p.stat().st_size) for p in sorted(source))
        with _lock:
            if cache.get('stamp')!=stamp:
                folder=m.DIRECTORY/'agent-artifacts';folder.mkdir(mode=0o700,exist_ok=True)
                target=folder/'bundle.tar.gz';tmp=target.with_suffix('.tmp')
                with tmp.open('wb') as raw, gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as compressed, tarfile.open(fileobj=compressed,mode='w') as tar:
                    for path in sorted(source):
                        data=path.read_bytes();info=tarfile.TarInfo(str(path.relative_to(root)));info.size=len(data);info.mode=0o644;info.mtime=0
                        tar.addfile(info,io.BytesIO(data))
                tmp.chmod(0o600);tmp.replace(target)
                cache.update(stamp=stamp,bundle=target,bundle_hash=digest(target))
        return cache['bundle']
    def core(arch):
        if arch not in ('linux-amd64','linux-arm64'):raise HTTPException(404)
        path=Path(os.environ.get('PANEL_AGENT_CORES',str(root/'agent-cores')))/('sing-box-'+arch)
        if not path.is_file():raise HTTPException(503,'尚未提供该架构的核心安装包')
        return path
    @app.get('/agent/install.sh')
    def installer():
        path=root/'deploy'/'install-agent.sh'
        if not path.is_file():raise HTTPException(503)
        return FileResponse(path,media_type='text/x-shellscript',headers={'Cache-Control':'no-store'})
    @app.get('/agent/manifest.json')
    def manifest():
        from agent import __version__
        bundle();cores={}
        for arch in ('linux-amd64','linux-arm64'):
            try:path=core(arch)
            except HTTPException:continue
            key=(str(path),path.stat().st_mtime_ns,path.stat().st_size)
            if key not in cache:cache[key]=digest(path)
            cores[arch]={'url':'/agent/core/'+arch,'sha256':cache[key]}
        return {'version':__version__,'bundle':{'url':'/agent/bundle.tar.gz','sha256':cache['bundle_hash']},'cores':cores}
    @app.get('/agent/bundle.tar.gz')
    def package():return FileResponse(bundle(),filename='sing-panel-agent.tar.gz',media_type='application/gzip',headers={'Cache-Control':'no-store'})
    @app.get('/agent/core/{arch}')
    def binary(arch:str):return FileResponse(core(arch),filename='sing-box-'+arch,media_type='application/octet-stream')
