"""Configurable public entry paths; route names stay stable internally."""
import re
from urllib.parse import urlsplit,urlunsplit
from starlette.responses import Response
from .sharing import read_settings

def validate_paths(admin, share):
    def check(value, allow_root=False):
        value=str(value).strip().rstrip('/')
        if allow_root and not value:return ''
        if not re.fullmatch(r'/[A-Za-z0-9_-]{3,64}',value):
            raise ValueError('路径须为 / 开头的 3–64 位字母、数字、下划线或短横线；管理路径 / 表示根目录')
        if value in ('/static','/health','/login','/logout','/users','/nodes','/settings','/system','/routing'):
            raise ValueError('此路径为系统保留路径')
        return value
    admin=check(admin,True);share='/s' if str(share).strip().rstrip('/')=='/s' else check(share)
    if admin==share:raise ValueError('管理路径与分享路径不能相同')
    return admin,share

class EntryPaths:
    def __init__(self,app,db):self.app=app;self.db=db
    async def __call__(self,scope,receive,send):
        if scope['type']!='http':return await self.app(scope,receive,send)
        settings=read_settings(self.db);admin=settings['admin_path'];share=settings['share_path']
        path=scope['path'];internal=None
        if path=='/health' or path.startswith('/static/'):internal=path
        elif path.startswith(share+'/'):internal='/s/'+path[len(share)+1:]
        elif admin and (path==admin or path.startswith(admin+'/')):internal=path[len(admin):] or '/'
        elif not admin and not path.startswith('/s/'):internal=path
        if internal is None:
            return await Response(status_code=404)(scope,receive,send)
        # The management prefix must never expose the old share namespace.
        if internal.startswith('/s/') and not path.startswith(share+'/'):
            return await Response(status_code=404)(scope,receive,send)
        scope=dict(scope,path=internal,raw_path=internal.encode())
        async def mapped_send(message):
            if message['type']=='http.response.start':
                current=read_settings(self.db)
                headers=[]
                for key,value in message['headers']:
                    if key.lower()==b'location':
                        target=value.decode('latin1')
                        parsed=urlsplit(target)
                        absolute=bool(parsed.netloc)
                        host=dict(scope.get('headers',[])).get(b'host',b'').decode('latin1')
                        local=not absolute or parsed.netloc==host
                        if absolute and local:target=parsed.path+('?' + parsed.query if parsed.query else '')
                        if local and target.startswith('/s/'):target=current['share_path']+target[2:]
                        elif local and target.startswith('/') and not target.startswith('//'):target=current['admin_path']+target
                        if absolute and local:
                            rewritten=urlsplit(target)
                            target=urlunsplit((parsed.scheme,parsed.netloc,rewritten.path,rewritten.query,parsed.fragment))
                        value=target.encode('latin1')
                    headers.append((key,value))
                message=dict(message,headers=headers)
            await send(message)
        await self.app(scope,receive,mapped_send)
