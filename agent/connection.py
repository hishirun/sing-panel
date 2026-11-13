"""Controller-origin validation and bounded HTTPS downloads."""
import json
import ssl
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Controller redirects are not accepted')


def origin(value, allow_local=False):
    parsed = urlsplit(value)
    local = allow_local and parsed.hostname in ('127.0.0.1', 'localhost', '::1')
    if parsed.scheme != 'https' and not (local and parsed.scheme == 'http'):
        raise ValueError('主控地址必须使用 HTTPS')
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        raise ValueError('主控地址不能包含路径、账号或查询参数')
    try:
        parsed.port
    except ValueError:
        raise ValueError('主控地址端口无效') from None
    return parsed.scheme + '://' + parsed.netloc


def request(panel, path, payload=None, maximum=4 * 1024 * 1024, timeout=30, allow_local=False):
    panel = origin(panel, allow_local)
    if not path.startswith('/agent/') or path.startswith('//') or any(x in path for x in ('?', '#', '..')):
        raise ValueError('Invalid agent endpoint')
    data = json.dumps(payload).encode() if payload is not None else None
    req = Request(panel + path, data=data, headers={'Content-Type': 'application/json', 'User-Agent': 'SingBox-Panel-Agent/0.1'})
    opener = build_opener(NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
    deadline = time.monotonic() + timeout
    with opener.open(req, timeout=timeout) as response:
        contents = bytearray()
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError('Controller response deadline exceeded')
            chunk = response.read1(min(65536, maximum + 1 - len(contents)))
            if not chunk:
                break
            contents.extend(chunk)
            if len(contents) > maximum:
                raise ValueError('Controller response exceeds its size limit')
    return bytes(contents)
