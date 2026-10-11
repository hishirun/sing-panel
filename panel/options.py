"""Validated node options supported by the pinned sing-box 1.14.3 core."""
import base64
import ipaddress
import json
import re
import socket
import ssl
import time
from typing import Literal
from pydantic import BaseModel, Field, field_validator

PRESETS = ('www.cloudflare.com', 'www.microsoft.com', 'www.apple.com')
FINGERPRINTS = ('chrome','firefox','edge','safari','ios','android','360','qq','random','randomized')

def domain(value):
    value=value.strip().lower().rstrip('.')
    if not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',value):
        raise ValueError('请输入有效域名，不含协议、路径或端口')
    return value

class NodeOptions(BaseModel):
    listen: str = '::'
    tcp_fast_open: bool = False
    tcp_multi_path: bool = False
    disable_tcp_keep_alive: bool = False
    keep_alive: int = Field(300,ge=1,le=86400)
    keep_alive_interval: int = Field(75,ge=1,le=3600)
    snell_mode: Literal['default','unshaped','unsafe-raw'] = 'default'
    reuse: bool = False
    network: Literal['both','tcp','udp'] = 'both'
    obfs_mode: Literal['none','http'] = 'none'
    obfs_host: str = ''
    handshake_host: str = ''
    handshake_port: int = Field(443,ge=1,le=65535)
    handshake_timeout: int = Field(15,ge=1,le=120)
    max_time_difference: int = Field(0,ge=0,le=86400)
    fingerprint: Literal['chrome','firefox','edge','safari','ios','android','360','qq','random','randomized'] = 'chrome'
    flow: Literal['xtls-rprx-vision',''] = 'xtls-rprx-vision'
    short_ids: str = ''
    alpn: str = ''

    @field_validator('listen')
    @classmethod
    def valid_listen(cls,v):
        return str(ipaddress.ip_address(v.strip()))

    @field_validator('handshake_host')
    @classmethod
    def valid_handshake(cls,v):
        if not v.strip():return ''
        try:return str(ipaddress.ip_address(v.strip()))
        except ValueError:return domain(v)

    @field_validator('short_ids')
    @classmethod
    def valid_short_ids(cls,v):
        values=list(dict.fromkeys(x.strip().lower() for x in v.split(',') if x.strip()))
        if len(values)>16 or any(not re.fullmatch(r'(?:[0-9a-f]{2}){1,8}',x) for x in values):
            raise ValueError('Short ID 必须为 2–16 位偶数长度十六进制，最多 16 个，逗号分隔')
        return ','.join(values)

    @field_validator('alpn')
    @classmethod
    def valid_alpn(cls,v):
        values=list(dict.fromkeys(x.strip() for x in v.split(',') if x.strip()))
        if any(x not in ('h2','http/1.1') for x in values):
            raise ValueError('Reality ALPN 可填写 h2、http/1.1，或留空跟随握手')
        return ','.join(values)

    @field_validator('obfs_host')
    @classmethod
    def valid_obfs(cls,v):
        return domain(v) if v.strip() else ''


def options(node):
    raw=node.get('options','{}')
    return NodeOptions.model_validate(json.loads(raw) if isinstance(raw,str) else raw).model_dump()


def listen_options(node):
    o=options(node)
    result={'listen':o['listen'], 'tcp_fast_open':o['tcp_fast_open'],
            'tcp_multi_path':o['tcp_multi_path'], 'disable_tcp_keep_alive':o['disable_tcp_keep_alive'],
            'tcp_keep_alive':f"{o['keep_alive']}s", 'tcp_keep_alive_interval':f"{o['keep_alive_interval']}s"}
    if o['disable_tcp_keep_alive']:
        result.pop('tcp_keep_alive');result.pop('tcp_keep_alive_interval')
    return result


def snell_options(node):
    o=options(node)
    return {'mode':o['snell_mode']} if node['protocol']=='snell6' else {'obfs_mode':o['obfs_mode']}


def reality_tls(node,client=False):
    o=options(node)
    ids=o['short_ids'].split(',') if o['short_ids'] else [node['short_id']]
    tls={'enabled':True,'server_name':node['server_name']}
    if o['alpn']:tls['alpn']=o['alpn'].split(',')
    if client:
        tls['utls']={'enabled':True,'fingerprint':o['fingerprint']}
        tls['reality']={'enabled':True,'public_key':node['public_key'],'short_id':ids[0]}
    else:
        tls['handshake_timeout']=f"{o['handshake_timeout']}s"
        tls['reality']={'enabled':True,'handshake':{
            'server':o['handshake_host'] or node['server_name'],'server_port':o['handshake_port']},
            'private_key':node['private_key'],'short_id':ids}
        if o['max_time_difference']:
            tls['reality']['max_time_difference']=f"{o['max_time_difference']}s"
    return tls


def import_key(private):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    try:
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}',private):raise ValueError()
        raw=base64.urlsafe_b64decode(private+'=')
        key=X25519PrivateKey.from_private_bytes(raw)
        public=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        return private,base64.urlsafe_b64encode(public).decode().rstrip('=')
    except ValueError:
        raise ValueError('Reality 私钥必须是 43 字符的 URL-safe base64 X25519 私钥')


def probe_tls(host,port,sni):
    """Administrative connectivity check; not a promise of censorship resistance."""
    started=time.monotonic()
    context=ssl.create_default_context()
    context.minimum_version=ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['h2','http/1.1'])
    try:
        with socket.create_connection((host,port),timeout=5) as sock:
            with context.wrap_socket(sock,server_hostname=sni) as tls:
                return f"TLS {tls.version()} · ALPN {tls.selected_alpn_protocol() or '未协商'} · {round((time.monotonic()-started)*1000)} ms；证书与 SNI 校验通过"
    except (OSError,ValueError) as e:
        raise ValueError(f'握手检测失败：{e}')
