"""Validated node options supported by the pinned sing-box 1.14.3 core."""
import base64
import ipaddress
import json
import re
import socket
import ssl
import time
from typing import Literal
from pydantic import BaseModel, Field, field_validator, model_validator

PRESETS = ('www.cloudflare.com', 'www.microsoft.com', 'www.apple.com')
FINGERPRINTS = ('chrome','firefox','edge','safari','ios','android','360','qq','random','randomized')

def domain(value):
    value=value.strip().lower().rstrip('.')
    if not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',value):
        raise ValueError('请输入有效域名，不含协议、路径或端口')
    return value

class NodeOptions(BaseModel):
    ss_method: Literal['aes-128-gcm','aes-256-gcm','chacha20-ietf-poly1305','2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','2022-blake3-chacha20-poly1305'] = 'chacha20-ietf-poly1305'
    trojan_transport: Literal['tcp','ws','grpc'] = 'tcp'
    ws_path: str = Field('/',max_length=2048)
    ws_host: str = ''
    grpc_service_name: str = Field('GunService',max_length=128)
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

    connect_host: str = ''
    certificate_path: str = ''
    key_path: str = ''
    tls_min_version: Literal['1.2','1.3'] = '1.3'
    tls_alpn: str = ''
    hy_up_mbps: int = Field(0,ge=0,le=100000)
    hy_down_mbps: int = Field(0,ge=0,le=100000)
    hy_client_up_mbps: int = Field(0,ge=0,le=100000)
    hy_client_down_mbps: int = Field(0,ge=0,le=100000)
    hy_ignore_client_bandwidth: bool = False
    hy_bbr_profile: Literal['standard','conservative','aggressive'] = 'standard'
    hy_obfs: Literal['none','salamander','gecko'] = 'none'
    hy_obfs_password: str = Field('',max_length=255)
    hy_gecko_min: int = Field(512,ge=512,le=1500)
    hy_gecko_max: int = Field(1200,ge=512,le=1500)
    hy_masquerade: str = Field('',max_length=2048)
    hy_initial_packet_size: int = Field(1200,ge=1200,le=1452)
    hy_disable_mtu_discovery: bool = False
    any_padding: str = Field('',max_length=4096)
    any_idle_check: int = Field(30,ge=1,le=3600)
    any_idle_timeout: int = Field(30,ge=1,le=3600)
    any_min_idle: int = Field(0,ge=0,le=128)

    @field_validator('ws_path')
    @classmethod
    def valid_ws_path(cls,v):
        if not v.startswith('/') or any(ord(c)<33 for c in v) or '#' in v:raise ValueError('WebSocket 路径须以 / 开头，不能含空白或片段')
        return v

    @field_validator('ws_host')
    @classmethod
    def valid_ws_host(cls,v):
        if not v.strip():return ''
        try:return str(ipaddress.ip_address(v.strip()))
        except ValueError:return domain(v)

    @field_validator('grpc_service_name')
    @classmethod
    def valid_grpc_service(cls,v):
        if not re.fullmatch(r'[A-Za-z0-9._/-]{1,128}',v):raise ValueError('gRPC 服务名仅支持字母、数字及 . _ / -')
        return v

    @field_validator('connect_host')
    @classmethod
    def valid_connect_host(cls,v):
        if not v.strip():return ''
        try:return str(ipaddress.ip_address(v.strip()))
        except ValueError:return domain(v)

    @field_validator('certificate_path','key_path')
    @classmethod
    def valid_tls_path(cls,v):
        v=v.strip()
        if v and (not v.startswith('/') or any(x in v for x in ('\n','\r','\x00'))):raise ValueError('证书路径须为绝对路径')
        return v

    @field_validator('tls_alpn')
    @classmethod
    def valid_tls_alpn(cls,v):
        values=list(dict.fromkeys(x.strip() for x in v.split(',') if x.strip()))
        if any(not re.fullmatch(r'[A-Za-z0-9./_-]{1,32}',x) for x in values):raise ValueError('ALPN 格式无效')
        return ','.join(values)

    @field_validator('hy_masquerade')
    @classmethod
    def valid_masquerade(cls,v):
        from urllib.parse import urlsplit
        if not v.strip():return ''
        u=urlsplit(v.strip())
        if u.scheme not in ('http','https') or not u.hostname or u.username or u.password or u.fragment:raise ValueError('伪装地址须为 http(s) URL')
        return v.strip()

    @model_validator(mode='after')
    def valid_tls_options(self):
        if self.hy_gecko_min>self.hy_gecko_max:raise ValueError('Gecko 最小包长度不能大于最大值')
        if self.hy_obfs!='none' and len(self.hy_obfs_password)<8:raise ValueError('QUIC 混淆密码至少 8 字符')
        if self.hy_ignore_client_bandwidth and (self.hy_up_mbps or self.hy_down_mbps):raise ValueError('忽略客户端带宽时，服务端带宽上限请填 0')
        return self

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
                return f"{tls.version()} · ALPN {tls.selected_alpn_protocol() or '未协商'} · {round((time.monotonic()-started)*1000)} ms；证书与 SNI 校验通过"
    except (OSError,ValueError) as e:
        raise ValueError(f'握手检测失败：{e}')


def certificate_tls(node,client=False):
    o=options(node)
    tls={'enabled':True,'server_name':node['server_name'],'min_version':o['tls_min_version']}
    alpn=o['tls_alpn'] or ('h3' if node['protocol']=='hysteria2' else '')
    if alpn:tls['alpn']=alpn.split(',')
    if not client:tls.update(certificate_path=o['certificate_path'],key_path=o['key_path'])
    return tls


def hysteria_options(node,client=False):
    o=options(node)
    out={'bbr_profile':o['hy_bbr_profile']}
    for field in ('up_mbps','down_mbps'):
        value=o[('hy_client_' if client else 'hy_')+field]
        if value:out[field]=value
    if not client:
        out['ignore_client_bandwidth']=o['hy_ignore_client_bandwidth']
        if o['hy_masquerade']:out['masquerade']=o['hy_masquerade']
    out.update(initial_packet_size=o['hy_initial_packet_size'],disable_path_mtu_discovery=o['hy_disable_mtu_discovery'])
    if o['hy_obfs']!='none':
        out['obfs']={'type':o['hy_obfs'],'password':o['hy_obfs_password']}
        if o['hy_obfs']=='gecko':out['obfs'].update(min_packet_size=o['hy_gecko_min'],max_packet_size=o['hy_gecko_max'])
    return out
