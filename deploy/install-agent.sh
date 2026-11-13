#!/usr/bin/env bash
# Run only from the administrator-generated HTTPS installation command.
set -euo pipefail
umask 077

panel=''
token=''
while (($#)); do
    case "$1" in
        --panel) [[ $# -ge 2 ]] || exit 2; panel="$2"; shift 2 ;;
        --token) [[ $# -ge 2 ]] || exit 2; token="$2"; shift 2 ;;
        *) echo "未知安装参数：$1" >&2; exit 2 ;;
    esac
done
[[ $(id -u) -eq 0 ]] || { echo '请使用 sudo 或 root 执行安装命令。' >&2; exit 1; }
[[ $(uname -s) == Linux ]] || { echo 'Agent 安装器仅支持 Linux。' >&2; exit 1; }
[[ "$panel" == https://* && -n "$token" ]] || { echo '缺少 HTTPS 主控地址或接入令牌。' >&2; exit 2; }
panel="${panel%/}"
case "$(uname -m)" in
    x86_64) architecture=linux-amd64 ;;
    aarch64|arm64) architecture=linux-arm64 ;;
    *) echo '暂不支持此 CPU 架构；支持 amd64 与 arm64。' >&2; exit 1 ;;
esac
command -v systemctl >/dev/null || { echo '此安装器需要 systemd。' >&2; exit 1; }
command -v flock >/dev/null || { echo '此安装器需要 util-linux（flock / runuser）。' >&2; exit 1; }
exec 9>/run/lock/sing-panel-agent-install.lock
flock -n 9 || { echo '另一个 Agent 安装任务正在运行。' >&2; exit 1; }
install_root=/opt/sing-panel-agent
state_root=/var/lib/sing-panel-agent

# A repeat command may refresh the same server's identity, never another panel.
if [[ -f "$state_root/config.json" ]]; then
    if ! command -v python3 >/dev/null; then
        echo '发现已有 Agent 配置，请先检查，未覆盖。' >&2; exit 1
    fi
    python3 - "$state_root/config.json" "$panel" <<'PY'
import json,sys
value=json.load(open(sys.argv[1]))
if value.get('panel')!=sys.argv[2]:
    raise SystemExit('这台机器已经接入另一主控，拒绝覆盖现有身份。')
PY
fi

if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq python3 python3-venv ca-certificates curl tar
elif command -v dnf >/dev/null; then
    dnf install -y python3 python3-pip ca-certificates curl tar
elif command -v yum >/dev/null; then
    yum install -y python3 python3-pip ca-certificates curl tar
else
    echo '暂支持 Debian / Ubuntu 与使用 dnf/yum 的发行版。' >&2; exit 1
fi
python3 - "$panel" <<'PY'
import sys
from urllib.parse import urlsplit
if sys.version_info<(3,10):raise SystemExit('需要 Python 3.10 或更新版本，请升级系统 Python 后再运行。')
p=urlsplit(sys.argv[1])
if p.scheme!='https' or not p.hostname or p.username or p.password or p.path or p.query or p.fragment:
    raise SystemExit('主控地址格式无效。')
p.port
PY

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 60 \
    "$panel/agent/manifest.json" -o "$temporary/manifest.json"
python3 - "$temporary/manifest.json" "$architecture" > "$temporary/validated-manifest.json" <<'PY'
import json,re,sys
m=json.load(open(sys.argv[1]));arch=sys.argv[2]
if not re.fullmatch(r'\d+\.\d+\.\d+',str(m.get('version',''))):raise SystemExit('Agent 版本信息无效。')
b=m.get('bundle',{});c=m.get('cores',{}).get(arch,{})
for item,path in [(b,'/agent/bundle.tar.gz'),(c,'/agent/core/'+arch)]:
    if item.get('url')!=path or not re.fullmatch('[a-f0-9]{64}',str(item.get('sha256',''))):
        raise SystemExit('当前主控尚未提供此架构的完整 Agent 安装包。')
print(json.dumps({'version':m['version'],'bundle':b,'core':c}))
PY
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 180 \
    --max-filesize 8388608 "$panel/agent/bundle.tar.gz" -o "$temporary/bundle.tar.gz"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 300 \
    --max-filesize 314572800 "$panel/agent/core/$architecture" -o "$temporary/sing-box"
python3 - "$temporary" <<'PY'
import hashlib,json,sys,tarfile
from pathlib import Path,PurePosixPath
p=Path(sys.argv[1]);m=json.loads((p/'validated-manifest.json').read_text())
for name,key in [('bundle.tar.gz','bundle'),('sing-box','core')]:
    if hashlib.sha256((p/name).read_bytes()).hexdigest()!=m[key]['sha256']:raise SystemExit('安装包 SHA256 校验失败。')
with tarfile.open(p/'bundle.tar.gz','r:gz') as archive:
    total=0;seen=set()
    for item in archive.getmembers():
        name=item.name.removeprefix('./');parts=PurePosixPath(name)
        if parts.is_absolute() or '..' in parts.parts or '\\' in name or not parts.parts:raise SystemExit('安装包路径无效。')
        if parts.parts[0]!='agent' and name not in ('deploy','deploy/sing-panel-agent.service'):raise SystemExit('安装包含未知文件。')
        if not (item.isfile() or item.isdir()):raise SystemExit('安装包不允许链接或特殊文件。')
        if item.isdir():continue
        total+=item.size
        if name in seen or item.size>4*1024*1024 or total>16*1024*1024:raise SystemExit('安装包内容超出限制。')
        seen.add(name);target=p/'unpacked'/name;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(archive.extractfile(item).read())
for required in ['agent/__init__.py','agent/__main__.py','agent/requirements.txt','deploy/sing-panel-agent.service']:
    if required not in seen:raise SystemExit('安装包不完整。')
(p/'release-name').write_text(m['version']+'-'+m['bundle']['sha256'][:16])
PY

if ! id singpanel-agent >/dev/null 2>&1; then
    useradd --system --user-group --home-dir "$state_root" --shell /usr/sbin/nologin singpanel-agent
fi
install -d -m 0755 "$install_root"
install -d -o singpanel-agent -g singpanel-agent -m 0755 "$install_root/releases"
install -d -o singpanel-agent -g singpanel-agent -m 0700 "$state_root"
release_name=$(cat "$temporary/release-name")
# Root never follows or recursively changes files inside the agent-writable
# release tree. Install verified contents with the service user's privileges.
chmod 0755 "$temporary" "$temporary/unpacked"
find "$temporary/unpacked/agent" -type d -exec chmod 0755 {} +
find "$temporary/unpacked/agent" -type f -exec chmod 0644 {} +
runuser -u singpanel-agent -- python3 - "$temporary/unpacked/agent" "$install_root/releases" "$release_name" <<'PYCODE'
from pathlib import Path
import os,shutil,sys,tempfile
source,releases=map(Path,sys.argv[1:3]);name=sys.argv[3];target=releases/name
staged=Path(tempfile.mkdtemp(prefix='.install-',dir=releases))
try:
    shutil.copytree(source,staged/'agent')
    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_dir():raise SystemExit('已有发布目录不安全，未覆盖。')
        for p in source.rglob('*'):
            other=target/'agent'/p.relative_to(source)
            if other.is_symlink():raise SystemExit('已有发布包包含链接，未覆盖。')
            if p.is_file() and (not other.is_file() or p.read_bytes()!=other.read_bytes()):
                raise SystemExit('已有安装目录与校验后的发布包不一致，未覆盖。')
    else:staged.rename(target)
    link=releases/'.install-current'
    link.unlink(missing_ok=True);link.symlink_to(name)
    os.replace(link,releases/'current')
finally:
    if staged.exists():shutil.rmtree(staged)
PYCODE
if [[ -e "$install_root/agent" && ! -L "$install_root/agent" ]]; then
    echo '已有非标准 agent 目录，未覆盖，请先检查。' >&2; exit 1
fi
ln -sfn releases/current/agent "$install_root/agent"
install -m 0755 "$temporary/sing-box" "$install_root/.sing-box-new"
mv -f "$install_root/.sing-box-new" "$install_root/sing-box"
"$install_root/sing-box" version
venv_root="$install_root/venv"
[[ ! -L "$venv_root" ]] || { echo '运行环境目录不能是符号链接。' >&2; exit 1; }
if [[ -e "$venv_root" ]] && [[ -n "$(find -P "$venv_root" ! -user root -print -quit)" ]]; then
    echo '运行环境包含非 root 所有的文件，拒绝以 root 修改。' >&2; exit 1
fi
# The service must traverse and read root-owned Python packages. Keep the
# restrictive global umask for identity/state, changing it only for the venv.
(
    umask 022
    python3 -m venv "$venv_root"
    "$venv_root/bin/python" -m pip install --disable-pip-version-check --quiet -r "$temporary/unpacked/agent/requirements.txt"
)
# Also repair a partial installation created with the old restrictive umask.
# -P prevents following the interpreter symlinks outside this root-owned tree.
find -P "$venv_root" -type d -exec chmod 0755 {} +
find -P "$venv_root" -type f -exec chmod a+rX {} +
cd "$install_root"
# Pass the one-use token over stdin, not into the Python process command line.
printf '%s' "$token" | runuser -u singpanel-agent -- "$install_root/venv/bin/python" -m agent enroll \
    --config "$state_root/config.json" --panel "$panel" --token-stdin \
    --binary "$install_root/sing-box" --install-dir "$install_root"
unset token
install -m 0644 "$temporary/unpacked/deploy/sing-panel-agent.service" /etc/systemd/system/sing-panel-agent.service
systemctl daemon-reload
systemctl enable sing-panel-agent
systemctl restart sing-panel-agent
systemctl is-active --quiet sing-panel-agent
echo 'Agent 已安装并启动。请在主面板“服务器管理”查看接入状态。'
