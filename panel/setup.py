"""Create or rotate administrator login credentials locally."""
import getpass
import json
import os
import re
import secrets
from pathlib import Path
from argon2 import PasswordHasher

def main():
    directory = Path(os.environ.get('PANEL_DATA', 'data'))
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / 'auth.json'
    previous = json.loads(path.read_text()) if path.exists() else {}
    default_username = previous.get('username', 'admin')
    username = input(f'管理员账号 [{default_username}]: ').strip() or default_username
    if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}', username):
        raise SystemExit('账号需要 1–64 位字母、数字、点、下划线、@ 或短横线')
    password = getpass.getpass('管理员密码（至少 12 字符）: ')
    if len(password) < 12:
        raise SystemExit('密码至少需要 12 字符')
    if password != getpass.getpass('再次输入: '):
        raise SystemExit('两次密码不一致')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump({'username': username, 'password_hash': PasswordHasher().hash(password),
                   'session_key': secrets.token_hex(32)}, f)
    path.chmod(0o600)
    print('管理员已配置；请启动或重启面板。')

if __name__ == '__main__':
    main()
