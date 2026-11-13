import hashlib
import io
import html
import os
import re
import subprocess
import tarfile

from test_app import client, csrf


def test_public_artifacts_contain_code_only_and_validate_manifest(client, monkeypatch, tmp_path):
    c,m=client
    cores=tmp_path/'cores';cores.mkdir()
    (cores/'sing-box-linux-amd64').write_bytes(b'core-fixture')
    monkeypatch.setenv('PANEL_AGENT_CORES',str(cores))
    c.cookies.clear()
    manifest=c.get('/agent/manifest.json')
    assert manifest.status_code==200
    payload=c.get('/agent/bundle.tar.gz')
    assert hashlib.sha256(payload.content).hexdigest()==manifest.json()['bundle']['sha256']
    assert c.get('/agent/core/linux-amd64').content==b'core-fixture'
    with tarfile.open(fileobj=io.BytesIO(payload.content)) as archive:
        names=archive.getnames()
        assert 'agent/__main__.py' in names
        assert all(name.startswith('agent/') or name=='deploy/sing-panel-agent.service' for name in names)
        assert not any(name.endswith(('config.json','auth.json','panel.db')) for name in names)
    assert c.get('/agent/core/auth.json').status_code==404
    assert c.get('/agent/auth.json').status_code==404


def test_backup_download_requires_admin_and_creation_requires_csrf(client):
    c,m=client
    token=csrf(c)
    assert c.post('/system/backups/create',data={'token':'invalid'}).status_code==403
    name=m.backup_manager.create()
    url='/system/backups/'+name+'/download'
    assert c.get(url).status_code==200
    assert c.get('/system/backups/not-a-backup/download').status_code==404
    assert c.post('/system/backups/settings',data={'token':token,'enabled':'true','interval_hours':'6','keep':'3'}).status_code==200
    c.cookies.clear()
    assert c.get(url,follow_redirects=False).status_code in (401,303)
    assert c.post('/system/backups/create',data={'token':token}).status_code==401


def test_install_command_supports_root_without_sudo_and_regular_users(client,tmp_path):
    c,m=client
    from panel.core import connect
    with connect(m.DB) as db:db.execute("INSERT OR REPLACE INTO settings VALUES('public_url','https://panel.example.com')")
    response=c.post('/servers/save',data={'token':csrf(c),'name':'Shell check','host':'192.0.2.1'})
    command=html.unescape(re.search(r'<textarea[^>]*id="fleet-install-command"[^>]*>(.*?)</textarea>',response.text,re.S)[1])
    binaries=tmp_path/'bin';binaries.mkdir()
    def executable(name,source):
        target=binaries/name;target.write_text('#!/bin/sh\n'+source);target.chmod(0o755)
    executable('curl',"cat <<'SCRIPT'\n[ \"$1\" = --panel ] && [ \"$2\" = https://panel.example.com ] && [ \"$3\" = --token ] || exit 2\nprintf installed\nSCRIPT\n")
    executable('sudo','exit 99\n')
    executable('id','printf 0\n')
    env={**os.environ,'PATH':str(binaries)+os.pathsep+os.environ['PATH']}
    assert subprocess.check_output(['bash','-c',command],env=env,text=True)=='installed'
    executable('id','printf 1000\n')
    executable('sudo','exec "$@"\n')
    assert subprocess.check_output(['bash','-c',command],env=env,text=True)=='installed'
