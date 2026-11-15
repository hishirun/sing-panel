"""Share credentials must not survive authorization changes while queued."""
import time

import pytest

from panel.core import connect
from test_app import client


@pytest.mark.parametrize('revocation,expected', [
    ('token', 404), ('disabled', 403), ('expired', 403), ('quota', 403),
])
def test_password_write_rechecks_authorization_after_waiting_for_lock(client, monkeypatch, revocation, expected):
    c, m = client
    m.routing_publisher.stop()
    with connect(m.DB) as db:
        db.execute("INSERT INTO users(id,name,secret,uuid,token) VALUES('u','Alice','original-secret','original-uuid','old-token')")
    c.cookies.clear()
    csrf = c.get('/s/old-token/routing/api').json()['csrf']
    original_lock = m.runtime.lock

    class RevokeBeforeWrite:
        changed = False

        def __enter__(self):
            original_lock.acquire()
            if not self.changed:
                self.changed = True
                with connect(m.DB) as db:
                    if revocation == 'token':
                        db.execute("UPDATE users SET token='replacement-token' WHERE id='u'")
                    elif revocation == 'disabled':
                        db.execute("UPDATE users SET enabled=0 WHERE id='u'")
                    elif revocation == 'expired':
                        db.execute("UPDATE users SET expires=? WHERE id='u'", (int(time.time()) - 1,))
                    else:
                        db.execute("UPDATE users SET quota=100,upload=100 WHERE id='u'")
            return self

        def __exit__(self, *args):
            original_lock.release()

    monkeypatch.setattr(m.runtime, 'lock', RevokeBeforeWrite())
    response = c.post('/s/old-token/psk', data={
        'csrf_token': csrf, 'psk': 'attacker-known-secret',
    }, follow_redirects=False)
    assert response.status_code == expected, response.text
    with connect(m.DB) as db:
        assert db.execute("SELECT secret FROM users WHERE id='u'").fetchone()[0] == 'original-secret'
        assert db.execute("SELECT value FROM settings WHERE key='psk_changed:u'").fetchone() is None
