"""Exercise real customer setup/login forms in pre-existing functional tests."""
import html
import re

PASSWORD = 'customer-test-password-2026'


def customer_csrf(response):
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', response.text)
    assert match, 'Customer response must expose a real form CSRF token'
    return html.unescape(match[1])


def customer_login(client, root, password=PASSWORD):
    root = root.rstrip('/')
    page = client.get(root + '/login')
    assert page.status_code == 200, page.text
    action = re.search(r'<form[^>]*action="([^"]+/(setup|login))"', page.text)
    if action:
        endpoint = html.unescape(action[1])
        fields = {'csrf_token': customer_csrf(page), 'password': password}
        if action[2] == 'setup':
            fields['password_confirm'] = password
        response = client.post(endpoint, data=fields)
        assert response.status_code == 200, response.text
    else:
        # The login endpoint may redirect an already authenticated customer.
        assert page.url.path.rstrip('/') == root, page.text
    security = client.get(root + '/security')
    assert security.status_code == 200, security.text
    return customer_csrf(security)
