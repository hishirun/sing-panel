from test_app import client


def test_expired_browser_and_async_navigation_redirect(client):
    c,m=client
    with m.connect(m.DB) as db:
        db.execute("INSERT OR REPLACE INTO settings VALUES('admin_path','/manage-test')")
    c.cookies.clear()
    for headers in ({'Accept':'text/html'}, {'X-Panel-Navigation':'1'}, {'Sec-Fetch-Dest':'document'}):
        response=c.get('/manage-test/users',headers=headers,follow_redirects=False)
        assert response.status_code==303
        assert response.headers['location']=='/manage-test/login?expired=1'
    page=c.get('/manage-test/users',headers={'Accept':'text/html'})
    assert page.status_code==200 and '登录状态已失效' in page.text
    assert '管理员密码' in page.text


def test_expired_api_and_post_remain_unauthorized_with_utf8(client):
    c,m=client
    c.cookies.clear()
    response=c.get('/users',headers={'Accept':'application/json'})
    assert response.status_code==401
    assert response.json()['detail']=='请先登录'
    assert 'charset=utf-8' in response.headers['content-type']
    response=c.post('/users/create',data={'name':'should-not-exist'},headers={'X-Panel-Navigation':'1'})
    assert response.status_code==401
    assert not m.records(m.DB,'users')
