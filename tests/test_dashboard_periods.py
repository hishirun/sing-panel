from test_app import client

def test_dashboard_periods_and_machine_auth(client):
    c,m=client
    for period,count in [('24h',24),('7d',7),('30d',30),('invalid',7)]:
        response=c.get('/?period='+period)
        assert response.status_code==200
        assert response.text.count('class="overview-day"')==count
        assert '累计接收' in response.text and '总网络流量' in response.text
    assert c.get('/system/metrics').status_code==200
    c.cookies.clear()
    assert c.get('/system/metrics').status_code==401
