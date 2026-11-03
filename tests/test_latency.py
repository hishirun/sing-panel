from panel.latency import node_exits,probe,cached
from panel.core import init_db
from types import SimpleNamespace

def test_latency_cache_and_first_matching_node_route(tmp_path):
    db=tmp_path/'test.db';init_db(db)
    out={'id':'seattle','name':'Seattle','enabled':True,'settings':{'server':'test'}}
    result=probe(db,SimpleNamespace(control=lambda _: {'delay':42}),out)
    assert result['delay']==42 and cached(db,out)['delay']==42
    data={'outbounds':[out],'final':'direct','rules':[{'enabled':True,'node_ids':['a'],'match':{},'target':'seattle'},{'enabled':True,'node_ids':[],'match':{'domain':['ai.test']},'target':'seattle'}]}
    assert len(node_exits(db,{'id':'a'},data))==1
    assert node_exits(db,{'id':'b'},data)[0]['conditional'] is True
    assert node_exits(db,{'id':'b'},data)[-1]['name']=='直连'
    assert cached(db,{**out,'settings':{'server':'changed'}})=={}
    assert probe(db,SimpleNamespace(control=lambda _: {}),out)['delay'] is None
