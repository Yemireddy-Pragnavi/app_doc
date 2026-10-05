from app.lifecycle import build_graph,graph_diff,traverse,memory,prioritize,decide,DEFAULT_POLICY
from app.remediation import dependency_patch
from test_api import clients
import pytest
ORIGIN={'Origin':'http://localhost:3000'}

def finding(**kw):return {'engine':'Code','title':'Unsafe evaluation','cwe':'CWE-95','file':'app.py','line':3,'severity':'High','fingerprint':'finding-1',**kw}
def scan(id,findings,status='completed',score=80):return {'id':id,'created_at':'2026-01-'+id.zfill(2)+'T00:00:00+00:00','findings':findings,'status':status,'score':score,'commit':id*40}

def test_graph_static_evidence_secret_values_not_retained(tmp_path):
    p=tmp_path/'app.py';p.write_text("import os\nTOKEN=os.getenv('PAYMENT_API_KEY')\ndef handler():\n return fetch()\ndef fetch():\n return 1\n")
    s={'route_inventory':{'routes':[{'file':'app.py','path':'/orders','methods':['GET'],'imports':{'app.py':['app.py']}}]}}
    graph=build_graph(s,[finding()],tmp_path,[p])
    route=next(n for n in graph['nodes'] if n['type']=='API Route')
    nodes={n['id']:n for n in graph['nodes']}
    assert any(nodes[p[-1]]['type']=='Finding' for p in traverse(graph,route['id'])['paths'])
    assert any(n['label']=='PAYMENT_API_KEY' for n in nodes.values())
    assert any(e['type']=='CALLS' for e in graph['edges'])
    assert all(e['inferred'] for e in graph['edges'])

def test_graph_changes_and_no_false_causality():
    a=build_graph({'components':[{'name':'Next.js','kind':'frontend'}]},[])
    b=build_graph({'components':[{'name':'Next.js','kind':'frontend'},{'name':'OpenAI','kind':'integration'}]},[])
    d=graph_diff(a,b);assert len(d['added_nodes'])==1;assert d['risks'][0]['kind']=='added External API'

def test_memory_partial_absence_never_resolves_and_line_move_is_same():
    f=finding();m=memory([scan('1',[f]),scan('2',[],'partial'),scan('3',[finding(line=30)])])
    assert len(m['patterns'])==1 and m['patterns'][0]['reintroduced']==0
    assert m['patterns'][0]['observations']==2

def test_memory_reintroduction_is_not_persistence():
    m=memory([scan('1',[finding()]),scan('2',[finding()]),scan('3',[]),scan('4',[finding()])])
    p=m['patterns'][0];assert p['observations']==3 and p['reintroduced']==1 and p['occurrences']==2

def test_unknown_context_never_suppresses_findings():
    p=prioritize([finding(file='tests/app.py')],{})[0]
    assert p['risk_score']==75 and p['exploitability']=='unverified'

def test_policy_fails_closed_and_blockers_survive_gaps():
    s={'status':'partial','score':95,'commit':'a'*40}
    result=decide(s,[finding(severity='Critical')],DEFAULT_POLICY)
    assert result['decision']=='NOT READY' and result['gaps'] and not result['allowed']
    assert decide({'status':'completed','score':95,'commit':'a'*40},[],DEFAULT_POLICY)['decision']=='INCOMPLETE'
    assert decide({'status':'completed','score':95},[],{'require_runtime':False})['allowed']

def test_patch_is_exact_and_only_advisory_versions():
    f=finding(engine='Dependencies',file='requirements.txt',package='requests',installed_version='2.19.0',fixed_versions=['2.32.4'])
    updated,diff=dependency_patch('requests==2.19.0\n',f,'2.32.4')
    assert updated=='requests==2.32.4\n' and '+requests==2.32.4' in diff
    for text,version in [('requests>=2.19.0\n','2.32.4'),('requests==2.19.0\n','99.0')]:
        with pytest.raises(ValueError):dependency_patch(text,f,version)

def test_lifecycle_tenant_and_role_controls(clients):
    owner,other,(rid,sid,fid)=clients;base='/api/lifecycle/repositories/'+rid
    assert other.get(base).status_code==404
    assert owner.post(base+'/members',json={'login':'two','role':'Viewer'},headers=ORIGIN).status_code==200
    assert other.get(base+'/activity').status_code==200
    assert other.post(base+'/policies',json={'reason':'Trying to change policy'},headers=ORIGIN).status_code==403
    assert other.post(base+'/gate-tokens',json={},headers=ORIGIN).status_code==403
    assert other.post(base+'/members',json={'login':'one','role':'Admin'},headers=ORIGIN).status_code==403
    members=owner.get(base+'/members').json();uid=next(m['user_id'] for m in members if m['login']=='two')
    assert owner.post(base+'/members/'+uid+'/revoke',json={},headers=ORIGIN).status_code==200
    assert other.get(base+'/activity').status_code==404

def test_gate_token_scope_rotation_and_missing_commit(clients):
    owner,other,(rid,_,_)=clients;base='/api/lifecycle/repositories/'+rid
    a=owner.post(base+'/gate-tokens',json={},headers=ORIGIN).json()['token']
    assert owner.get('/api/lifecycle/gate/'+rid+'?commit='+'a'*40,headers={'Authorization':'Bearer '+a}).json()['allowed'] is False
    b=owner.post(base+'/gate-tokens',json={},headers=ORIGIN).json()['token']
    assert a!=b
    assert owner.get('/api/lifecycle/gate/'+rid+'?commit='+'a'*40,headers={'Authorization':'Bearer '+a}).status_code==401
    assert other.get('/api/lifecycle/gate/another?commit='+'a'*40,headers={'Authorization':'Bearer '+b}).status_code==401

def test_policies_are_versioned_and_csrf_protected(clients):
    owner,_,(rid,_,_)=clients;base='/api/lifecycle/repositories/'+rid
    assert owner.post(base+'/policies',json={'reason':'Approved policy revision'}).status_code==403
    first=owner.post(base+'/policies',json={'reason':'Approved policy revision','minimum_score':70},headers=ORIGIN)
    second=owner.post(base+'/policies',json={'reason':'Raise score threshold','minimum_score':80},headers=ORIGIN)
    assert first.status_code==second.status_code==200 and first.json()['revision']!=second.json()['revision']
    assert len(owner.get(base+'/audit').json()['policies'])==2

def test_viewer_cannot_override_or_patch(clients):
    owner,other,(rid,sid,fid)=clients;base='/api/lifecycle/repositories/'+rid
    owner.post(base+'/members',json={'login':'two','role':'Viewer'},headers=ORIGIN)
    assert other.post(base+'/overrides',json={'reason':'Bypass security gate','scan_id':sid},headers=ORIGIN).status_code==403
    assert other.post(base+'/patches',json={'finding_id':fid,'version':'1.0'},headers=ORIGIN).status_code==403
