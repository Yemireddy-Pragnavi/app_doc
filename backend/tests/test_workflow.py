"""Exercise API → worker → persisted reports → triage → rescan.
Network providers and external binaries are isolated test doubles, not live scans.
"""
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
from app.main import app
from app.db import Base, get_db, User, Repository, Scan, Finding
from app.security import create_session
from app.scanners import finding

@pytest.fixture
def workflow(monkeypatch):
    import app.worker as worker
    import app.main as main
    from app.config import settings
    engine=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool)
    Base.metadata.create_all(engine);Session=sessionmaker(engine,expire_on_commit=False)
    def db_override():
        with Session() as db:yield db
    app.dependency_overrides[get_db]=db_override
    monkeypatch.setattr(worker,'Session',Session)
    monkeypatch.setattr(worker,'decrypt',lambda x:'synthetic-token')
    monkeypatch.setattr(main,'decrypt',lambda x:'synthetic-token')
    monkeypatch.setattr(settings(),'frontend_url','http://localhost:3000')
    with Session() as db:
        user=User(github_id='42',login='fixture',encrypted_token='test');db.add(user);db.flush()
        token=create_session(db,user.id);db.commit()
    client=TestClient(app);client.cookies.set('asd_session',token)
    async def github(path,token):
        if '/branches/' in path:return {'name':'main','commit':{'sha':'a'*40}}
        return {'full_name':'fixture/app','name':'app','owner':{'login':'fixture'},'default_branch':'main','language':'TypeScript','updated_at':'2026-10-04','size':1,'visibility':'private'}
    monkeypatch.setattr(main,'github',github)
    def command(args,cwd,extra_env=None):
        from pathlib import Path
        if 'clone' in args:
            root=Path(args[-1]);root.mkdir();(root/'package.json').write_text('{"dependencies":{"next":"15.0.0"}}');return ''
        return 'a'*40
    monkeypatch.setattr(worker,'command',command)
    state={'issue':True,'fail':False}
    def code(root):
        if state['fail']:raise RuntimeError('tool unavailable')
        return ([finding('Code','Unsafe command','High','app/api/admin/route.ts',1,'Synthetic detection','Replace unsafe call',.95)] if state['issue'] else []),{'status':'completed','note':'test adapter'}
    monkeypatch.setattr(worker,'semgrep',code)
    for engine_name in ('gitleaks','dependencies','auth_checks'):
        monkeypatch.setattr(worker,engine_name,lambda *a:([],{'status':'completed','note':'test adapter'}))
    monkeypatch.setattr(worker.run_scan,'delay',lambda id:worker.run_scan(id))
    yield client,Session,state
    app.dependency_overrides.clear()

def test_repository_workflow_and_comparison(workflow):
    client,Session,state=workflow
    headers={'Origin':'http://localhost:3000'}
    response=client.post('/api/github/connect',json={'url':'https://github.com/fixture/app'},headers=headers)
    assert response.status_code==200
    repo=response.json()['id']
    first=client.post('/api/repositories/'+repo+'/scan',json={'branch':'main'},headers=headers)
    assert first.status_code==202
    scan=client.get('/api/scans/'+first.json()['id']).json()
    assert scan['status']=='completed' and scan['commit']=='a'*40
    assert len(scan['coverage'])==4 and len(scan['findings'])==1
    original_score=scan['score'];original_decision=scan['decision']
    assert scan['technologies']==['Next.js','Node.js']
    assert len(client.get('/api/scans/'+scan['id']+'/status').json()['events'])==10
    finding_id=scan['findings'][0]['id']
    assert client.patch('/api/findings/'+finding_id,json={'status':'fixed'},headers=headers).json()['verified'] is False
    report=client.get('/api/scans/'+scan['id']+'/report').json()
    assert report['score']==original_score and report['decision']==original_decision
    state['issue']=False
    second=client.post('/api/repositories/'+repo+'/scan',json={'branch':'main'},headers=headers).json()
    report=client.get('/api/scans/'+second['id']).json()
    assert report['score']==100 and report['decision']=='READY'
    assert report['diff']['resolved']==1 and report['diff']['comparable']
    state['fail']=True
    third=client.post('/api/repositories/'+repo+'/scan',json={'branch':'main'},headers=headers).json()
    report=client.get('/api/scans/'+third['id']).json()
    assert report['status']=='partial' and report['score'] is None
    assert report['diff']['resolved'] is None
    assert len(client.get('/api/repositories/'+repo+'/history').json())==3

def test_runtime_worker_persists_and_uses_immutable_baseline(workflow,monkeypatch):
    client,Session,state=workflow
    import app.worker as worker
    import app.runtime as runtime
    from app.config import settings
    headers={'Origin':'http://localhost:3000'}
    repo=client.post('/api/github/connect',json={'url':'https://github.com/fixture/app'},headers=headers).json()['id']
    scan=client.post('/api/repositories/'+repo+'/scan',json={'branch':'main'},headers=headers).json()['id']
    original=runtime.scan_runtime
    def run(target,paths,baseline,findings):
        return original(target,paths,baseline,findings,fetch=lambda *a,**k:{'status':200,'headers':[('Content-Type','application/json'),('Strict-Transport-Security','max-age=31536000'),('X-Content-Type-Options','nosniff')]})
    monkeypatch.setattr(runtime,'scan_runtime',run)
    monkeypatch.setattr(settings(),'runtime_allowed_hosts','staging.example.com')
    monkeypatch.setattr(worker.run_runtime,'delay',lambda id:worker.run_runtime(id))
    response=client.post('/api/repositories/'+repo+'/runtime-scans',json={'target_url':'https://staging.example.com/','paths':['/api/admin'],'source_scan_id':scan,'authorized':True},headers=headers)
    assert response.status_code==202
    result=client.get('/api/runtime-scans/'+response.json()['id']).json()
    assert result['status']=='partial' and result['decision']=='NOT READY'
    assert result['browser']['status']=='unavailable'
    assert any(e['path']=='deployment' for e in result['errors'])
    assert result['repository_assessment']['id']==scan
    assert len(result['correlations'])==1

def test_worker_rejects_source_that_moved_after_request(workflow,monkeypatch):
    client,Session,state=workflow
    import app.worker as worker
    original=worker.command
    def moved(args,cwd,extra_env=None):
        if 'FETCH_HEAD^{commit}' in args:return 'b'*40
        return original(args,cwd,extra_env)
    monkeypatch.setattr(worker,'command',moved)
    headers={'Origin':'http://localhost:3000'}
    rid=client.post('/api/github/connect',json={'url':'https://github.com/fixture/app'},headers=headers).json()['id']
    sid=client.post('/api/repositories/'+rid+'/scan',json={'branch':'main'},headers=headers).json()['id']
    assert client.get('/api/scans/'+sid).json()['status']=='failed'
    assert client.get('/api/scans/'+sid+'/findings').json()==[]
