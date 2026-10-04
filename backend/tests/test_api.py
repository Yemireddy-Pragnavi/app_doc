import os
os.environ['DATABASE_URL']='sqlite://'
os.environ['FRONTEND_URL']='http://localhost:3000'
os.environ['COOKIE_SECURE']='false'
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.main import app
from app.db import Base,get_db,User,Repository,Scan,Finding
from app.security import create_session
import pytest

@pytest.fixture
def clients():
    engine=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool)
    Base.metadata.create_all(engine);Session=sessionmaker(engine,expire_on_commit=False)
    def override():
        with Session() as db:yield db
    app.dependency_overrides[get_db]=override
    with Session() as db:
        u=User(github_id='1',login='one',encrypted_token='none');v=User(github_id='2',login='two',encrypted_token='none');db.add_all([u,v]);db.flush()
        repo=Repository(user_id=u.id,full_name='one/repo',data={'name':'repo'});db.add(repo);db.flush()
        scan=Scan(repository_id=repo.id,user_id=u.id);db.add(scan);db.flush()
        f=Finding(scan_id=scan.id,user_id=u.id,data={'title':'example'});db.add(f);db.flush()
        a=create_session(db,u.id);b=create_session(db,v.id);db.commit();ids=(repo.id,scan.id,f.id)
    c=TestClient(app);c.cookies.set('asd_session',a)
    d=TestClient(app);d.cookies.set('asd_session',b)
    yield c,d,ids
    app.dependency_overrides.clear()

def test_tenant_isolation_every_resource(clients):
    owner,other,(repo,scan,finding)=clients
    assert owner.get('/api/repositories/'+repo).status_code==200
    for route in ['/api/repositories/'+repo,'/api/repositories/'+repo+'/history','/api/scans/'+scan,'/api/scans/'+scan+'/findings','/api/scans/'+scan+'/diagnosis','/api/scans/'+scan+'/status']:
        assert other.get(route).status_code==404
    assert other.get('/api/repositories').json()==[]
    assert other.patch('/api/findings/'+finding,json={'status':'fixed'},headers={'Origin':'http://localhost:3000'}).status_code==404

def test_csrf_and_manual_fix(clients):
    owner,_,(_,_,finding)=clients
    assert owner.patch('/api/findings/'+finding,json={'status':'fixed'}).status_code==403
    r=owner.patch('/api/findings/'+finding,json={'status':'fixed'},headers={'Origin':'http://localhost:3000'})
    assert r.status_code==200 and r.json()['verified'] is False
    assert owner.patch('/api/findings/'+finding,json={'status':'invalid'},headers={'Origin':'http://localhost:3000'}).status_code==422

def test_auth_required():
    assert TestClient(app).get('/api/repositories').status_code==401

def test_oauth_missing_configuration():
    assert TestClient(app).get('/api/auth/github').status_code==503

def test_logout_invalidates_session(clients):
    owner,_,_=clients
    result=owner.post('/api/auth/logout',headers={'Origin':'http://localhost:3000'})
    assert result.status_code==200 and result.json()['signed_out']
    assert owner.get('/api/me').status_code==401

def test_branch_selection_is_authorized_and_passed_to_queue(clients,monkeypatch):
    owner,other,(repo,_,_)=clients
    import app.main as main
    import app.worker as worker
    calls=[]
    async def fake_github(path,token):
        calls.append(path)
        return {'name':'feature/security','commit':{'sha':'a'*40}}
    monkeypatch.setattr(main,'decrypt',lambda token:'fake-token')
    monkeypatch.setattr(main,'github',fake_github)
    monkeypatch.setattr(worker.run_scan,'delay',lambda id:None)
    result=owner.post('/api/repositories/'+repo+'/scan',json={'branch':'feature/security'},headers={'Origin':'http://localhost:3000'})
    assert result.status_code==202
    assert result.json()['branch']=='feature/security'
    assert calls[0].endswith('/branches/feature%2Fsecurity')
    assert other.post('/api/repositories/'+repo+'/scan',json={'branch':'main'},headers={'Origin':'http://localhost:3000'}).status_code==404
    assert owner.post('/api/repositories/'+repo+'/scan',json={'branch':'--upload-pack=evil'},headers={'Origin':'http://localhost:3000'}).status_code==422

def test_repository_listing_is_paginated(clients,monkeypatch):
    owner,_,_=clients
    import app.main as main
    seen=[]
    async def fake_github(path,token):
        seen.append(path)
        return [{'full_name':'one/app','html_url':'https://github.com/one/app','private':True,'language':'Python','default_branch':'main'}]
    monkeypatch.setattr(main,'decrypt',lambda token:'fake-token')
    monkeypatch.setattr(main,'github',fake_github)
    response=owner.get('/api/github/repositories?page=2')
    assert response.status_code==200
    assert 'page=2'in seen[0]
    assert response.json()['repositories'][0]['full_name']=='one/app'
    assert response.json()['has_more'] is False
    assert owner.get('/api/github/repositories?page=-1').status_code==422

def test_runtime_ownership_origin_and_allowlist(clients,monkeypatch):
    owner,other,(repo,scan,_)=clients
    import app.main as main
    import app.worker as worker
    from app.config import settings
    from app.db import RuntimeScan
    # Complete the source baseline in this test's isolated database.
    with next(app.dependency_overrides[get_db]()) as db:
        baseline=db.get(Scan,scan);baseline.status='completed';baseline.data={'decision':'READY'};db.commit()
    monkeypatch.setattr(settings(),'runtime_allowed_hosts','staging.example.com')
    monkeypatch.setattr(worker.run_runtime,'delay',lambda id:None)
    body={'source_scan_id':scan,'target_url':'https://staging.example.com/','paths':['/api/status'],'authorized':True}
    route='/api/repositories/'+repo+'/runtime-scans'
    assert owner.post(route,json=body).status_code==403
    headers={'Origin':'http://localhost:3000'}
    assert other.post(route,json=body,headers=headers).status_code==404
    assert owner.post(route,json={**body,'authorized':False},headers=headers).status_code==422
    assert owner.post(route,json={**body,'target_url':'https://not-allowed.example.com/'},headers=headers).status_code==422
    response=owner.post(route,json=body,headers=headers)
    assert response.status_code==202
    runtime_id=response.json()['id']
    assert other.get('/api/runtime-scans/'+runtime_id).status_code==404
    assert other.get(route).status_code==404
    assert owner.get(route).json()[0]['id']==runtime_id
    assert owner.post(route,json=body,headers=headers).status_code==429

def test_stale_scans_recover_without_losing_branch(clients):
    from app.operations import reconcile_stale
    from app.db import RuntimeScan
    owner,_,(repo,scan,_)=clients
    with next(app.dependency_overrides[get_db]()) as db:
        row=db.get(Scan,scan);row.created_at='2020-01-01T00:00:00+00:00';row.data={'branch':'feature/security'};row.status='running';row.score=99;db.commit()
    result=owner.get('/api/scans/'+scan).json()
    assert result['status']=='failed' and result['score'] is None
    assert result['branch']=='feature/security'
    assert 'window' in result['error']

def test_queue_failure_keeps_scan_context(clients,monkeypatch):
    owner,_,(repo,_,_)=clients
    import app.main as main
    import app.worker as worker
    async def github(path,token):return {'name':'main','commit':{'sha':'b'*40}}
    monkeypatch.setattr(main,'github',github);monkeypatch.setattr(main,'decrypt',lambda x:'token')
    def fail(id):raise ConnectionError()
    monkeypatch.setattr(worker.run_scan,'delay',fail)
    response=owner.post('/api/repositories/'+repo+'/scan',json={'branch':'main'},headers={'Origin':'http://localhost:3000'})
    assert response.status_code==503
    rows=owner.get('/api/repositories/'+repo+'/history').json()
    assert any(r['status']=='failed' and r['branch']=='main' for r in rows)

def test_service_diagnostics_require_auth():
    assert TestClient(app).get('/api/system/status').status_code==401

def test_oauth_rejects_bad_state_before_token_exchange(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings(),'session_secret','test-session-secret-'*3)
    response=TestClient(app).get('/api/auth/callback?code=fake&state=invalid',follow_redirects=False)
    assert response.status_code==400

def test_oauth_round_trip_stores_encrypted_token(clients,monkeypatch):
    from cryptography.fernet import Fernet
    from app.config import settings
    import app.main as main
    from urllib.parse import urlsplit,parse_qs
    from app.security import decrypt
    monkeypatch.setattr(settings(),'session_secret','test-session-secret-'*3)
    monkeypatch.setattr(settings(),'token_encryption_key',Fernet.generate_key().decode())
    monkeypatch.setattr(settings(),'github_client_id','test-client')
    monkeypatch.setattr(settings(),'github_client_secret','test-secret')
    client=TestClient(app)
    start=client.get('/api/auth/github',follow_redirects=False)
    state=parse_qs(urlsplit(start.headers['location']).query)['state'][0]
    class Exchange:
        async def __aenter__(self):return self
        async def __aexit__(self,*args):pass
        async def post(self,*args,**kwargs):
            class Response:
                def json(self):return {'access_token':'synthetic-access-token'}
            return Response()
    monkeypatch.setattr(main.httpx,'AsyncClient',lambda **kwargs:Exchange())
    async def profile(path,token):return {'id':999,'login':'oauth-fixture'}
    monkeypatch.setattr(main,'github',profile)
    result=client.get('/api/auth/callback',params={'code':'test-code','state':state},follow_redirects=False)
    assert result.status_code==303
    assert client.get('/api/me').json()['login']=='oauth-fixture'
    with next(app.dependency_overrides[get_db]()) as db:
        from sqlalchemy import select
        user=db.scalar(select(User).where(User.github_id=='999'))
        assert user.encrypted_token!='synthetic-access-token'
        assert decrypt(user.encrypted_token)=='synthetic-access-token'
    assert client.post('/api/auth/logout',headers={'Origin':'http://localhost:3000'}).status_code==200
    assert client.get('/api/me').status_code==401
