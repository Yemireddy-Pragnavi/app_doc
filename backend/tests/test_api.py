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
