import asyncio
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from test_api import clients
from test_lifecycle_flows import complete_scan,ORIGIN
from app.revisions import resolve_revision

def test_organization_grants_revocation_and_policy_floor(clients):
    owner,other,(rid,sid,_)=clients;complete_scan(sid)
    oid=owner.post('/api/organizations',json={'name':'Engineering'},headers=ORIGIN).json()['id'];base='/api/organizations/'+oid
    assert other.get(base).status_code==404
    assert other.get('/api/lifecycle/portfolio?organization_id='+oid).status_code==404
    assert owner.post(base+'/repositories',json={'repository_id':rid},headers=ORIGIN).status_code==200
    assert owner.post(base+'/members',json={'login':'two','role':'Viewer'},headers=ORIGIN).status_code==200
    assert other.get('/api/lifecycle/repositories/'+rid).status_code==200
    assert other.post(base+'/policies',json={'reason':'Attempted policy change'},headers=ORIGIN).status_code==403
    assert other.post(base+'/repositories',json={'repository_id':rid},headers=ORIGIN).status_code==403
    owner.post('/api/lifecycle/repositories/'+rid+'/policies',json={'minimum_score':0,'require_runtime':False,'reason':'Development repository policy'},headers=ORIGIN)
    owner.post(base+'/policies',json={'minimum_score':95,'require_runtime':True,'reason':'Organization release requirements'},headers=ORIGIN)
    decision=other.get('/api/lifecycle/repositories/'+rid).json()['decision']
    assert decision['policy']['minimum_score']==95 and decision['policy']['require_runtime'] and not decision['allowed']
    d=owner.get(base).json();assert len(d['repositories'])==1 and d['portfolio']['metrics']['assessed_repositories']==1
    uid=next(m['user_id'] for m in d['members'] if m['login']=='two')
    assert owner.post(base+'/members/'+uid+'/revoke',json={},headers=ORIGIN).status_code==200
    assert other.get('/api/lifecycle/repositories/'+rid).status_code==404
    assert other.get(base).status_code==404

def test_organization_detach_preserves_direct_grant(clients):
    owner,other,(rid,sid,_)=clients;complete_scan(sid)
    oid=other.post('/api/organizations',json={'name':'Other organization'},headers=ORIGIN).json()['id']
    assert other.post('/api/organizations/'+oid+'/repositories',json={'repository_id':rid},headers=ORIGIN).status_code==404
    oid=owner.post('/api/organizations',json={'name':'Engineering'},headers=ORIGIN).json()['id'];base='/api/organizations/'+oid
    owner.post(base+'/repositories',json={'repository_id':rid},headers=ORIGIN)
    owner.post(base+'/members',json={'login':'two','role':'Admin'},headers=ORIGIN)
    owner.post('/api/lifecycle/repositories/'+rid+'/members',json={'login':'two','role':'Viewer'},headers=ORIGIN)
    assert other.get('/api/lifecycle/repositories/'+rid).json()['role']=='Viewer'
    assert other.post(base+'/repositories/'+rid+'/detach',json={},headers=ORIGIN).status_code==403
    owner.post(base+'/repositories/'+rid+'/detach',json={},headers=ORIGIN)
    assert other.get('/api/lifecycle/repositories/'+rid).json()['role']=='Viewer'

def resolve(**kwargs):
    repo=SimpleNamespace(full_name='one/repo',data={'default_branch':'main'})
    body=SimpleNamespace(commit=None,pull_request=None,tag=None,branch=None);body.__dict__.update(kwargs)
    return repo,body

def test_exact_pr_revision_with_deleted_fork():
    async def github(path,token):return {'head':{'sha':'a'*40,'repo':None},'base':{'sha':'b'*40,'ref':'main','repo':{'full_name':'one/repo'}}}
    repo,body=resolve(pull_request=12)
    r=asyncio.run(resolve_revision(repo,body,'token',github))
    assert r['source_ref']=='refs/pull/12/head' and r['requested_commit']=='a'*40 and r['source_is_fork']

def test_revision_binding_and_exclusivity():
    async def wrong(path,token):return {'base':{'repo':{'full_name':'other/repo'}}}
    repo,body=resolve(pull_request=1)
    with pytest.raises(HTTPException):asyncio.run(resolve_revision(repo,body,'token',wrong))
    repo,body=resolve(pull_request=1,tag='v1')
    with pytest.raises(HTTPException):asyncio.run(resolve_revision(repo,body,'token',wrong))
    repo,body=resolve(tag='../bad')
    with pytest.raises(HTTPException):asyncio.run(resolve_revision(repo,body,'token',wrong))

def test_release_tag_pinned_and_commit_mismatch_rejected():
    paths=[]
    async def github(path,token):paths.append(path);return {'sha':'a'*40}
    repo,body=resolve(tag='v1.2')
    r=asyncio.run(resolve_revision(repo,body,'token',github))
    assert paths==['/repos/one/repo/commits/tags%2Fv1.2'] and r['source_ref']=='a'*40
    repo,body=resolve(commit='b'*40)
    with pytest.raises(HTTPException):asyncio.run(resolve_revision(repo,body,'token',github))

def test_signed_pr_and_release_events_pin_revision(clients,monkeypatch):
    import json,hmac,hashlib
    import app.security as security
    import app.main as main
    monkeypatch.setattr(security,'encrypt',lambda x:x);monkeypatch.setattr(security,'decrypt',lambda x:x)
    queued=[]
    async def start(rid,body,owner,db):queued.append(body.model_dump());return {'id':'scan-fixture'}
    monkeypatch.setattr(main,'start_scan',start)
    owner,_,(rid,_,_)=clients
    secret=owner.post('/api/lifecycle/repositories/'+rid+'/webhook',json={'enabled':True,'branches':['main']},headers=ORIGIN).json()['secret']
    def send(kind,payload,n):
        body=json.dumps({'repository':{'full_name':'one/repo'},**payload}).encode()
        return owner.post('/api/lifecycle/webhooks/github/'+rid,content=body,headers={'x-github-event':kind,'x-github-delivery':'test-delivery-'+str(n),'x-hub-signature-256':'sha256='+hmac.new(secret.encode(),body,hashlib.sha256).hexdigest()})
    assert send('pull_request',{'action':'synchronize','number':12,'pull_request':{'base':{'ref':'main'}}},1).status_code==200
    assert queued[-1]['pull_request']==12
    assert send('release',{'action':'published','release':{'tag_name':'v1.2'}},2).status_code==200
    assert queued[-1]['tag']=='v1.2'
    assert send('push',{'ref':'refs/heads/main','after':'c'*40},3).status_code==200
    assert queued[-1]['commit']=='c'*40
    assert send('pull_request',{'action':'closed','pull_request':{'merged':True,'base':{'ref':'main'}}},4).status_code==422
    assert send('release',{'action':'published','release':{}},5).status_code==422
    assert len(queued)==3
