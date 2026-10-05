import json,hmac,hashlib
import pytest
from test_api import clients
from app.main import app
from app.db import get_db,Scan,Finding,RuntimeScan,LifecycleEvent,Repository
from sqlalchemy import select
ORIGIN={'Origin':'http://localhost:3000'}

def db_for_test():return app.dependency_overrides[get_db]()

def complete_scan(sid,score=90):
    gen=db_for_test();db=next(gen)
    s=db.get(Scan,sid);s.status='completed';s.score=score;s.data={'commit':'a'*40,'branch':'main','components':[{'name':'FastAPI','kind':'backend'}]};db.commit();gen.close()

def test_end_to_end_policy_and_gate_exact_commit(clients):
    owner,other,(rid,sid,fid)=clients;base='/api/lifecycle/repositories/'+rid;complete_scan(sid)
    owner.post(base+'/policies',json={'reason':'Static-only gate for development','require_runtime':False},headers=ORIGIN)
    result=owner.get(base).json();assert result['scan']['commit']=='a'*40 and result['decision']['allowed']
    token=owner.post(base+'/gate-tokens',json={},headers=ORIGIN).json()['token']
    result=other.get('/api/lifecycle/gate/'+rid+'?commit='+'a'*40,headers={'Authorization':'Bearer '+token})
    assert result.status_code==200 and result.json()['allowed']
    assert other.get('/api/lifecycle/gate/'+rid+'?commit='+'b'*40,headers={'Authorization':'Bearer '+token}).json()['allowed'] is False

def test_incomplete_override_denied_and_policy_change_invalidates(clients):
    owner,_,(rid,sid,fid)=clients;base='/api/lifecycle/repositories/'+rid;complete_scan(sid,60)
    assert owner.post(base+'/overrides',json={'reason':'Reviewed risk for release','scan_id':sid},headers=ORIGIN).status_code==409
    owner.post(base+'/policies',json={'reason':'Static-only gate for development','require_runtime':False},headers=ORIGIN)
    assert owner.post(base+'/overrides',json={'reason':'Reviewed score exception','scan_id':sid},headers=ORIGIN).status_code==200
    token=owner.post(base+'/gate-tokens',json={},headers=ORIGIN).json()['token'];headers={'Authorization':'Bearer '+token}
    assert owner.get('/api/lifecycle/gate/'+rid+'?commit='+'a'*40,headers=headers).json()['decision']=='OVERRIDDEN'
    owner.post(base+'/policies',json={'reason':'Tighter static deployment policy','minimum_score':95,'require_runtime':False},headers=ORIGIN)
    assert owner.get('/api/lifecycle/gate/'+rid+'?commit='+'a'*40,headers=headers).json()['allowed'] is False

def test_signed_webhook_bound_to_repository_branch_and_delivery(clients,monkeypatch):
    import app.lifecycle_api as api
    import app.security as security
    import app.main as main
    monkeypatch.setattr(security,'encrypt',lambda x:x);monkeypatch.setattr(security,'decrypt',lambda x:x)
    queued=[]
    async def start(rid,body,owner,db):queued.append(body.branch);return {'id':'queued-fixture'}
    monkeypatch.setattr(main,'start_scan',start)
    owner,_,(rid,_,_)=clients;base='/api/lifecycle/repositories/'+rid
    response=owner.post(base+'/webhook',json={'enabled':True,'branches':['main']},headers=ORIGIN);assert response.status_code==200
    secret=response.json()['secret'];payload={'repository':{'full_name':'one/repo'},'ref':'refs/heads/main'};body=json.dumps(payload).encode()
    headers={'x-github-event':'push','x-github-delivery':'delivery-000001','x-hub-signature-256':'sha256='+hmac.new(secret.encode(),body,hashlib.sha256).hexdigest()}
    path='/api/lifecycle/webhooks/github/'+rid
    assert owner.post(path,content=body,headers={**headers,'x-hub-signature-256':'bad'}).status_code==401
    assert owner.post(path,content=body,headers=headers).json()['scan_id']=='queued-fixture'
    assert owner.post(path,content=body,headers=headers).json()['duplicate'] and queued==['main']
    changed=json.dumps({**payload,'repository':{'full_name':'other/repo'}}).encode()
    headers['x-hub-signature-256']='sha256='+hmac.new(secret.encode(),changed,hashlib.sha256).hexdigest()
    assert owner.post(path,content=changed,headers=headers).status_code==403

def test_new_runtime_evidence_invalidates_override(clients):
    owner,_,(rid,sid,_)=clients;base='/api/lifecycle/repositories/'+rid;complete_scan(sid,60)
    owner.post(base+'/policies',json={'reason':'Static gate with runtime optional','require_runtime':False},headers=ORIGIN)
    owner.post(base+'/overrides',json={'reason':'Reviewed original evidence','scan_id':sid},headers=ORIGIN)
    gen=db_for_test();db=next(gen);repo=db.get(Repository,rid);db.add(RuntimeScan(repository_id=rid,user_id=repo.user_id,source_scan_id=sid,status='completed',data={}));db.commit();gen.close()
    token=owner.post(base+'/gate-tokens',json={},headers=ORIGIN).json()['token']
    assert owner.get('/api/lifecycle/gate/'+rid+'?commit='+'a'*40,headers={'Authorization':'Bearer '+token}).json()['allowed'] is False

def test_reviewed_patch_pr_uses_reviewer_access_and_never_updates_base(clients,monkeypatch):
    import base64
    import app.remediation as remediation
    import app.security as security
    from app.db import User
    owner,reviewer,(rid,sid,fid)=clients;base='/api/lifecycle/repositories/'+rid;complete_scan(sid)
    gen=db_for_test();db=next(gen)
    for u in db.scalars(select(User)):u.encrypted_token=u.login+'-credential'
    f=db.get(Finding,fid);f.data={'engine':'Dependencies','file':'requirements.txt','package':'requests','installed_version':'2.19.0','fixed_versions':['2.32.4'],'fingerprint':'fixture-fingerprint','advisory':'GHSA-fixture'};db.commit();gen.close()
    monkeypatch.setattr(security,'decrypt',lambda token:token)
    calls=[]
    async def gh(method,path,token,body=None):
        calls.append((method,path,token,body))
        if '/branches/' in path:return {'commit':{'sha':'a'*40}}
        if method=='GET':return {'type':'file','encoding':'base64','size':17,'content':base64.b64encode(b'requests==2.19.0\n').decode(),'sha':'b'*40}
        if '/git/refs' in path:return {'ref':body['ref']}
        if method=='PUT':return {'commit':{'sha':'c'*40}}
        return {'html_url':'https://github.com/one/repo/pull/1','number':1}
    monkeypatch.setattr(remediation,'gh',gh)
    owner.post(base+'/members',json={'login':'two','role':'Developer'},headers=ORIGIN)
    created=reviewer.post(base+'/patches',json={'finding_id':fid,'version':'2.32.4'},headers=ORIGIN)
    assert created.status_code==200
    pid=created.json()['id'];path=base+'/patches/'+pid+'/pull-request'
    assert reviewer.post(path,json={'reviewed':False,'reason':'Not reviewed this patch'},headers=ORIGIN).status_code==422
    calls.clear()
    result=reviewer.post(path,json={'reviewed':True,'reason':'Reviewed dependency compatibility'},headers=ORIGIN)
    assert result.status_code==200 and result.json()['draft']
    assert all(c[2]=='two-credential' for c in calls)
    update=next(c for c in calls if c[0]=='PUT');assert update[3]['branch'].startswith('security-doctor/')
    assert reviewer.post(path,json={'reviewed':True,'reason':'Repeated submission should stop'},headers=ORIGIN).status_code==409

def test_known_configuration_risk_included_even_without_runtime_requirement(clients):
    owner,_,(rid,sid,_)=clients;base='/api/lifecycle/repositories/'+rid;complete_scan(sid)
    gen=db_for_test();db=next(gen);scan=db.get(Scan,sid);scan.data={**scan.data,'cloud_review':{'findings':[{'id':'cloud-fixture','title':'Explicit unsafe access','severity':'High','path':'rules.json'}]}};db.commit();gen.close()
    owner.post(base+'/policies',json={'reason':'Block high configuration findings','require_runtime':False,'block_high':True},headers=ORIGIN)
    result=owner.get(base).json()
    assert any(f['engine']=='Configuration' for f in result['priorities'])
    assert result['decision']['decision']=='NOT READY'
