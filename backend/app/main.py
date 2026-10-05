import secrets,time
from contextlib import asynccontextmanager
from urllib.parse import urlencode, quote
import httpx
from itsdangerous import URLSafeTimedSerializer, BadSignature
from fastapi import FastAPI, Depends, HTTPException, Request, Query, Body
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.orm import Session as DBSession
from .config import settings
from .db import Base, engine, get_db, User, LoginSession, Repository, Scan, Finding, Event, Installation, Audit, RuntimeScan
from .security import current_user, encrypt, decrypt, create_session, repo_name, secret_hash

@asynccontextmanager
async def lifespan(app):
    Base.metadata.create_all(engine)
    yield
app=FastAPI(title='App Security Doctor',version='0.2.0',lifespan=lifespan)
app.add_middleware(CORSMiddleware,allow_origins=[settings().frontend_url.rstrip('/')],allow_credentials=True,allow_methods=['GET','POST','PATCH','OPTIONS'],allow_headers=['Content-Type'])
@app.middleware('http')
async def headers(request,call_next):
    response=await call_next(request)
    response.headers['Cache-Control']='no-store'
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['X-Frame-Options']='DENY'
    return response

def owned(db,model,id,user):
    row=db.get(model,id)
    if not row or row.user_id!=user.id:raise HTTPException(404,'Resource not found')
    return row
async def github(path,token):
    async with httpx.AsyncClient(timeout=20) as c:
        r=await c.get('https://api.github.com'+path,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json'})
    if r.status_code!=200:raise HTTPException(502,'GitHub could not authorize or retrieve this resource')
    return r.json()
def serializer():
    if len(settings().session_secret)<32:raise HTTPException(503,'GitHub authentication is not configured')
    return URLSafeTimedSerializer(settings().session_secret,salt='github-oauth')
def cookie(response,name,value,max_age):
    response.set_cookie(name,value,httponly=True,secure=settings().cookie_secure,samesite='lax',max_age=max_age,path='/')
def repo_json(r):return {**r.data,'id':r.id}
def scan_json(db,s):return {'id':s.id,'status':s.status,'created_at':s.created_at,'stage':s.stage,'score':s.score,**s.data,'findings':[{**f.data,'id':f.id,'status':f.status} for f in db.scalars(select(Finding).where(Finding.scan_id==s.id))]}
@app.get('/health')
def health():return {'status':'ok'}
@app.get('/api/auth/github')
def oauth_start():
    if not settings().github_client_id or not settings().github_client_secret:raise HTTPException(503,'GitHub OAuth is not configured')
    nonce=secrets.token_urlsafe(32)
    state=serializer().dumps(nonce)
    response=RedirectResponse('https://github.com/login/oauth/authorize?'+urlencode({'client_id':settings().github_client_id,'redirect_uri':settings().github_callback_url,'scope':'read:user repo','state':state}))
    cookie(response,'asd_oauth',nonce,600)
    return response
@app.get('/api/auth/callback')
async def oauth_callback(request:Request,code:str='',state:str='',db:DBSession=Depends(get_db)):
    try:nonce=serializer().loads(state,max_age=600)
    except BadSignature:raise HTTPException(400,'Invalid or expired OAuth state')
    if not secrets.compare_digest(nonce,request.cookies.get('asd_oauth','')):raise HTTPException(400,'OAuth state mismatch')
    async with httpx.AsyncClient(timeout=20) as c:
        r=await c.post('https://github.com/login/oauth/access_token',json={'client_id':settings().github_client_id,'client_secret':settings().github_client_secret,'code':code,'redirect_uri':settings().github_callback_url},headers={'Accept':'application/json'})
    token=r.json().get('access_token')
    if not token:raise HTTPException(400,'GitHub authentication failed')
    profile=await github('/user',token)
    user=db.scalar(select(User).where(User.github_id==str(profile['id'])))
    if not user:
        user=User(github_id=str(profile['id']),login=profile['login'],encrypted_token=encrypt(token));db.add(user);db.flush()
        db.add(Installation(user_id=user.id,kind='oauth'))
    else:user.encrypted_token=encrypt(token);user.login=profile['login']
    session=create_session(db,user.id)
    db.add(Audit(user_id=user.id,action='login',target=user.id));db.commit()
    response=RedirectResponse(settings().frontend_url.rstrip('/')+'/dashboard',status_code=303)
    response.delete_cookie('asd_oauth');cookie(response,'asd_session',session,86400)
    return response
@app.get('/api/me')
def me(user:User=Depends(current_user)):return {'id':user.id,'login':user.login}
@app.post('/api/auth/logout')
def logout(request:Request,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    session=db.get(LoginSession,secret_hash(request.cookies.get('asd_session','')))
    if session:db.delete(session);db.commit()
    response=JSONResponse({'signed_out':True});response.delete_cookie('asd_session',path='/');return response
class Connect(BaseModel):url:str=Field(max_length=250)
@app.post('/api/github/connect')
async def connect(body:Connect,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    try:name=repo_name(body.url)
    except ValueError as e:raise HTTPException(422,str(e))
    token=decrypt(user.encrypted_token)
    meta=await github('/repos/'+name,token)
    if meta.get('size',0)>settings().max_repository_mb*1024:raise HTTPException(413,'Repository exceeds the configured scan size limit')
    r=db.scalar(select(Repository).where(Repository.user_id==user.id,Repository.full_name==meta['full_name']))
    if not r:r=Repository(user_id=user.id,full_name=meta['full_name']);db.add(r)
    r.data={**(r.data or {}),'name':meta['name'],'owner':meta['owner']['login'],'visibility':meta.get('visibility','private'),'default_branch':meta['default_branch'],'language':meta['language'],'updated_at':meta['updated_at'],'technologies':(r.data or {}).get('technologies',[]),'score':(r.data or {}).get('score')}
    db.flush();db.add(Audit(user_id=user.id,action='connect_repository',target=r.id));db.commit();return repo_json(r)
@app.get('/api/repositories')
def repositories(user:User=Depends(current_user),db:DBSession=Depends(get_db)):return [repo_json(r) for r in db.scalars(select(Repository).where(Repository.user_id==user.id))]
@app.get('/api/repositories/{id}')
def repository(id:str,user:User=Depends(current_user),db:DBSession=Depends(get_db)):return repo_json(owned(db,Repository,id,user))
@app.get('/api/github/repositories')
async def github_repositories(page:int=Query(1,ge=1,le=1000),user:User=Depends(current_user)):
    rows=await github(f'/user/repos?per_page=30&page={page}&sort=updated&affiliation=owner,collaborator,organization_member',decrypt(user.encrypted_token))
    return {'repositories':[{k:r.get(k) for k in ['full_name','html_url','private','language','default_branch']} for r in rows],'has_more':len(rows)==30}
@app.get('/api/repositories/{id}/branches')
async def repository_branches(id:str,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    r=owned(db,Repository,id,user)
    rows=await github('/repos/'+r.full_name+'/branches?per_page=100',decrypt(user.encrypted_token))
    result=[{'name':b['name'],'commit':b['commit']['sha']} for b in rows]
    if r.data['default_branch'] not in [b['name'] for b in result]:
        default=await github('/repos/'+r.full_name+'/branches/'+quote(r.data['default_branch'],safe=''),decrypt(user.encrypted_token))
        result.insert(0,{'name':default['name'],'commit':default['commit']['sha']})
    return result
class StartScan(BaseModel):
    branch:str|None=Field(default=None,min_length=1,max_length=200)
    commit:str|None=Field(default=None,pattern='^[a-fA-F0-9]{40}$')
    pull_request:int|None=Field(default=None,ge=1,le=100000000)
    tag:str|None=Field(default=None,min_length=1,max_length=200)
@app.post('/api/repositories/{id}/scan',status_code=202)
async def start_scan(id:str,body:StartScan=Body(default=StartScan()),user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    r=owned(db,Repository,id,user)
    from .operations import reconcile_stale
    reconcile_stale(db,user.id)
    from .revisions import resolve_revision
    revision=await resolve_revision(r,body,decrypt(user.encrypted_token),github)
    # Serialize tenant quota decisions in Postgres, including simultaneous submissions.
    db.execute(select(User).where(User.id==user.id).with_for_update()).first()
    active=db.scalar(select(func.count()).select_from(Scan).where(Scan.user_id==user.id,Scan.status.in_(['queued','running'])))
    if active>=2:raise HTTPException(429,'At most two scans may run at once')
    from datetime import datetime,timezone,timedelta
    cutoff=(datetime.now(timezone.utc)-timedelta(hours=1)).isoformat()
    count=db.scalar(select(func.count()).select_from(Scan).where(Scan.user_id==user.id,Scan.created_at>=cutoff))
    if count>=10:raise HTTPException(429,'Hourly scan limit reached')
    s=Scan(repository_id=r.id,user_id=user.id,data=revision);db.add(s);db.flush();db.add(Audit(user_id=user.id,action='start_scan',target=s.id));db.commit()
    from .worker import run_scan
    try:run_scan.delay(s.id)
    except Exception:
        s.status='failed';s.data={**s.data,'error':'Scan queue is unavailable. Please retry later.'};db.commit();raise HTTPException(503,'Scan queue is unavailable')
    return scan_json(db,s)
@app.get('/api/scans/{id}')
def scan(id:str,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    from .operations import reconcile_stale
    reconcile_stale(db,user.id)
    return scan_json(db,owned(db,Scan,id,user))
@app.get('/api/scans/{id}/status')
def scan_status(id:str,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    s=owned(db,Scan,id,user)
    return {'id':s.id,'status':s.status,'stage':s.stage,'events':[e.data for e in db.scalars(select(Event).where(Event.scan_id==id).order_by(Event.created_at))]}
@app.get('/api/scans/{id}/findings')
def findings(id:str,user:User=Depends(current_user),db:DBSession=Depends(get_db)):return scan_json(db,owned(db,Scan,id,user))['findings']
@app.get('/api/scans/{id}/diagnosis')
def diagnosis(id:str,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    s=owned(db,Scan,id,user);return {'score':s.score,**s.data}
@app.get('/api/repositories/{id}/history')
def history(id:str,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    owned(db,Repository,id,user)
    from .operations import reconcile_stale
    reconcile_stale(db,user.id)
    return [{'id':s.id,'created_at':s.created_at,'status':s.status,'score':s.score,'diff':s.data.get('diff'),'branch':s.data.get('branch'),'commit':s.data.get('commit')} for s in db.scalars(select(Scan).where(Scan.repository_id==id,Scan.user_id==user.id).order_by(Scan.created_at.desc()))]
class Triage(BaseModel):status:str=Field(pattern='^(open|fixed)$')
@app.patch('/api/findings/{id}')
def triage(id:str,body:Triage,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    f=owned(db,Finding,id,user);f.status=body.status
    db.add(Audit(user_id=user.id,action='triage_'+body.status,target=id));db.commit()
    return {'id':id,'status':f.status,'verified':False}
@app.post('/api/findings/{id}/explain')
async def explain_finding(id:str,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    f=owned(db,Finding,id,user)
    # Bound paid explanation calls per tenant, including concurrent requests.
    db.execute(select(User).where(User.id==user.id).with_for_update()).first()
    from datetime import datetime,timezone,timedelta
    cutoff=(datetime.now(timezone.utc)-timedelta(hours=1)).isoformat()
    count=db.scalar(select(func.count()).select_from(Audit).where(Audit.user_id==user.id,Audit.action=='explain',Audit.created_at>=cutoff))
    if count>=30:raise HTTPException(429,'Explanation limit reached')
    db.add(Audit(user_id=user.id,action='explain',target=f.id));db.commit()
    from .reports import explain
    return await explain(f.data)
@app.get('/api/scans/{id}/report')
def report(id:str,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    return scan_json(db,owned(db,Scan,id,user))


@app.get('/ready')
def readiness(db:DBSession=Depends(get_db)):
    from .operations import service_status
    status = service_status(db)
    return JSONResponse({'ready': status['ready']}, status_code=200 if status['ready'] else 503)

@app.get('/api/system/status')
def system_status(user:User=Depends(current_user), db:DBSession=Depends(get_db)):
    from .operations import service_status
    return service_status(db, include_worker=True)

class StartRuntime(BaseModel):
    target_url: str = Field(max_length=500)
    paths: list[str] = Field(default_factory=list, max_length=5)
    source_scan_id: str
    authorized: bool = False
    deployment_commit: str = Field(default='',max_length=40,pattern='^([a-fA-F0-9]{40})?$')
    browser: bool = True
    cloud_applicable: bool = True

def runtime_json(s):
    return {**s.data, 'id': s.id, 'created_at': s.created_at, 'status': s.status, 'source_scan_id': s.source_scan_id}

@app.post('/api/repositories/{id}/runtime-scans', status_code=202)
def start_runtime(id:str, body:StartRuntime, user:User=Depends(current_user), db:DBSession=Depends(get_db)):
    from .runtime import target_url, route_path
    from .operations import reconcile_stale
    from urllib.parse import urlsplit
    from datetime import datetime, timezone, timedelta
    owned(db, Repository, id, user)
    source = owned(db, Scan, body.source_scan_id, user)
    if source.repository_id != id or source.status not in ('completed', 'partial'):
        raise HTTPException(422, 'Choose a completed or partial assessment of this repository.')
    if not body.authorized:
        raise HTTPException(422, 'Confirm authorization to inspect this deployment.')
    try:
        target = target_url(body.target_url)
        paths = list(dict.fromkeys(route_path(p) for p in body.paths))
    except ValueError as e:
        raise HTTPException(422, str(e))
    allowed = {h.strip().lower() for h in settings().runtime_allowed_hosts.split(',') if h.strip()}
    if urlsplit(target).hostname not in allowed:
        raise HTTPException(422, 'This hostname must be added to RUNTIME_ALLOWED_HOSTS by the deployment operator.')
    reconcile_stale(db, user.id)
    db.execute(select(User).where(User.id == user.id).with_for_update()).first()
    active = db.scalar(select(func.count()).select_from(RuntimeScan).where(RuntimeScan.user_id == user.id, RuntimeScan.status.in_(['queued', 'running'])))
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    count = db.scalar(select(func.count()).select_from(RuntimeScan).where(RuntimeScan.user_id == user.id, RuntimeScan.created_at >= cutoff))
    if active >= 1 or count >= 6:
        raise HTTPException(429, 'One runtime scan may run at once, with six starts per hour.')
    scan = RuntimeScan(repository_id=id, user_id=user.id, source_scan_id=source.id, data={'target_url': target, 'paths': paths, 'authorized': True,'deployment_commit':body.deployment_commit.lower(),'browser':body.browser,'cloud_applicable':body.cloud_applicable})
    db.add(scan); db.flush()
    db.add(Audit(user_id=user.id, action='start_runtime_scan', target=scan.id))
    db.commit()
    from .worker import run_runtime
    try:
        run_runtime.delay(scan.id)
    except Exception:
        scan.status = 'failed'
        scan.data = {**scan.data, 'error': 'Runtime queue unavailable. Please retry later.', 'decision': 'INCOMPLETE'}
        db.commit()
        raise HTTPException(503, 'Runtime queue unavailable')
    return runtime_json(scan)

@app.get('/api/repositories/{id}/runtime-scans')
def runtime_history(id:str, user:User=Depends(current_user), db:DBSession=Depends(get_db)):
    owned(db, Repository, id, user)
    from .operations import reconcile_stale
    reconcile_stale(db, user.id)
    return [runtime_json(s) for s in db.scalars(select(RuntimeScan).where(RuntimeScan.repository_id == id, RuntimeScan.user_id == user.id).order_by(RuntimeScan.created_at.desc()).limit(50))]

@app.get('/api/runtime-scans/{id}')
def runtime_result(id:str, user:User=Depends(current_user), db:DBSession=Depends(get_db)):
    from .operations import reconcile_stale
    reconcile_stale(db, user.id)
    return runtime_json(owned(db, RuntimeScan, id, user))

from .lifecycle_api import router as lifecycle_router
app.include_router(lifecycle_router)

from .organizations import router as organization_router
app.include_router(organization_router)
