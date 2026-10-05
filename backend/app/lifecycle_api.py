"""Repository-scoped lifecycle APIs. All external writes require explicit review."""
import secrets,time
from datetime import datetime,timezone,timedelta
from typing import Literal
from fastapi import APIRouter,Depends,HTTPException,Request,Query
from pydantic import BaseModel,Field,ConfigDict
from sqlalchemy import select,or_
from sqlalchemy.orm import Session as DBSession
from .db import get_db,User,Repository,Scan,Finding,RuntimeScan,RepositoryMember,PolicyVersion,LifecycleEvent,GateToken,RemediationPatch
from .security import current_user,secret_hash,redact
from .lifecycle import build_graph,graph_diff,prioritize,memory,decide,DEFAULT_POLICY,finding_key,traverse,configuration_findings
router=APIRouter(prefix='/api/lifecycle')
PERMISSIONS={'Owner':{'read','scan','policy','accept','override','members','remediate'},'Admin':{'read','scan','policy','accept','override','remediate'},'Security Lead':{'read','scan','policy','accept','remediate'},'Developer':{'read','scan','remediate'},'Viewer':{'read'}}

def access(db,repo_id,user,permission='read'):
    repo=db.get(Repository,repo_id)
    if not repo:raise HTTPException(404,'Repository not found')
    member=db.scalar(select(RepositoryMember).where(RepositoryMember.repository_id==repo_id,RepositoryMember.user_id==user.id))
    role='Owner' if repo.user_id==user.id else member.role if member else None
    if role is None:raise HTTPException(404,'Repository not found')
    if permission not in PERMISSIONS.get(role,set()):raise HTTPException(403,'Your role does not allow this action')
    return repo,role

def event(db,rid,uid,kind,data):
    row=LifecycleEvent(repository_id=rid,user_id=uid,kind=kind,data=data);db.add(row);return row

def read_scan(db,s):
    return {**s.data,'id':s.id,'created_at':s.created_at,'score':s.score,'status':s.status,'findings':[{**f.data,'id':f.id,'triage_status':f.status} for f in db.scalars(select(Finding).where(Finding.scan_id==s.id))]+configuration_findings(s.data)}

def selected_scan(db,rid,scan_id=None):
    scan=db.get(Scan,scan_id) if scan_id else db.scalar(select(Scan).where(Scan.repository_id==rid,Scan.status.in_(['completed','partial'])).order_by(Scan.created_at.desc()))
    if not scan or scan.repository_id!=rid:raise HTTPException(404,'Choose an assessed scan from this repository')
    return scan

def policy(db,rid):
    row=db.scalar(select(PolicyVersion).where(PolicyVersion.repository_id==rid).order_by(PolicyVersion.created_at.desc()))
    return ({**DEFAULT_POLICY,**row.data},row.id) if row else (DEFAULT_POLICY.copy(),'default-v1')

def analysis(db,rid,scan_id=None,before_id=None):
    scan=selected_scan(db,rid,scan_id);s=read_scan(db,scan)
    rows=list(db.scalars(select(Scan).where(Scan.repository_id==rid,Scan.created_at<=scan.created_at,Scan.status.in_(['completed','partial'])).order_by(Scan.created_at.desc()).limit(100)))
    branch=s.get('branch');same=[r for r in rows if r.data.get('branch')==branch]
    hist=[read_scan(db,r) for r in reversed(same)]
    mem=memory(hist);graph=s.get('security_graph') or build_graph(s,s['findings'])
    prior=selected_scan(db,rid,before_id) if before_id else next((r for r in same if r.id!=scan.id),None)
    diff=None
    if prior:
        old=read_scan(db,prior);diff=graph_diff(old.get('security_graph') or build_graph(old,old['findings']),graph)
        comparable=prior.status==scan.status=='completed' and prior.data.get('branch')==branch and prior.created_at<scan.created_at
        diff.update(before=prior.id,after=scan.id,before_commit=old.get('commit'),after_commit=s.get('commit'),comparable=comparable,previous_score=prior.score,current_score=scan.score,regression=bool(comparable and prior.score is not None and scan.score is not None and scan.score<prior.score))
        diff['causality']='Changed declarations and score movement are correlated; exact causal attribution is unverified.'
    runtime=db.scalar(select(RuntimeScan).where(RuntimeScan.repository_id==rid,RuntimeScan.source_scan_id==scan.id).order_by(RuntimeScan.created_at.desc()))
    run={**runtime.data,'status':runtime.status,'source_commit':runtime.data.get('deployment_identity',{}).get('declared_deployment_commit')} if runtime else None
    priorities=prioritize(s['findings'],s,{r['key']:r['occurrences'] for r in mem['patterns']},run)
    rules,revision=policy(db,rid);decision=decide(s,priorities,rules,diff,run)
    decision['policy_revision']=revision
    import hashlib,json
    decision['evidence_digest']=hashlib.sha256(json.dumps({'decision':decision,'runtime_id':runtime.id if runtime else None},sort_keys=True).encode()).hexdigest()
    paths=[];byid={n['id']:n for n in graph['nodes']}
    for n in graph['nodes']:
        if n['type']!='API Route':continue
        walk=traverse(graph,n['id'])
        for chain in walk['paths']:
            target=byid[chain[-1]]
            if target['type']=='Finding':paths.append({'entry':n['label'],'node_ids':chain,'finding':target['label'],'severity':target.get('severity'),'confidence':'Static association','exploitability':'Unverified','note':'Potential route/import path; authorization and sensitive data access not proven.'})
        if len(paths)>=100:break
    return {'available_scans':[{'id':r.id,'commit':r.data.get('commit'),'branch':r.data.get('branch'),'at':r.created_at} for r in rows], 'scan':{k:s.get(k) for k in ('id','commit','branch','created_at','score','status')},'graph':graph,'diff':diff,'memory':mem,'priorities':priorities,'decision':decision,'paths':paths[:100],'runtime':run,'history_limit':100}

@router.get('/repositories')
def repositories(user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    grants=select(RepositoryMember.repository_id).where(RepositoryMember.user_id==user.id)
    rows=db.scalars(select(Repository).where(or_(Repository.user_id==user.id,Repository.id.in_(grants))))
    return [{'id':r.id,'name':r.full_name,'role':access(db,r.id,user)[1],**{k:r.data.get(k) for k in ('score','last_scan')}} for r in rows]

@router.get('/repositories/{rid}')
def overview(rid:str,scan_id:str|None=None,before_id:str|None=None,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    _,role=access(db,rid,user);return {**analysis(db,rid,scan_id,before_id),'role':role,'permissions':sorted(PERMISSIONS[role])}

@router.get('/repositories/{rid}/activity')
def activity(rid:str,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    access(db,rid,user)
    rows=[{'id':e.id,'kind':e.kind,'at':e.created_at,'actor':e.user_id,'data':e.data} for e in db.scalars(select(LifecycleEvent).where(LifecycleEvent.repository_id==rid).order_by(LifecycleEvent.created_at.desc()).limit(200))]
    for s in db.scalars(select(Scan).where(Scan.repository_id==rid).order_by(Scan.created_at.desc()).limit(100)):
        rows.append({'id':s.id,'kind':'repository_scan','at':s.created_at,'actor':s.user_id,'data':{'status':s.status,'commit':s.data.get('commit'),'score':s.score,'decision':s.data.get('decision')}})
    return sorted(rows,key=lambda r:r['at'],reverse=True)[:200]

class PolicyInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    minimum_score:int=Field(default=75,ge=0,le=100)
    block_critical:bool=True
    block_high:bool=False
    block_secret:bool=True
    block_regression:bool=True
    review_external_changes:bool=True
    require_runtime:bool=True
    reason:str=Field(min_length=10,max_length=500)

@router.post('/repositories/{rid}/policies')
def save_policy(rid:str,body:PolicyInput,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    access(db,rid,user,'policy');data=body.model_dump(exclude={'reason'});row=PolicyVersion(repository_id=rid,user_id=user.id,data=data);db.add(row);db.flush()
    event(db,rid,user.id,'policy_changed',{'policy_revision':row.id,'policy':data,'reason':redact(body.reason)});db.commit();return {'revision':row.id,'policy':data}

class MemberInput(BaseModel):
    login:str=Field(min_length=1,max_length=100)
    role:Literal['Admin','Security Lead','Developer','Viewer']

@router.get('/repositories/{rid}/members')
def members(rid:str,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    repo,_=access(db,rid,user);owner=db.get(User,repo.user_id)
    rows=[{'user_id':owner.id,'login':owner.login,'role':'Owner'}]
    for m in db.scalars(select(RepositoryMember).where(RepositoryMember.repository_id==rid)):
        u=db.get(User,m.user_id);rows.append({'user_id':u.id,'login':u.login,'role':m.role})
    return rows

@router.post('/repositories/{rid}/members')
def member(rid:str,body:MemberInput,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    repo,_=access(db,rid,user,'members');target=db.scalar(select(User).where(User.login==body.login))
    if not target:raise HTTPException(422,'This person must sign in with GitHub first')
    if target.id==repo.user_id:raise HTTPException(422,'Repository owner role cannot be changed here')
    row=db.scalar(select(RepositoryMember).where(RepositoryMember.repository_id==rid,RepositoryMember.user_id==target.id))
    if not row:row=RepositoryMember(repository_id=rid,user_id=target.id,role=body.role);db.add(row)
    row.role=body.role;event(db,rid,user.id,'member_role_changed',{'user_id':target.id,'role':body.role});db.commit();return {'saved':True}

@router.post('/repositories/{rid}/members/{uid}/revoke')
def revoke_member(rid:str,uid:str,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    access(db,rid,user,'members');row=db.scalar(select(RepositoryMember).where(RepositoryMember.repository_id==rid,RepositoryMember.user_id==uid))
    if row:db.delete(row);event(db,rid,user.id,'member_revoked',{'user_id':uid});db.commit()
    return {'revoked':True}

class ReasonInput(BaseModel):
    reason:str=Field(min_length=10,max_length=1000)
    finding_refs:list[str]=Field(default_factory=list,max_length=100)
    scan_id:str

@router.post('/repositories/{rid}/overrides')
def override(rid:str,body:ReasonInput,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    access(db,rid,user,'override');result=analysis(db,rid,body.scan_id);decision=result['decision']
    if decision['gaps']:raise HTTPException(409,'Incomplete evidence cannot be overridden')
    if decision['allowed']:raise HTTPException(409,'This decision does not need an override')
    known={f.get('fingerprint') for f in result['priorities']}
    if not set(body.finding_refs)<=known:raise HTTPException(422,'Unknown finding references')
    required={f for b in decision['blockers'] for f in b['finding_refs']}
    if not required<=set(body.finding_refs):raise HTTPException(422,'Reference every blocking finding')
    e=event(db,rid,user.id,'deployment_override',{'scan_id':body.scan_id,'commit':result['scan']['commit'],'policy_revision':decision['policy_revision'],'evidence_digest':decision['evidence_digest'],'reason':redact(body.reason),'finding_refs':body.finding_refs,'expires_at':(datetime.now(timezone.utc)+timedelta(hours=24)).isoformat()});db.flush();db.commit();return {'id':e.id,'recorded':True,'expires_in_hours':24}

class Acceptance(ReasonInput):
    status:Literal['accepted_risk','ignored','reopened']
@router.post('/repositories/{rid}/triage')
def triage(rid:str,body:Acceptance,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    access(db,rid,user,'accept');scan=selected_scan(db,rid,body.scan_id);known={f.get('fingerprint') for f in read_scan(db,scan)['findings']}
    if not body.finding_refs or not set(body.finding_refs)<=known:raise HTTPException(422,'Select findings from this scan')
    event(db,rid,user.id,'finding_'+body.status,body.model_dump()|{'reason':redact(body.reason)});db.commit();return {'recorded':True,'note':'Acceptance is audited; it does not erase evidence or bypass deployment policy.'}

@router.get('/repositories/{rid}/audit')
def audit(rid:str,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    access(db,rid,user);rows=list(db.scalars(select(Scan).where(Scan.repository_id==rid).order_by(Scan.created_at.desc()).limit(100)))
    return {'repository_id':rid,'exported_at':datetime.now(timezone.utc).isoformat(),'scope':'Last 100 scans and 200 activity events; not a certification','scans':[read_scan(db,s) for s in rows],'activity':activity(rid,user,db),'policies':[{'id':p.id,'at':p.created_at,'actor':p.user_id,'policy':p.data} for p in db.scalars(select(PolicyVersion).where(PolicyVersion.repository_id==rid))]}

@router.post('/repositories/{rid}/gate-tokens')
def token(rid:str,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    access(db,rid,user,'policy');raw=secrets.token_urlsafe(40);expires=int(time.time())+30*86400
    # One active CI credential per repository; rotation invalidates the old token.
    for old in db.scalars(select(GateToken).where(GateToken.repository_id==rid)):db.delete(old)
    db.add(GateToken(id=secret_hash(raw),repository_id=rid,user_id=user.id,expires=expires));event(db,rid,user.id,'gate_token_rotated',{'expires':expires});db.commit();return {'token':raw,'expires':expires,'note':'Shown once. Store as a GitHub Actions secret.'}

@router.get('/gate/{rid}')
def gate(rid:str,request:Request,commit:str=Query(pattern='^[a-fA-F0-9]{40}$'),db:DBSession=Depends(get_db)):
    authorization=request.headers.get('authorization','')
    row=db.get(GateToken,secret_hash(authorization.removeprefix('Bearer '))) if authorization.startswith('Bearer ') else None
    if not row or row.repository_id!=rid or row.expires<int(time.time()):raise HTTPException(401,'Invalid or expired repository gate token')
    # Revoked membership also revokes capabilities minted by that member.
    actor=db.get(User,row.user_id);access(db,rid,actor,'policy')
    scans=db.scalars(select(Scan).where(Scan.repository_id==rid).order_by(Scan.created_at.desc()).limit(200))
    scan=next((s for s in scans if s.data.get('commit','').lower()==commit.lower()),None)
    if not scan:return {'allowed':False,'decision':'INCOMPLETE','gaps':['No assessment for this exact commit']}
    result=analysis(db,rid,scan.id);decision=result['decision'];overrides=db.scalars(select(LifecycleEvent).where(LifecycleEvent.repository_id==rid,LifecycleEvent.kind=='deployment_override').order_by(LifecycleEvent.created_at.desc()))
    override=next((e for e in overrides if e.data.get('scan_id')==scan.id and e.data.get('policy_revision')==decision['policy_revision'] and e.data.get('evidence_digest')==decision['evidence_digest'] and e.data.get('expires_at','')>datetime.now(timezone.utc).isoformat()),None)
    if override and not decision['gaps']:
        # Re-check the override author's current authority.
        try:access(db,rid,db.get(User,override.user_id),'override');decision={**decision,'allowed':True,'override_id':override.id,'decision':'OVERRIDDEN'}
        except HTTPException:pass
    event(db,rid,row.user_id,'gate_evaluated',{'commit':commit,'scan_id':scan.id,'decision':decision['decision'],'policy_revision':decision['policy_revision']});db.commit()
    return {**decision,'scan_id':scan.id,'commit':commit}

class PatchInput(BaseModel):
    finding_id:str
    version:str=Field(min_length=1,max_length=80,pattern=r'^[0-9A-Za-z.+!-]+$')

@router.post('/repositories/{rid}/patches')
async def generate_patch(rid:str,body:PatchInput,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    from .security import decrypt
    from .remediation import gh,decode_file,dependency_patch
    from urllib.parse import quote
    import hashlib
    repo,_=access(db,rid,user,'remediate');f=db.get(Finding,body.finding_id)
    if not f:raise HTTPException(404,'Finding not found')
    scan=selected_scan(db,rid,f.scan_id);commit=scan.data.get('commit','');path=f.data.get('file','')
    if not __import__('re').fullmatch(r'[a-f0-9]{40}',commit):raise HTTPException(422,'A commit-pinned assessment is required')
    if path.startswith('/') or '..' in path.split('/') or not path.endswith('requirements.txt'):raise HTTPException(422,'Only repository-relative requirements.txt pins are supported')
    owner=db.get(User,repo.user_id);data=await gh('GET',f'/repos/{repo.full_name}/contents/{quote(path,safe="/")}?ref={commit}',decrypt(owner.encrypted_token))
    text=decode_file(data)
    try:updated,diff=dependency_patch(text,f.data,body.version)
    except ValueError as e:raise HTTPException(422,str(e))
    patch=RemediationPatch(repository_id=rid,user_id=user.id,data={'finding_id':f.id,'fingerprint':f.data.get('fingerprint'),'scan_id':scan.id,'commit':commit,'branch':scan.data.get('branch'),'path':path,'file_sha':data['sha'],'version':body.version,'diff':redact(diff),'content_digest':hashlib.sha256(updated.encode()).hexdigest(),'confidence':'Needs manual compatibility review','validation':['Exact pinned dependency matched','Replacement listed by advisory','Replacement version increases'],'not_validated':['Application compatibility','Other advisories','Tests (repository code is never executed)']})
    db.add(patch);db.flush();event(db,rid,user.id,'patch_generated',{'patch_id':patch.id,'finding_id':f.id});db.commit();return {'id':patch.id,'status':patch.status,**patch.data}

@router.get('/repositories/{rid}/patches')
def patches(rid:str,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    access(db,rid,user);return [{'id':p.id,'status':p.status,'at':p.created_at,**p.data} for p in db.scalars(select(RemediationPatch).where(RemediationPatch.repository_id==rid).order_by(RemediationPatch.created_at.desc()).limit(100))]

class ReviewInput(BaseModel):
    reviewed:bool
    reason:str=Field(min_length=10,max_length=500)

@router.post('/repositories/{rid}/patches/{pid}/pull-request')
async def create_pr(rid:str,pid:str,body:ReviewInput,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    from .security import decrypt
    from .remediation import gh,decode_file,dependency_patch
    from urllib.parse import quote
    import base64,hashlib
    repo,_=access(db,rid,user,'remediate')
    patch=db.scalar(select(RemediationPatch).where(RemediationPatch.id==pid).with_for_update())
    if not patch or patch.repository_id!=rid:raise HTTPException(404,'Patch not found')
    if not body.reviewed:raise HTTPException(422,'Review the complete patch and compatibility limits first')
    if patch.status!='review':raise HTTPException(409,'Patch already submitted or an earlier attempt needs reconciliation')
    d=patch.data;token=decrypt(user.encrypted_token)
    # Use the reviewing developer's GitHub authorization for writes, never owner credentials.
    branch=await gh('GET',f'/repos/{repo.full_name}/branches/{quote(d["branch"],safe="")}',token)
    if branch['commit']['sha']!=d['commit']:raise HTTPException(409,'Base branch changed. Rescan and regenerate the patch.')
    original=await gh('GET',f'/repos/{repo.full_name}/contents/{quote(d["path"],safe="/")}?ref={d["commit"]}',token)
    finding=db.get(Finding,d['finding_id'])
    try:updated,_=dependency_patch(decode_file(original),finding.data,d['version'])
    except ValueError as e:raise HTTPException(409,str(e))
    if hashlib.sha256(updated.encode()).hexdigest()!=d['content_digest'] or original['sha']!=d['file_sha']:raise HTTPException(409,'Patch content no longer matches the reviewed artifact')
    new_branch='security-doctor/'+patch.id
    patch.status='creating';patch.data={**d,'draft_branch':new_branch,'reviewer':user.id,'review_reason':redact(body.reason)};db.commit()
    try:
        await gh('POST',f'/repos/{repo.full_name}/git/refs',token,{'ref':'refs/heads/'+new_branch,'sha':d['commit']})
        commit=await gh('PUT',f'/repos/{repo.full_name}/contents/{quote(d["path"],safe="/")}',token,{'message':'security: update vulnerable dependency pin','content':base64.b64encode(updated.encode()).decode(),'sha':d['file_sha'],'branch':new_branch})
        pr=await gh('POST',f'/repos/{repo.full_name}/pulls',token,{'title':'security: update reviewed dependency pin','head':new_branch,'base':d['branch'],'draft':True,'body':'Updates a dependency pin linked to finding '+finding.id+'.\n\nValidated: exact pin, advisory-listed fixed version, unchanged base commit.\nNot validated: application tests, compatibility or complete remediation. Review CI and rescan after merge.\n\nReviewer reason: '+redact(body.reason)})
        patch.status='pull_request';patch.data={**patch.data,'pull_request_url':pr['html_url'],'pull_request_number':pr['number'],'patch_commit':commit['commit']['sha']};event(db,rid,user.id,'remediation_pr_created',{'patch_id':pid,'url':pr['html_url']});db.commit()
        return {'url':pr['html_url'],'draft':True}
    except Exception:
        patch.status='needs_reconciliation';db.commit();raise

@router.post('/repositories/{rid}/patches/{pid}/verify')
async def verify_patch(rid:str,pid:str,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    from .remediation import gh
    from .security import decrypt
    repo,_=access(db,rid,user,'remediate');p=db.get(RemediationPatch,pid)
    if not p or p.repository_id!=rid:raise HTTPException(404,'Patch not found')
    if not p.data.get('pull_request_number'):raise HTTPException(409,'No pull request is recorded')
    pr=await gh('GET',f'/repos/{repo.full_name}/pulls/{p.data["pull_request_number"]}',decrypt(user.encrypted_token))
    if not pr.get('merged'):return {'status':'awaiting_merge'}
    # Verify only an exact merge-commit scan, never an unrelated newer result.
    scans=db.scalars(select(Scan).where(Scan.repository_id==rid,Scan.status=='completed').order_by(Scan.created_at.desc()).limit(100))
    s=next((s for s in scans if s.data.get('commit')==pr.get('merge_commit_sha')),None)
    if not s:return {'status':'rescan_required','commit':pr.get('merge_commit_sha'),'branch':pr['base']['ref']}
    original=db.get(Finding,p.data['finding_id'])
    remaining=any(finding_key(f.data)==finding_key(original.data) for f in db.scalars(select(Finding).where(Finding.scan_id==s.id)))
    status='issue_still_present' if remaining else 'not_detected_in_merge_scan';event(db,rid,user.id,'remediation_verified',{'patch_id':pid,'scan_id':s.id,'status':status});db.commit();return {'status':status,'scan_id':s.id,'note':'Finding absence in performed checks is not proof of complete remediation.'}

class SharedScanInput(BaseModel):
    branch:str=Field(min_length=1,max_length=200)
@router.post('/repositories/{rid}/scan',status_code=202)
async def shared_scan(rid:str,body:SharedScanInput,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    repo,_=access(db,rid,user,'scan')
    from .main import start_scan,StartScan
    owner=db.get(User,repo.user_id);result=await start_scan(rid,StartScan(branch=body.branch),owner,db)
    event(db,rid,user.id,'team_scan_requested',{'scan_id':result['id'],'branch':body.branch});db.commit();return result

@router.get('/portfolio')
def portfolio(user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    repos=repositories(user,db);assessments=[];shared={}
    for r in repos[:50]:
        try:a=analysis(db,r['id'])
        except HTTPException:continue
        assessments.append({'repository':r,'scan':a['scan'],'decision':a['decision'],'critical':sum(f.get('severity')=='Critical' for f in a['priorities']),'recurrences':sum(p['reintroduced'] for p in a['memory']['patterns']),'regression':bool((a['diff'] or {}).get('regression'))})
        for n in a['graph']['nodes']:
            if n['type'] in ('Dependency','External API','Auth Provider','Database'):
                key=(n['type'],n['label']);shared.setdefault(key,set()).add(r['id'])
    return {'repositories':assessments,'shared_components':[{'type':k[0],'label':k[1],'repository_ids':sorted(v),'association':'Same declared component name; not proof of the same deployed service'} for k,v in shared.items() if len(v)>1],'scope':'Accessible repositories only; up to 50. No industry benchmark or raw-secret matching.','metrics':{'assessed_repositories':len(assessments),'blocked':sum(a['decision']['decision']=='NOT READY' for a in assessments),'incomplete':sum(a['decision']['decision']=='INCOMPLETE' for a in assessments),'regressions':sum(a['regression'] for a in assessments),'reintroductions':sum(a['recurrences'] for a in assessments)}}

class WebhookInput(BaseModel):
    enabled:bool=True
    branches:list[str]=Field(min_length=1,max_length=10)
@router.post('/repositories/{rid}/webhook')
def configure_webhook(rid:str,body:WebhookInput,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    from .db import WebhookConfig
    from .security import encrypt
    import re
    access(db,rid,user,'policy')
    if any(not re.fullmatch(r'[A-Za-z0-9_./-]{1,200}',b) or b.startswith('-') or '..' in b for b in body.branches):raise HTTPException(422,'Use exact valid branch names')
    raw=secrets.token_urlsafe(40);row=db.get(WebhookConfig,rid)
    if not row:row=WebhookConfig(repository_id=rid,encrypted_secret=encrypt(raw));db.add(row)
    row.encrypted_secret=encrypt(raw);row.data={'enabled':body.enabled,'branches':body.branches};event(db,rid,user.id,'webhook_configured',row.data);db.commit()
    return {'secret':raw,'path':'/api/lifecycle/webhooks/github/'+rid,'events':['push','pull_request'],'note':'Configure this webhook in GitHub using HTTPS and this secret. Rotating invalidates the previous signature secret.'}

@router.post('/webhooks/github/{rid}')
async def webhook(rid:str,request:Request,db:DBSession=Depends(get_db)):
    import hmac,hashlib,json,re
    from sqlalchemy.exc import IntegrityError
    from .db import WebhookConfig,WebhookDelivery
    from .security import decrypt
    config=db.get(WebhookConfig,rid)
    if not config or not config.data.get('enabled'):raise HTTPException(404,'Webhook not enabled')
    body=b''
    async for chunk in request.stream():
        body+=chunk
        if len(body)>1000000:raise HTTPException(413,'Webhook payload too large')
    expected='sha256='+hmac.new(decrypt(config.encrypted_secret).encode(),body,hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected,request.headers.get('x-hub-signature-256','')):raise HTTPException(401,'Invalid webhook signature')
    try:payload=json.loads(body)
    except ValueError:raise HTTPException(422,'Invalid JSON')
    repo=db.get(Repository,rid)
    if payload.get('repository',{}).get('full_name')!=repo.full_name:raise HTTPException(403,'Repository does not match webhook')
    delivery=request.headers.get('x-github-delivery','')
    if not re.fullmatch(r'[A-Za-z0-9-]{10,100}',delivery):raise HTTPException(422,'Invalid delivery identifier')
    kind=request.headers.get('x-github-event','');branch=None
    if kind=='ping':return {'received':True}
    if kind=='push' and not payload.get('deleted') and payload.get('ref','').startswith('refs/heads/'):branch=payload['ref'][11:]
    elif kind=='pull_request' and payload.get('action')=='closed' and payload.get('pull_request',{}).get('merged'):branch=payload['pull_request']['base']['ref']
    if branch not in config.data.get('branches',[]):return {'ignored':True,'reason':'Event or branch not subscribed'}
    row=WebhookDelivery(id=rid+':'+delivery,repository_id=rid);db.add(row)
    try:db.commit()
    except IntegrityError:db.rollback();return {'duplicate':True}
    try:
        from .main import start_scan,StartScan
        owner=db.get(User,repo.user_id);result=await start_scan(rid,StartScan(branch=branch),owner,db)
        row.status='queued';event(db,rid,owner.id,'webhook_scan_queued',{'delivery':delivery,'scan_id':result['id'],'branch':branch,'trigger':kind});db.commit();return {'scan_id':result['id']}
    except HTTPException:
        row.status='failed';event(db,rid,repo.user_id,'webhook_scan_failed',{'delivery':delivery,'branch':branch,'note':'Queue, authorization or scan quota prevented dispatch; manually retry the scan.'});db.commit();raise
