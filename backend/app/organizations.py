"""Organization grants and policy floors. Existing repository ownership is preserved."""
from fastapi import APIRouter,Depends,HTTPException
from pydantic import BaseModel,Field
from typing import Literal
from sqlalchemy import select,or_
from sqlalchemy.orm import Session as DBSession
from .db import get_db,User,Repository,Organization,OrganizationMember,OrganizationRepository,OrganizationPolicy,OrganizationEvent
from .security import current_user,redact
router=APIRouter(prefix='/api/organizations')

def org_access(db,oid,user,write=False,owner_only=False):
    org=db.get(Organization,oid)
    if not org:raise HTTPException(404,'Organization not found')
    member=db.scalar(select(OrganizationMember).where(OrganizationMember.organization_id==oid,OrganizationMember.user_id==user.id))
    role='Owner' if org.owner_id==user.id else member.role if member else None
    if role is None:raise HTTPException(404,'Organization not found')
    if owner_only and role!='Owner' or write and role not in ('Owner','Admin','Security Lead'):raise HTTPException(403,'Organization role does not allow this action')
    return org,role

def organization_role(db,rid,uid):
    link=db.get(OrganizationRepository,rid)
    if not link:return None
    org=db.get(Organization,link.organization_id)
    if org.owner_id==uid:return 'Admin'
    m=db.scalar(select(OrganizationMember).where(OrganizationMember.organization_id==org.id,OrganizationMember.user_id==uid))
    return m.role if m else None

def effective_policy(db,rid,repo_policy,repo_revision):
    link=db.get(OrganizationRepository,rid)
    if not link:return repo_policy,repo_revision
    row=db.scalar(select(OrganizationPolicy).where(OrganizationPolicy.organization_id==link.organization_id).order_by(OrganizationPolicy.created_at.desc()))
    if not row:return repo_policy,repo_revision
    # A repository policy may strengthen the organization floor, never weaken it.
    result={k:max(value,row.data.get(k,value)) if k=='minimum_score' else bool(value or row.data.get(k,False)) for k,value in repo_policy.items()}
    return result,repo_revision+':org:'+row.id

def org_event(db,oid,uid,kind,data):db.add(OrganizationEvent(organization_id=oid,user_id=uid,kind=kind,data=data))

class CreateOrganization(BaseModel):name:str=Field(min_length=2,max_length=100)
@router.post('')
def create(body:CreateOrganization,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    if len(list(db.scalars(select(Organization.id).where(Organization.owner_id==user.id))))>=10:raise HTTPException(429,'Organization limit reached')
    org=Organization(owner_id=user.id,name=redact(body.name));db.add(org);db.flush();org_event(db,org.id,user.id,'created',{});db.commit();return {'id':org.id,'name':org.name,'role':'Owner'}
@router.get('')
def organizations(user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    granted=select(OrganizationMember.organization_id).where(OrganizationMember.user_id==user.id)
    return [{'id':o.id,'name':o.name,'role':org_access(db,o.id,user)[1]} for o in db.scalars(select(Organization).where(or_(Organization.owner_id==user.id,Organization.id.in_(granted))))]

class Member(BaseModel):
    login:str=Field(min_length=1,max_length=100)
    role:Literal['Admin','Security Lead','Developer','Viewer']
@router.post('/{oid}/members')
def add_member(oid:str,body:Member,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    org,_=org_access(db,oid,user,owner_only=True);target=db.scalar(select(User).where(User.login==body.login))
    if not target:raise HTTPException(422,'User must sign in with GitHub first')
    if target.id==org.owner_id:raise HTTPException(422,'Organization owner cannot be demoted here')
    m=db.scalar(select(OrganizationMember).where(OrganizationMember.organization_id==oid,OrganizationMember.user_id==target.id))
    if not m:m=OrganizationMember(organization_id=oid,user_id=target.id,role=body.role);db.add(m)
    m.role=body.role;org_event(db,oid,user.id,'member_granted',{'user_id':target.id,'role':body.role});db.commit();return {'saved':True}
@router.post('/{oid}/members/{uid}/revoke')
def revoke(oid:str,uid:str,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    org_access(db,oid,user,owner_only=True);m=db.scalar(select(OrganizationMember).where(OrganizationMember.organization_id==oid,OrganizationMember.user_id==uid))
    if m:db.delete(m);org_event(db,oid,user.id,'member_revoked',{'user_id':uid});db.commit()
    return {'revoked':True,'note':'Independent repository grants, if any, remain explicit and separate.'}

class Attach(BaseModel):repository_id:str
@router.post('/{oid}/repositories')
def attach(oid:str,body:Attach,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    org_access(db,oid,user,write=True);repo=db.get(Repository,body.repository_id)
    # Granting group access is always an explicit act by the repository owner.
    if not repo or repo.user_id!=user.id:raise HTTPException(404,'Only repositories you own can be attached')
    link=db.get(OrganizationRepository,repo.id)
    if link:raise HTTPException(409,'Repository already belongs to an organization; detach it first')
    db.add(OrganizationRepository(repository_id=repo.id,organization_id=oid,attached_by=user.id));org_event(db,oid,user.id,'repository_attached',{'repository_id':repo.id});db.commit();return {'attached':True}
@router.post('/{oid}/repositories/{rid}/detach')
def detach(oid:str,rid:str,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    org,role=org_access(db,oid,user);repo=db.get(Repository,rid);link=db.get(OrganizationRepository,rid)
    if not link or link.organization_id!=oid:raise HTTPException(404,'Repository not attached')
    if user.id not in (repo.user_id,org.owner_id):raise HTTPException(403,'Repository or organization owner required')
    db.delete(link);org_event(db,oid,user.id,'repository_detached',{'repository_id':rid});db.commit();return {'detached':True}

class PolicyInput(BaseModel):
    minimum_score:int=Field(default=75,ge=0,le=100)
    block_critical:bool=True
    block_high:bool=False
    block_secret:bool=True
    block_regression:bool=True
    review_external_changes:bool=True
    require_runtime:bool=True
    reason:str=Field(min_length=10,max_length=500)
@router.post('/{oid}/policies')
def policy(oid:str,body:PolicyInput,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    org_access(db,oid,user,write=True);p=OrganizationPolicy(organization_id=oid,user_id=user.id,data=body.model_dump(exclude={'reason'}));db.add(p);db.flush();org_event(db,oid,user.id,'policy_changed',{'revision':p.id,'policy':p.data,'reason':redact(body.reason)});db.commit();return {'revision':p.id}

@router.get('/{oid}')
def detail(oid:str,user:User=Depends(current_user),db:DBSession=Depends(get_db)):
    org,role=org_access(db,oid,user)
    rows=list(db.scalars(select(OrganizationRepository).where(OrganizationRepository.organization_id==oid)))
    members=[{'user_id':org.owner_id,'login':db.get(User,org.owner_id).login,'role':'Owner'}]
    members.extend({'user_id':m.user_id,'login':db.get(User,m.user_id).login,'role':m.role} for m in db.scalars(select(OrganizationMember).where(OrganizationMember.organization_id==oid)))
    p=db.scalar(select(OrganizationPolicy).where(OrganizationPolicy.organization_id==oid).order_by(OrganizationPolicy.created_at.desc()))
    events=[{'id':e.id,'kind':e.kind,'at':e.created_at,'actor':e.user_id,'data':e.data} for e in db.scalars(select(OrganizationEvent).where(OrganizationEvent.organization_id==oid).order_by(OrganizationEvent.created_at.desc()).limit(200))]
    from .lifecycle_api import portfolio
    port=portfolio(user,db,organization_id=oid)
    return {'id':org.id,'name':org.name,'role':role,'members':members,'repositories':[{'id':r.repository_id,'name':db.get(Repository,r.repository_id).full_name,'owner_id':db.get(Repository,r.repository_id).user_id} for r in rows],'policy':p.data if p else None,'policy_revision':p.id if p else None,'activity':events,'portfolio':port}
