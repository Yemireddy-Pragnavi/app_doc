"""Resolve and pin source revisions before any job is queued."""
import re
from urllib.parse import quote
from fastapi import HTTPException

def valid_ref(value):
    if not isinstance(value,str) or value.startswith('-') or '..' in value or not re.fullmatch(r'[A-Za-z0-9_./-]{1,200}',value):raise HTTPException(422,'Invalid branch or tag name')
    return value

async def resolve_revision(repo,body,token,github):
    if sum(bool(x) for x in (body.commit,body.pull_request,body.tag))>1:raise HTTPException(422,'Choose one commit, pull request or release tag')
    prefix='/repos/'+repo.full_name
    if body.pull_request:
        pr=await github(prefix+'/pulls/'+str(body.pull_request),token)
        if pr.get('base',{}).get('repo',{}).get('full_name')!=repo.full_name:raise HTTPException(422,'Pull request base repository does not match')
        result={'branch':'pull-request/'+str(body.pull_request),'base_branch':valid_ref(pr['base']['ref']),'requested_commit':pr['head']['sha'],'source_ref':'refs/pull/'+str(body.pull_request)+'/head','revision_kind':'pull_request','pull_request':body.pull_request,'base_commit':pr['base']['sha'],'source_is_fork':(pr['head'].get('repo') or {}).get('full_name')!=repo.full_name}
    elif body.tag:
        tag=valid_ref(body.tag);commit=await github(prefix+'/commits/'+quote('tags/'+tag,safe=''),token)
        result={'branch':'release/'+tag,'base_branch':valid_ref(repo.data.get('default_branch','main')),'requested_commit':commit['sha'],'source_ref':commit['sha'],'revision_kind':'release','tag':tag}
    elif body.commit:
        commit=await github(prefix+'/commits/'+body.commit,token)
        result={'branch':valid_ref(body.branch) if body.branch else 'commit/'+body.commit,'base_branch':valid_ref(repo.data.get('default_branch','main')),'requested_commit':commit['sha'],'source_ref':commit['sha'],'revision_kind':'commit'}
        if commit['sha'].lower()!=body.commit.lower():raise HTTPException(422,'Commit resolution did not match request')
    else:
        name=valid_ref(body.branch or repo.data.get('default_branch','main'));branch=await github(prefix+'/branches/'+quote(name,safe=''),token)
        result={'branch':branch['name'],'base_branch':name,'requested_commit':branch['commit']['sha'],'source_ref':branch['commit']['sha'],'revision_kind':'branch'}
    if not re.fullmatch('[a-fA-F0-9]{40}',result['requested_commit']):raise HTTPException(502,'GitHub did not return a valid commit identity')
    result['requested_commit']=result['requested_commit'].lower()
    return result
