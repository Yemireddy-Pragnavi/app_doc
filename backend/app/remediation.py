"""Narrow deterministic dependency patches. Never guess business-logic fixes."""
import base64,difflib,re
from packaging.version import Version,InvalidVersion
from fastapi import HTTPException
import httpx

def dependency_patch(text,finding,version):
    if finding.get('engine')!='Dependencies' or not finding.get('file','').endswith('requirements.txt'):
        raise ValueError('Automatic patches currently support exact pins in requirements.txt only. Use manual remediation for this finding.')
    if version not in finding.get('fixed_versions',[]):raise ValueError('Select a fixed version listed in the advisory')
    try:
        if Version(version)<=Version(finding['installed_version']):raise ValueError('The replacement must be newer than the installed version')
    except InvalidVersion:raise ValueError('Unsupported package version')
    name=finding['package'];old=finding['installed_version']
    pattern=re.compile(r'(?m)^('+re.escape(name)+r'\s*==\s*)'+re.escape(old)+r'(\s*(?:#[^\n]*)?)$',re.I)
    updated,count=pattern.subn(lambda m:m[1]+version+m[2],text)
    if count!=1:raise ValueError('Expected exactly one matching pin; generate a fresh scan or edit manually')
    # Exclude arbitrary index URLs, source credentials and unrelated manifest data
    # from the review artifact. Raw source is refetched only for the reviewed write.
    diff=''.join(difflib.unified_diff(text.splitlines(True),updated.splitlines(True),fromfile='a/'+finding['file'],tofile='b/'+finding['file'],n=0))
    return updated,diff

async def gh(method,path,token,body=None):
    async with httpx.AsyncClient(timeout=25,follow_redirects=False) as client:
        response=await client.request(method,'https://api.github.com'+path,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'},json=body)
    if response.status_code not in (200,201):raise HTTPException(502,'GitHub operation failed. Check repository access and any recorded draft branch before retrying.')
    return response.json()

def decode_file(data):
    if data.get('type')!='file' or data.get('encoding')!='base64' or data.get('size',0)>200000:raise HTTPException(422,'Only small regular manifest files are supported')
    try:return base64.b64decode(data['content']).decode('utf-8')
    except (ValueError,UnicodeError):raise HTTPException(422,'Manifest must be UTF-8')
