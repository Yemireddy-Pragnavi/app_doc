"""Read-only release gate. No source checkout or user code execution required."""
import json,os,sys,urllib.request,urllib.parse
base=os.environ['ASD_URL'].rstrip('/')
if urllib.parse.urlsplit(base).scheme!='https':raise SystemExit('ASD_URL must use HTTPS')
repo=os.environ['ASD_REPOSITORY_ID'];commit=os.environ['ASD_COMMIT_SHA'];token=os.environ['ASD_GATE_TOKEN']
url=base+'/api/lifecycle/gate/'+urllib.parse.quote(repo,safe='')+'?commit='+urllib.parse.quote(commit,safe='')
request=urllib.request.Request(url,headers={'Authorization':'Bearer '+token})
# Redirects must not forward the repository credential.
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args):return None
try:
    with urllib.request.build_opener(NoRedirect).open(request,timeout=30) as response:result=json.load(response)
except Exception:raise SystemExit('Security Doctor unavailable: release gate failed closed')
print(json.dumps({k:result.get(k) for k in ['decision','commit','scan_id','blockers','gaps']},indent=2))
if result.get('allowed') is not True:sys.exit(1)
