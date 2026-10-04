"""Runs in Compose CI: real Postgres, Redis, Celery, scanners and offline Chromium.
Only synthetic source/HTML; no user repository, credentials or staging endpoint.
"""
import base64
import json
import tempfile
from pathlib import Path
from sqlalchemy import text
from redis import Redis
from app.db import Session
from app.config import settings
from app.worker import celery
from app.scanners import command, semgrep, gitleaks, dependencies, source_files
from app.browser_bridge import observe_browser
from app.scanners import RULES

failures=[]

with Session() as db:assert db.execute(text('SELECT 1')).scalar()==1
assert Redis.from_url(settings().redis_url).ping()
assert celery.control.inspect(timeout=5).ping(), 'Worker did not respond'
print('PostgreSQL, Redis and Celery connected', flush=True)
with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp)
    (root/'app.py').write_text("import subprocess\neval(user_input)\nsubprocess.run(user_input, shell=True)\n")
    synthetic='fixture-only-not-a-real-credential'
    (root/'config.py').write_text("jwt_secret = '"+synthetic+"'\n")
    (root/'requirements.txt').write_text('requests==2.19.0\n')
    command(['git','init'],root)
    command(['git','add','.'],root)
    command(['git','-c','user.name=Scanner Fixture','-c','user.email=fixture@example.invalid','commit','-m','synthetic fixture'],root)
    code,cov=semgrep(root)
    if cov['status']!='completed' or len(code)<2:
        failures.append('Semgrep fixture')
        print('Semgrep fixture diagnostics:',code,cov,command(['semgrep','scan','--config',str(RULES/'security.yaml'),'--json','--metrics','off','--disable-version-check','--no-git-ignore',str(root)],root),flush=True)
    secrets,cov=gitleaks(root)
    if cov['status']!='completed' or len(secrets)<1:
        failures.append('Gitleaks fixture');print('Gitleaks:',cov,flush=True)
    assert synthetic not in json.dumps(secrets)
    deps,cov=dependencies(root,source_files(root))
    if cov['status']!='completed' or not deps:
        failures.append('OSV fixture');print('OSV:',cov,flush=True)
print('Scanner fixture failures:',failures, flush=True)
html=b'''<!doctype html><html><head><title>Fixture</title></head><body><form action="http://example.com/login"><input type="password"></form><script>document.body.dataset.observed='yes'</script></body></html>'''
def fetch(url):
    return {'status':200,'headers':{'content-type':'text/html'},'body':base64.b64encode(html).decode()},len(html)
result=observe_browser('https://staging.example.com/',fetch=fetch)
assert result['status']=='completed', result
assert result['page']['passwordForms']==1, result
assert any(i['rule']=='browser-password-http' for i in result['issues']),result
print('Network-isolated sandboxed Chromium and request broker passed', flush=True)
assert not failures, failures
