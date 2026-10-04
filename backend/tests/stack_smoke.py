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
    assert cov['status']=='completed' and len(code)>=2, cov
    secrets,cov=gitleaks(root)
    assert cov['status']=='completed' and len(secrets)>=1, cov
    assert synthetic not in json.dumps(secrets)
    deps,cov=dependencies(root,source_files(root))
    assert cov['status']=='completed' and deps, cov
print('Real Semgrep, Gitleaks and OSV adapters passed', flush=True)
html=b'''<!doctype html><html><head><title>Fixture</title></head><body><form action="http://example.com/login"><input type="password"></form><script>document.body.dataset.observed='yes'</script></body></html>'''
def fetch(url):
    return {'status':200,'headers':{'content-type':'text/html'},'body':base64.b64encode(html).decode()},len(html)
result=observe_browser('https://staging.example.com/',fetch=fetch)
assert result['status']=='completed', result
assert result['page']['passwordForms']==1, result
assert any(i['rule']=='browser-password-http' for i in result['issues']),result
print('Network-isolated sandboxed Chromium and request broker passed', flush=True)
