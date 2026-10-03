import os
os.environ['DATABASE_URL']='sqlite://'
os.environ['COOKIE_SECURE']='false'
os.environ['FRONTEND_URL']='http://localhost:3000'
from pathlib import Path
import pytest
from app.security import repo_name,redact
from app.scanners import normalize,auth_checks,source_files,finding,detect,dependencies

def test_repository_url_is_origin_locked():
    assert repo_name('https://github.com/team/repo.git')=='team/repo'
    for url in ['http://github.com/a/b','https://github.com.evil.com/a/b','https://u:p@github.com/a/b','https://github.com:443/a/b','https://github.com/a/b?x=1','file:///etc/passwd','https://github.com/a/../b','https://github.com/a/b/-x']:
        with pytest.raises(ValueError):repo_name(url)
def test_redaction():
    assert 'super-secret-password' not in redact('password = super-secret-password')
    assert 'ghp_' not in redact('ghp_'+'a'*36)
    assert 'postgres://' not in redact('postgres://user:pass@host/db')
def test_partial_scan_never_has_readiness_score():
    rows,score=normalize([],complete=False);assert score is None
    rows,score=normalize([],complete=True);assert score==100

def test_risk_prioritizes_exposure_and_confidence():
    a=finding('Code','test','High','api/x.ts',1,'d','r',.95)
    b=finding('Authentication','review','High','lib/x.ts',1,'d','r',.4)
    rows,score=normalize([a,b,a]);assert len(rows)==2;assert rows[0]['risk']>rows[1]['risk'];assert rows[0]['priority']=='Must Fix';assert score<100

def test_stack_and_auth_patterns(tmp_path):
    (tmp_path/'package.json').write_text('{"dependencies":{"next":"15.0.0","@supabase/supabase-js":"2.0.0"}}')
    p=tmp_path/'admin.ts';p.write_text('export function GET() { return jwt.decode(token) }')
    files=source_files(tmp_path);tech,components,edges=detect(tmp_path,files)
    assert 'Next.js'in tech and 'Supabase'in tech
    findings,coverage=auth_checks(tmp_path,files)
    assert len(findings)==2
    assert all('Potential'in f['title'] for f in findings)
    assert all('jwt.decode(token)' not in f['evidence'] for f in findings)

def test_symlinks_not_read(tmp_path):
    (tmp_path/'escape.py').symlink_to('/etc/passwd')
    assert source_files(tmp_path)==[]

def test_unpinned_manifest_is_incomplete(tmp_path):
    (tmp_path/'requirements.txt').write_text('requests>=2\n')
    rows,coverage=dependencies(tmp_path,source_files(tmp_path))
    assert coverage['status']=='partial';assert not rows

def test_graph_uses_import_and_folder_evidence(tmp_path):
    directory=tmp_path/'app'/'api'/'checkout';directory.mkdir(parents=True)
    (directory/'route.ts').write_text("import Stripe from 'stripe';\nconst stripe = new Stripe(process.env.STRIPE_SECRET_KEY);\n")
    (tmp_path/'page.tsx').write_text("import React from 'react';")
    tech,components,edges=detect(tmp_path,source_files(tmp_path))
    assert {'Stripe','React','API Routes'}.issubset(tech)
    stripe=next(c for c in components if c['name']=='Stripe')
    assert 'module import' in stripe['evidence']
    assert stripe['kind']=='integration'
    assert any(e['source']=='API Routes' and e['target']=='Stripe' for e in edges)
