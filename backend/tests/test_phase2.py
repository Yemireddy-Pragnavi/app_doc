import json
from pathlib import Path
import httpx
import pytest
from app.cloud_review import review_cloud
from app.reachability import route_inventory, correlate_routes, matches_route
from app.launch_review import complete_review
from app.browser_bridge import browser_url, broker


def test_cloud_explicit_risks_and_no_raw_secrets(tmp_path):
    folder=tmp_path/'supabase'/'migrations';folder.mkdir(parents=True)
    sql=folder/'test.sql';sql.write_text("-- alter table public.safe disable row level security;\nalter table public.users disable row level security;\ncreate policy p on public.users using (true);\n-- secret=synthetic-secret")
    rules=tmp_path/'firestore.rules';rules.write_text('match /{document=**} { allow read, write: if true; }')
    s3=tmp_path/'template.json';s3.write_text(json.dumps({'Resources':{'B':{'Type':'AWS::S3::Bucket','Properties':{'AccessControl':'PublicRead'}}}}))
    report=review_cloud(tmp_path,[sql,rules,s3])
    assert report['status']=='completed' and report['deployment_verified'] is False
    assert {'Supabase','Firebase','AWS S3'}==set(report['providers'])
    assert len(report['findings'])==4
    assert 'synthetic-secret' not in str(report)


def test_missing_cloud_files_not_assumed_secure(tmp_path):
    report=review_cloud(tmp_path,[])
    assert report['status']=='not_detected' and not report['deployment_verified']


def test_unsupported_cloud_yaml_marks_partial(tmp_path):
    p=tmp_path/'stack.yaml';p.write_text('Resources:\n  B:\n    Type: AWS::S3::Bucket')
    assert review_cloud(tmp_path,[p])['status']=='partial'


def test_route_import_graph_dynamic_parameter(tmp_path):
    route=tmp_path/'app/api/users/[id]/route.ts';route.parent.mkdir(parents=True)
    lib=tmp_path/'app/api/users/shared.ts';lib.write_text('export function unsafe(){}')
    route.write_text("import {unsafe} from '../shared'; export function GET(){ return unsafe() }")
    inv=route_inventory(tmp_path,[route,lib])
    f={'id':'f1','file':'app/api/users/shared.ts','title':'Unsafe operation','severity':'High','priority':'Must Fix'}
    results=correlate_routes(inv,[f],[{'path':'/api/users/123','status':200}])
    assert len(results)==1 and len(results[0]['steps'])==4
    assert results[0]['exploitability']=='Unverified'
    assert not correlate_routes(inv,[f],[{'path':'/api/products/123','status':200}])

@pytest.mark.parametrize('pattern,path',[('/api/{id}','/api/1'),('/api/:id','/api/2'),('/files/[...path]','/files/a/b')])
def test_framework_route_patterns(pattern,path):assert matches_route(pattern,path)


def test_cross_origin_and_queries_blocked():
    assert browser_url('https://example.com/app.js','https://example.com/')=='https://example.com/app.js'
    for url in ['https://evil.test/x','http://example.com/','https://example.com/?key=x','https://example.com/../x']:
        with pytest.raises(ValueError):browser_url(url,'https://example.com/')


def test_browser_broker_capability_and_request_filter(tmp_path,monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings(),'browser_socket_dir',str(tmp_path))
    calls=[]
    def fetch(url):calls.append(url);return {'status':200,'headers':{'content-type':'text/html'},'body':'aGk='},2
    import socket
    try:
        probe=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);probe.close()
    except PermissionError:
        pytest.skip('Authoring sandbox prohibits Unix sockets; run this integration check in CI/deployment.')
    with broker('https://example.com/',fetch) as (job,key,state):
        transport=httpx.HTTPTransport(uds=str(tmp_path/(job+'.sock')))
        with httpx.Client(transport=transport,trust_env=False) as client:
            body={'url':'https://example.com/','method':'GET'}
            assert client.post('http://broker/fetch',json=body).status_code==403
            headers={'Authorization':'Bearer '+key}
            assert client.post('http://broker/fetch',json=body,headers=headers).status_code==200
            assert client.post('http://broker/fetch',json={**body,'method':'POST'},headers=headers).status_code==422
            assert client.post('http://broker/fetch',json={**body,'url':'https://other.example.com/'},headers=headers).status_code==422
        assert state['requests']==1 and len(calls)==1
    assert not (tmp_path/(job+'.sock')).exists()


def baseline_report():
    return {'target_url':'https://example.com/','findings':[],'errors':[],'coverage':{},'observations':[], 'repository_assessment':{'status':'completed','decision':'READY'}}

def source():return {'commit':'a'*40,'cloud_review':{'status':'completed','findings':[],'deployment_verified':False},'route_inventory':{'status':'completed','routes':[]}}

def test_full_review_requires_all_coverage_and_matching_commit():
    good=lambda url:{'status':'completed','issues':[],'observations':[]}
    result=complete_review(baseline_report(),source(),[],{'deployment_commit':'a'*40},good)
    assert result['status']=='completed' and result['decision']=='READY FOR REVIEW'
    result=complete_review(baseline_report(),source(),[],{'deployment_commit':'b'*40},good)
    assert result['status']=='partial' and result['decision']=='INCOMPLETE'
    assert result['deployment_identity']['verification'].startswith('Reviewer')


def test_browser_failure_never_becomes_clean():
    result=complete_review(baseline_report(),source(),[],{'deployment_commit':'a'*40},lambda url:{'status':'unavailable'})
    assert result['decision']=='INCOMPLETE' and result['status']=='partial'


def test_cloud_na_does_not_hide_known_blocker():
    s=source();s['cloud_review']['findings']=[{'id':'cloud1','title':'Public write','severity':'High','priority':'Must Fix','path':'firestore.rules','remediation':'Fix access'}]
    result=complete_review(baseline_report(),s,[],{'deployment_commit':'a'*40,'cloud_applicable':False},lambda url:{'status':'completed'})
    assert result['decision']=='NOT READY' and len(result['must_fix'])==1
