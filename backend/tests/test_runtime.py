import ipaddress
import socket
import pytest
from app.runtime import target_url, route_path, public_addresses, analyze_response, scan_runtime, launch_verdict, PinnedHTTPSConnection

@pytest.mark.parametrize('url', ['http://example.com', 'https://user:pass@example.com', 'https://example.com:8443', 'https://localhost', 'https://metadata.google.internal', 'https://example.com/?token=secret', 'https://example.com/#x', 'https://example.com/\\evil', 'https://example.com/%0d%0aX-Test:hi', 'https://example.com/a/../b'])
def test_unsafe_targets(url):
    with pytest.raises(ValueError): target_url(url)

@pytest.mark.parametrize('path',['//evil.test/','https://evil.test/','/api?token=x','/a/../admin','/%2f%2fevil.test','/%0aHost:evil'])
def test_unsafe_route(path):
    with pytest.raises(ValueError): route_path(path)

@pytest.mark.parametrize('address',['127.0.0.1','10.0.0.3','169.254.169.254','::1','::ffff:127.0.0.1','100.64.0.1','192.0.2.1'])
def test_blocks_private_and_special_dns(monkeypatch,address):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[(socket.AF_INET,socket.SOCK_STREAM,6,'',(address,443)),(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443))])
    with pytest.raises(ValueError): public_addresses('example.com')

def test_socket_is_pinned_and_tls_hostname_preserved(monkeypatch):
    calls=[]
    class Context:
        def wrap_socket(self,raw,server_hostname):calls.append(server_hostname);return raw
    monkeypatch.setattr(socket,'create_connection',lambda address,timeout: calls.append(address) or object())
    conn=PinnedHTTPSConnection('example.com','8.8.8.8');conn._context=Context();conn.connect()
    assert calls==[('8.8.8.8',443),'example.com']

def secure_response(status=200):
    return {'status':status,'headers':[('Content-Type','text/html'),('Strict-Transport-Security','max-age=31536000'),('Content-Security-Policy',"default-src 'self'; frame-ancestors 'none'"),('X-Content-Type-Options','nosniff')]}

def test_cookie_values_never_retained():
    response=secure_response();response['headers'] += [('Set-Cookie','session=SUPER_SECRET_VALUE; Path=/')]
    found=analyze_response('/',response)
    assert len(found)==1
    assert 'SUPER_SECRET_VALUE' not in str(found) and 'session=' not in str(found)
    assert 'secure' in found[0]['evidence']

def test_cors_reports_observation_not_proven_exploit():
    response={'status':200,'headers':[('Access-Control-Allow-Origin','https://cors-check.invalid'),('Access-Control-Allow-Credentials','true')]}
    finding=analyze_response('/api/status',response,cors=True)[0]
    assert finding['severity']=='High'
    assert 'does not prove' in finding['remediation']
    response['headers'][0]=('Access-Control-Allow-Origin','*')
    assert analyze_response('/',response,cors=True)[0]['severity']=='Low'

def test_redirect_is_not_followed_and_verdict_incomplete():
    calls=[]
    def fetch(url,origin=None):
        calls.append(url)
        return {'status':302,'headers':[('Location','http://169.254.169.254/latest/meta-data/')]}
    result=scan_runtime('https://example.com/',[],{'status':'completed','decision':'READY'},[],fetch)
    assert calls==['https://example.com/']
    assert result['status']=='partial' and result['decision']=='INCOMPLETE'

def test_runtime_correlates_exact_routes_and_preserves_repository_blocker():
    calls=[]
    def fetch(url,origin=None):calls.append((url,origin));return secure_response()
    baseline={'status':'completed','decision':'NOT READY'}
    result=scan_runtime('https://example.com/',['/api/admin'],baseline,[{'id':'f1','file':'src/app/api/admin/route.ts','title':'Admin access'}],fetch)
    assert len(calls)==4 and result['status']=='completed'
    assert result['decision']=='NOT READY'
    assert result['correlations'][0]['finding_id']=='f1'
    assert 'unverified' in result['correlations'][0]['evidence']
    assert result['coverage']['browser']=='Pending extended review'

def test_failed_or_partial_baseline_cannot_get_ready():
    assert launch_verdict({'status':'partial','decision':'INCOMPLETE'},[],True)=='INCOMPLETE'
    assert launch_verdict({'status':'completed','decision':'READY'},[],False)=='INCOMPLETE'
    assert launch_verdict({'status':'completed','decision':'READY'},[],True)=='READY FOR REVIEW'

def test_unavailable_route_is_coverage_gap():
    result=scan_runtime('https://example.com/',[],{'status':'completed','decision':'READY'},[],lambda *a,**k:secure_response(500))
    assert result['decision']=='INCOMPLETE' and result['status']=='partial'

def test_cors_status_change_is_incomplete():
    result=scan_runtime('https://example.com/',[],{'status':'completed','decision':'READY'},[],lambda url,origin=None:secure_response(403 if origin else 200))
    assert result['decision']=='INCOMPLETE'

def test_script_src_overrides_default_src():
    response=secure_response()
    response['headers']=[(k,v) for k,v in response['headers'] if k!='Content-Security-Policy']
    response['headers'].append(('Content-Security-Policy',"default-src 'unsafe-eval'; script-src 'self'; frame-ancestors 'none'"))
    assert not any(f['rule']=='csp-eval' for f in analyze_response('/',response))
