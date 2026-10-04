"""Ephemeral capability-authenticated Unix socket broker for an offline browser.
The browser container has network_mode:none. This trusted worker alone fetches
validated public HTTPS resources. No incoming browser cookies/headers are forwarded.
"""
import base64
import http.client
import json
import os
import secrets
import socketserver
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit
import httpx
from .config import settings
from .runtime import target_url, public_addresses, PinnedHTTPSConnection

MAX_BODY=2_000_000
MAX_TOTAL=12_000_000
MAX_FETCHES=60


def browser_url(url, target):
    # Queries are deliberately excluded: they can contain credentials or actions.
    clean=target_url(url)
    if urlsplit(clean).netloc!=urlsplit(target).netloc:
        raise ValueError('Cross-origin browser request blocked')
    return clean


def fetch_resource(url):
    p=urlsplit(target_url(url))
    conn=PinnedHTTPSConnection(p.hostname,public_addresses(p.hostname)[0])
    try:
        conn.request('GET',p.path,headers={'User-Agent':'AppSecurityDoctor/0.3 browser-observation','Accept':'*/*','Accept-Encoding':'identity','Connection':'close'})
        response=conn.getresponse()
        if 300<=response.status<400:raise ValueError('Redirect not followed')
        body=response.read(MAX_BODY+1)
        if len(body)>MAX_BODY:raise ValueError('Resource size exceeded')
        # Retain only headers needed to render/enforce security. Set-Cookie is
        # excluded: browsing is intentionally stateless and unauthenticated.
        allowed={'content-type','content-security-policy','x-content-type-options','referrer-policy','cross-origin-resource-policy','cross-origin-opener-policy','cross-origin-embedder-policy','access-control-allow-origin'}
        headers={k.lower():v for k,v in response.getheaders() if k.lower() in allowed}
        return {'status':response.status,'headers':headers,'body':base64.b64encode(body).decode()},len(body)
    finally:conn.close()


@contextmanager
def broker(target, fetch=fetch_resource):
    directory=Path(settings().browser_socket_dir)
    directory.mkdir(parents=True,exist_ok=True)
    capability=secrets.token_urlsafe(32)
    job=secrets.token_hex(16)
    path=directory/(job+'.sock')
    state={'requests':0,'bytes':0,'blocked':0,'observations':[],'started':time.monotonic()}
    lock=threading.Lock()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):
            self.connection.settimeout(5)
            if self.path!='/fetch' or not secrets.compare_digest(self.headers.get('Authorization',''),'Bearer '+capability):
                self.send_error(403);return
            try:
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=4096:raise ValueError()
                obj=json.loads(self.rfile.read(length))
                if obj.get('method')!='GET':raise ValueError()
                url=browser_url(obj['url'],target)
                with lock:
                    if state['requests']>=MAX_FETCHES or state['bytes']>=MAX_TOTAL or time.monotonic()-state['started']>55:raise ValueError()
                    state['requests']+=1
                    data,size=fetch(url)
                    state['bytes']+=size
                    if state['bytes']>MAX_TOTAL:raise ValueError()
                    state['observations'].append({'path':urlsplit(url).path,'status':data['status'],'access':'browser GET'})
                payload=json.dumps(data).encode()
                self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
            except (ValueError,KeyError,OSError,http.client.HTTPException):
                with lock:state['blocked']+=1
                self.send_error(422,'Request outside inspection scope or unavailable')
    class Server(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):
        daemon_threads=True
    server=Server(str(path),Handler)
    os.chmod(path,0o600)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:yield job,capability,state
    finally:
        server.shutdown();server.server_close();thread.join(timeout=2)
        path.unlink(missing_ok=True)


def observe_browser(target, fetch=fetch_resource):
    socket_path=Path(settings().browser_service_socket)
    if not socket_path.exists():return {'status':'unavailable','note':'The isolated browser service is not running.','findings':[],'observations':[]}
    try:
        with broker(target,fetch=fetch) as (job,capability,state):
            transport=httpx.HTTPTransport(uds=str(socket_path))
            with httpx.Client(transport=transport,timeout=70,trust_env=False) as client:
                response=client.post('http://browser/observe',json={'target':target,'job':job,'capability':capability})
                response.raise_for_status()
                result=response.json()
            # Only allowlisted metadata leaves the isolated service. No DOM text,
            # screenshots, cookies, storage values or console strings are retained.
            return {'status':'partial' if state['blocked'] or result.get('status')!='completed' else 'completed',
                'note':'Isolated Chromium observation; stateless same-origin GET resources only.',
                'page':result.get('page',{}),'issues':result.get('issues',[])[:30],
                'requests':state['requests'],'blocked_requests':state['blocked'],'observations':state['observations'][:60]}
    except Exception:
        return {'status':'unavailable','note':'Browser observation failed, timed out or could not start with its required sandbox.','findings':[],'observations':[]}
