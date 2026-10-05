"""Offline Chromium service. All network requests are brokered over Unix sockets.
Deploy with network_mode:none, a read-only filesystem and an unprivileged user.
"""
import base64
import json
import os
import re
import socketserver
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
import httpx
from playwright.sync_api import sync_playwright

SOCKET_DIR=Path('/run/asd-browser')


def observe(payload):
    if not re.fullmatch(r'[a-f0-9]{32}',payload.get('job','')):raise ValueError('Invalid job')
    target=payload['target'];started=time.monotonic();blocked=0;errors=0
    transport=httpx.HTTPTransport(uds=str(SOCKET_DIR/(payload['job']+'.sock')))
    with httpx.Client(transport=transport,timeout=6,trust_env=False) as client, sync_playwright() as p:
        browser=p.chromium.launch(headless=True,chromium_sandbox=True,args=['--disable-background-networking','--disable-dev-shm-usage'])
        try:
            context=browser.new_context(service_workers='block',accept_downloads=False,viewport={'width':1280,'height':800})
            context.set_default_timeout(4000)
            def handle(route):
                nonlocal blocked
                if time.monotonic()-started>45 or route.request.method!='GET':
                    blocked+=1;route.abort();return
                try:
                    response=client.post('http://broker/fetch',headers={'Authorization':'Bearer '+payload['capability']},json={'url':route.request.url,'method':route.request.method})
                    response.raise_for_status();data=response.json()
                    route.fulfill(status=data['status'],headers=data['headers'],body=base64.b64decode(data['body'],validate=True))
                except Exception:
                    blocked+=1;route.abort()
            context.route('**/*',handle)
            context.route_web_socket('**/*',lambda ws:ws.close())
            page=context.new_page()
            def page_error(error):
                nonlocal errors
                errors+=1
            page.on('pageerror',page_error)
            page.goto(target,wait_until='domcontentloaded',timeout=25000)
            page.wait_for_timeout(1800)
            # Count only; never return form inputs, page text, cookies or storage.
            info=page.evaluate('''() => ({
              passwordForms: [...document.forms].filter(f=>f.querySelector('input[type=password]')).length,
              insecurePasswordForms: [...document.forms].filter(f=>f.querySelector('input[type=password]') && (new URL(f.action||location.href,location.href)).protocol!=='https:').length,
              crossOriginPasswordForms: [...document.forms].filter(f=>f.querySelector('input[type=password]') && (new URL(f.action||location.href,location.href)).origin!==location.origin).length,
              mixedResources: [...document.querySelectorAll('script[src],iframe[src],img[src],link[href]')].filter(n=>(n.src||n.href||'').startsWith('http:')).length,
              hasCspMeta: !!document.querySelector('meta[http-equiv="Content-Security-Policy" i]')
            })''')
            info={key: int(value) if isinstance(value,(bool,int)) else 0 for key,value in info.items() if key in ('passwordForms','insecurePasswordForms','crossOriginPasswordForms','mixedResources','hasCspMeta')}
            issues=[]
            if info['insecurePasswordForms']:issues.append({'rule':'browser-password-http','title':'Password form targets insecure transport','severity':'High','evidence':'A password form action resolves to HTTP. No form was submitted.','remediation':'Submit credentials only over HTTPS to a trusted endpoint.'})
            if info['crossOriginPasswordForms']:issues.append({'rule':'browser-password-origin','title':'Password form targets another origin','severity':'Medium','evidence':'A password form action has a different origin. This can be intentional identity-provider behavior.','remediation':'Verify the destination belongs to the intended trusted identity provider.'})
            if info['mixedResources']:issues.append({'rule':'browser-mixed-content','title':'Page declares insecure resource URLs','severity':'Medium','evidence':'HTTP subresources were declared. Requests outside scope were blocked.','remediation':'Use HTTPS for all active and passive page resources.'})
            return {'status':'partial' if blocked or errors else 'completed','page':{**info,'script_errors':errors,'blocked_requests':blocked},'issues':issues}
        finally:browser.close()


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        if self.path!='/health':self.send_error(404);return
        body=b'{"ready":true}'
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def do_POST(self):
        self.connection.settimeout(80)
        if self.path!='/observe':self.send_error(404);return
        try:
            size=int(self.headers.get('Content-Length','0'))
            if not 0<size<4096:raise ValueError()
            data=observe(json.loads(self.rfile.read(size)))
            body=json.dumps(data).encode()
            self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        except Exception:self.send_error(503,'Browser observation unavailable')

if __name__=='__main__':
    # A blank-page startup probe contains no user target or credentials.
    with sync_playwright() as p:
        probe=p.chromium.launch(headless=True,chromium_sandbox=True,args=['--disable-background-networking','--disable-dev-shm-usage'])
        probe.close()
    SOCKET_DIR.mkdir(exist_ok=True)
    path=SOCKET_DIR/'service.sock';path.unlink(missing_ok=True)
    with socketserver.UnixStreamServer(str(path),Handler) as server:
        os.chmod(path,0o600);server.serve_forever()
