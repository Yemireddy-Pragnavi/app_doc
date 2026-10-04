"""Phase 2 HTTP baseline: authorized, bounded GETs; no browser or source execution."""
import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import time
from http.cookies import SimpleCookie
from urllib.parse import urlsplit, urlunsplit, unquote

PROBE_ORIGIN = 'https://cors-check.invalid'
MAX_ROUTES = 6
MAX_REQUESTS = 18


def target_url(value):
    if len(value) > 500 or re.search(r'[\s\\\x00-\x1f\x7f]', value):
        raise ValueError('Use a public HTTPS URL without whitespace or backslashes.')
    try:
        p = urlsplit(value)
        if p.scheme != 'https' or not p.hostname or p.username or p.password or p.port not in (None, 443) or p.query or p.fragment:
            raise ValueError()
        host = p.hostname.encode('idna').decode('ascii').lower()
        if not re.fullmatch(r'[a-z0-9.-]+', host) or '.' not in host or host.endswith('.'):
            raise ValueError()
        if host in ('localhost', 'metadata.google.internal') or host.endswith(('.localhost', '.local', '.internal')):
            raise ValueError()
        path = route_path(p.path or '/')
    except (ValueError, UnicodeError):
        raise ValueError('Use a public HTTPS hostname on port 443, without credentials, queries or fragments.')
    return urlunsplit(('https', host, path, '', ''))


def route_path(path):
    if not path.startswith('/') or path.startswith('//') or len(path) > 200 or re.search(r'[\s\\?#\x00-\x1f\x7f]', path):
        raise ValueError('Routes must be relative paths without queries, fragments or whitespace.')
    decoded = unquote(path)
    if re.search(r'[\\\x00-\x20\x7f]', decoded) or '..' in decoded.split('/') or decoded.startswith('//'):
        raise ValueError('Invalid route path.')
    return path


def public_addresses(host):
    addresses = sorted({r[4][0] for r in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise ValueError('The target resolves to a non-public address.')
    # Every returned address is checked. The connection uses one exact checked IP,
    # while TLS still verifies the original hostname (no DNS rebinding window).
    return addresses


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, address):
        super().__init__(host, 443, timeout=5, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        raw = socket.create_connection((self.address, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def fetch_headers(url, origin=None):
    p = urlsplit(target_url(url))
    conn = PinnedHTTPSConnection(p.hostname, public_addresses(p.hostname)[0])
    try:
        headers = {'User-Agent': 'AppSecurityDoctor/0.2 (authorized configuration review)', 'Accept': '*/*', 'Connection': 'close'}
        if origin:
            headers['Origin'] = origin
        conn.request('GET', p.path, headers=headers)
        response = conn.getresponse()
        # Body and cookie values are never read into reports. http.client bounds
        # header line lengths and header count. No environment proxy is used.
        return {'status': response.status, 'headers': response.getheaders()}
    finally:
        conn.close()


def item(rule, title, severity, path, evidence, remediation):
    return {'id': hashlib.sha256((rule + path).encode()).hexdigest()[:20], 'rule': rule,
            'title': title, 'severity': severity, 'path': path, 'evidence': evidence,
            'remediation': remediation, 'priority': 'Must Fix' if severity == 'High' else 'Fix Soon' if severity == 'Medium' else 'Review',
            'source': 'Observed HTTP response', 'confidence': 'Observed configuration; impact requires context'}


def analyze_response(path, response, cors=False):
    h = {k.lower(): v for k, v in response['headers']}
    findings = []
    def add(rule, title, severity, evidence, fix):
        findings.append(item(rule, title, severity, path, evidence, fix))
    if cors:
        allow = h.get('access-control-allow-origin', '')
        credentials = h.get('access-control-allow-credentials', '').lower() == 'true'
        if allow == PROBE_ORIGIN:
            add('cors-reflection', 'Untrusted origin accepted by CORS', 'High' if credentials else 'Medium',
                'The supplied test origin is allowed' + (' with credentials.' if credentials else '.'),
                'Use an explicit trusted-origin allowlist. Confirm whether sensitive data is exposed; this check does not prove data theft.')
        elif allow == '*' and credentials:
            add('cors-invalid', 'Wildcard CORS combined with credentials', 'Low', 'Wildcard origin and credential allowance are both present.',
                'Use explicit trusted origins or disable credentials. Browsers reject this combination for credentialed reads.')
        return findings
    hsts = h.get('strict-transport-security', '')
    age = re.search(r'(?:^|;)\s*max-age\s*=\s*(\d+)', hsts, re.I)
    if not age or int(age[1]) == 0:
        add('hsts', 'Transport security policy missing or disabled', 'Medium', 'No positive HSTS max-age was observed.',
            'Configure Strict-Transport-Security after validating HTTPS across the intended domain scope.')
    html = 'text/html' in h.get('content-type', '').lower()
    csp = h.get('content-security-policy', '')
    directives = {d.strip().split()[0].lower(): d.strip().split()[1:] for d in csp.split(';') if d.strip()}
    scripts = directives.get('script-src', directives.get('default-src', []))
    if html and not csp:
        add('csp', 'No enforced CSP response header observed', 'Medium', 'No Content-Security-Policy response header was observed.',
            'Deploy a tested nonce/hash-based CSP. Report-only policies do not enforce restrictions.')
    elif html and "'unsafe-eval'" in scripts:
        add('csp-eval', 'Content Security Policy permits evaluated scripts', 'Medium', 'An effective script policy includes unsafe-eval.',
            'Remove evaluated-script dependencies and unsafe-eval after compatibility testing.')
    if html and not re.search(r'(?:^|;)\s*frame-ancestors\s+', csp, re.I) and h.get('x-frame-options', '').upper() not in ('DENY', 'SAMEORIGIN'):
        add('framing', 'Framing restrictions were not observed', 'Low', 'No recognized frame-ancestors or X-Frame-Options protection.',
            'Set frame-ancestors in CSP to the required trusted origins or none.')
    if h.get('x-content-type-options', '').lower() != 'nosniff':
        add('nosniff', 'MIME sniffing protection missing', 'Low', 'X-Content-Type-Options: nosniff was not observed.', 'Set X-Content-Type-Options: nosniff and serve correct content types.')
    cookie_count = 0
    for name, value in response['headers']:
        if name.lower() != 'set-cookie':
            continue
        cookie_count += 1
        cookie = SimpleCookie()
        try:
            cookie.load(value)
        except Exception:
            cookie = SimpleCookie()
        if not cookie:
            add('cookie-parse-'+str(cookie_count), 'Cookie attributes could not be parsed', 'Low', 'Cookie values were discarded.', 'Review this response’s Set-Cookie attributes manually.')
        for m in cookie.values():
            missing = [x for x in ('secure', 'httponly', 'samesite') if not m[x]]
            if missing:
                add('cookie-'+str(cookie_count), 'Review cookie protection attributes', 'Medium' if 'secure' in missing else 'Low',
                    'Cookie #' + str(cookie_count) + ' missing: ' + ', '.join(missing) + '. Names and values omitted.',
                    'Use Secure, HttpOnly and an appropriate SameSite policy for session cookies. JavaScript-readable non-sensitive cookies may intentionally omit HttpOnly.')
    return findings


def correlate(static_findings, observations):
    correlations = []
    for f in static_findings:
        file = f.get('file', '')
        match = re.search(r'(?:^|/)(?:src/)?(?:app/(api/.+?)/route\.[jt]s|pages/(api/.+?)\.[jt]s)', file)
        if not match:
            continue
        route = '/' + (match[1] or match[2]).removesuffix('/index')
        if '[' in route:
            continue
        for obs in observations:
            if obs['path'] == route:
                correlations.append({'finding_id': f.get('id', f.get('fingerprint')), 'title': f.get('title'), 'path': route,
                    'status': obs['status'], 'evidence': 'File-path mapping matched a requested route. The response may come from middleware or a proxy; authorization and exploitability are unverified.'})
    return correlations


def launch_verdict(repository, findings, complete):
    if repository.get('decision') == 'NOT READY' or any(f['priority'] == 'Must Fix' for f in findings):
        return 'NOT READY'
    if not complete or repository.get('status') != 'completed' or repository.get('decision') not in ('READY', 'READY WITH WARNINGS'):
        return 'INCOMPLETE'
    return 'READY WITH WARNINGS' if findings or repository.get('decision') == 'READY WITH WARNINGS' else 'READY FOR REVIEW'


def scan_runtime(target, paths, repository, static_findings, fetch=fetch_headers):
    target = target_url(target)
    origin = 'https://' + urlsplit(target).netloc
    paths = list(dict.fromkeys([urlsplit(target).path] + [route_path(p) for p in paths]))
    if len(paths) > MAX_ROUTES:
        raise ValueError('At most six paths including the target are supported.')
    start = time.monotonic()
    findings, observations, errors = [], [], []
    requests = 0
    for path in paths:
        if time.monotonic() - start > 120 or requests >= MAX_REQUESTS:
            errors.append({'path': path, 'reason': 'Scan time/request budget reached.'})
            break
        url = origin + path
        try:
            # Do not follow redirects: record scope boundaries explicitly. This
            # avoids silently scanning a different deployment or identity provider.
            requests += 1
            response = fetch(url)
            status = response['status']
            kind = 'protected' if status in (401, 403) else 'redirect' if 300 <= status < 400 else 'responded' if 200 <= status < 300 else 'unavailable'
            observations.append({'path': path, 'status': status, 'access': kind})
            if status >= 300 and status not in (401, 403):
                errors.append({'path': path, 'reason': 'Redirects are not followed.' if status < 400 else 'This path did not return a usable response.'})
                continue
            findings.extend(analyze_response(path, response))
            requests += 1
            probe = fetch(url, origin=PROBE_ORIGIN)
            if probe['status'] == status:
                findings.extend(analyze_response(path, probe, cors=True))
            else:
                errors.append({'path': path, 'reason': 'Origin probe returned a different status; CORS assessment incomplete.'})
        except (OSError, ValueError, http.client.HTTPException):
            errors.append({'path': path, 'reason': 'TLS, DNS, network or target validation failed. No response contents retained.'})
    findings = sorted({f['id']: f for f in findings}.values(), key=lambda f: {'High': 0, 'Medium': 1, 'Low': 2}[f['severity']])
    return {'target_url': target, 'findings': findings, 'observations': observations, 'errors': errors,
            'requests': requests, 'status': 'partial' if errors else 'completed',
            'decision': launch_verdict(repository, findings, not errors), 'repository_assessment': repository,
            'correlations': correlate(static_findings, observations),
            'coverage': {'headers': 'HTTP response rules', 'cookies': 'Attributes only; values discarded', 'cors': 'One untrusted-origin GET probe per path', 'routes': 'User-selected, unauthenticated GET requests', 'browser': 'Pending extended review', 'cloud_configuration': 'Pending extended review', 'exploitability': 'Not verified'},
            'disclaimer': 'A bounded HTTP baseline combined with one repository assessment. It is not a penetration test or a guarantee of launch safety.'}
