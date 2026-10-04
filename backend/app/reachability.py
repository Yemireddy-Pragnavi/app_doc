"""Bounded static route/import graph with explicit inference, not taint analysis."""
import ast
import hashlib
import posixpath
import re


def route_inventory(root, files):
    sources={p.relative_to(root).as_posix():p for p in files if p.suffix in ('.js','.jsx','.ts','.tsx','.mjs','.py')}
    links={};routes=[]
    for rel,p in list(sources.items())[:3000]:
        text=p.read_text(errors='replace'); imports=[]
        for match in re.finditer(r"(?:from\s*|require\s*\(|import\s*\()['\"](\.[^'\"]+)['\"]",text):
            base=posixpath.normpath(posixpath.join(posixpath.dirname(rel),match[1]))
            if base.startswith('../'):continue
            target=next((x for x in [base]+[base+s for s in ('.ts','.tsx','.js','.jsx','/index.ts','/index.js')] if x in sources),None)
            if target:imports.append(target)
        links[rel]=sorted(set(imports))[:30]
        route=None
        match=re.search(r'(?:^|/)(?:app/(.*)/route\.[jt]s|pages/(api/.*)\.[jt]s)',rel)
        if match:
            route='/'+(match[1] or match[2]).removesuffix('/index')
            route='/'.join(s for s in route.split('/') if not(s.startswith('(') and s.endswith(')')))
            methods=re.findall(r'export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\b',text)
            routes.append({'path':route,'file':rel,'methods':sorted(set(methods)) or ['UNKNOWN'],'framework':'Next.js'})
        if p.suffix=='.py':
            try:
                tree=ast.parse(text)
                for node in ast.walk(tree):
                    if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):continue
                    for dec in node.decorator_list:
                        if isinstance(dec,ast.Call) and isinstance(dec.func,ast.Attribute) and dec.func.attr in ('get','post','put','delete','patch') and dec.args and isinstance(dec.args[0],ast.Constant) and isinstance(dec.args[0].value,str) and dec.args[0].value.startswith('/'):
                            routes.append({'path':dec.args[0].value,'file':rel,'methods':[dec.func.attr.upper()],'framework':'Python decorator; router prefix unverified'})
            except SyntaxError:pass
        for match in re.finditer(r"\b(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['\"](/[^'\"]*)['\"]",text):
            routes.append({'path':match[2],'file':rel,'methods':[match[1].upper()],'framework':'Express; mount prefix unverified'})
    for route in routes[:300]:
        queue=[(route['file'],[route['file']])];paths={}
        while queue and len(paths)<100:
            file,chain=queue.pop(0)
            if file in paths:continue
            paths[file]=chain
            if len(chain)<5:
                queue.extend((target,chain+[target]) for target in links.get(file,[]) if target not in paths)
        route['imports']=paths;route['inferred']=True
    return {'routes':routes[:300],'status':'partial' if len(sources)>3000 or len(routes)>300 else 'completed',
            'note':'Literal routes, local JS/TS imports up to four hops. Middleware, alias imports, dynamic imports and Python call graphs are not resolved.'}


def matches_route(pattern,path):
    if len(pattern)>250 or len(path)>250:return False
    parts=[]
    for part in pattern.strip('/').split('/'):
        if re.fullmatch(r'\[\[\.\.\.\w+\]\]',part):parts.append('.*')
        elif re.fullmatch(r'\[\.\.\.\w+\]',part):parts.append('.+')
        elif re.fullmatch(r'\[\w+\]|\{\w+(?::[^}]+)?\}|:\w+',part):parts.append('[^/]+')
        else:parts.append(re.escape(part))
    return bool(re.fullmatch('/'+'/'.join(parts).rstrip('/')+'/?',path))


def correlate_routes(inventory,findings,observations):
    paths=[]
    for route in inventory.get('routes',[]):
        for obs in observations:
            if not matches_route(route['path'],obs['path']):continue
            for finding in findings:
                chain=route.get('imports',{}).get(finding.get('file'))
                if not chain:continue
                status=obs['status'];exposure='responded without supplied credentials' if 200<=status<300 else 'access denied in this request' if status in (401,403) else 'not established'
                paths.append({'id':hashlib.sha256((obs['path']+finding.get('fingerprint',finding.get('id',''))).encode()).hexdigest()[:20],
                    'finding_id':finding.get('id',finding.get('fingerprint')),'title':finding.get('title'),'path':obs['path'],'status':status,
                    'severity':finding.get('severity'),'priority':finding.get('priority'),'exposure':exposure,
                    'steps':['Observed GET '+obs['path']+' → HTTP '+str(status)]+['Inferred source '+c for c in chain]+['Scanner finding: '+finding.get('title','')],
                    'evidence':'Observed HTTP response plus inferred route/import links. This is a potential risk path, not proof of a reachable vulnerable operation or exploit.',
                    'exploitability':'Unverified','inferred':True})
    return list({p['id']:p for p in paths}.values())[:100]
