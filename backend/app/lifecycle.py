"""Deterministic, bounded lifecycle analysis. Unknown evidence never means safe."""
import ast
import hashlib
import json
import re
from collections import defaultdict, deque
from .security import redact

SCHEMA=1
SEVERITY={'Critical':95,'High':75,'Medium':45,'Low':20,'Informational':5}
DEFAULT_POLICY={'minimum_score':75,'block_critical':True,'block_high':False,'block_secret':True,'block_regression':True,'review_external_changes':True,'require_runtime':True}

def identity(*parts):
    return hashlib.sha256('|'.join(map(str,parts)).encode()).hexdigest()[:24]

def finding_key(f):
    # Line changes should not create a new incident. No credential values retained.
    return identity(f.get('engine'),f.get('file'),f.get('cwe') or f.get('advisory') or f.get('title'),f.get('package',''))

def configuration_findings(summary):
    return [{**f,'engine':'Configuration','file':f.get('path','unknown'),'line':1,'fingerprint':f['id']} for f in summary.get('cloud_review',{}).get('findings',[])]

def build_graph(summary,findings,root=None,files=None):
    nodes={};edges={};gaps=[]
    def node(kind,label,file='',line=1,**attrs):
        key=identity(kind,label,file)
        nodes[key]={'id':key,'type':kind,'label':redact(label),'file':redact(file),'line':line,'evidence':'source declaration' if file else 'scanner metadata','inferred':True,**attrs}
        return key
    def edge(source,target,kind,evidence):
        key=identity(source,target,kind)
        if source!=target:edges[key]={'id':key,'source':source,'target':target,'type':kind,'evidence':evidence,'inferred':True}
    repo=node('Repository','Repository')
    kinds={'frontend':'Frontend','backend':'Backend','database':'Database','auth':'Auth Provider','integration':'External API'}
    components={}
    for c in summary.get('components',[]):
        components[c['name']]=node(kinds.get(c.get('kind'),'Service'),c['name'],evidence=c.get('evidence','Detected component'))
        edge(repo,components[c['name']],'USES','Detected repository component')
    for e in summary.get('edges',[]):
        if e['source'] in components and e['target'] in components:edge(components[e['source']],components[e['target']],'CONNECTS_TO',e.get('evidence','Component association; not verified data flow'))
    file_ids={}
    def file_node(path):
        if path not in file_ids:file_ids[path]=node('File',path,path)
        return file_ids[path]
    routes=summary.get('route_inventory',{}).get('routes',[])
    for r in routes:
        rid=node('API Route',','.join(r.get('methods',[]))+' '+r['path'],r['file'],path=r['path'])
        edge(repo,rid,'EXPOSES','Route declaration; deployment exposure unknown')
        for file,chain in r.get('imports',{}).items():
            last=rid
            for source in chain:
                target=file_node(source);edge(last,target,'DEPENDS_ON','Static local import; execution not established');last=target
    if root is not None:
        if len(files or [])>3000:gaps.append('Only first 3000 files considered for lifecycle extraction')
        for p in (files or [])[:3000]:
            rel=p.relative_to(root).as_posix()
            if p.suffix not in ('.py','.js','.jsx','.ts','.tsx','.json','.sql','.yml','.yaml','.toml') and p.name not in ('Dockerfile','requirements.txt'):continue
            text=p.read_text(errors='replace');fid=file_node(rel)
            if p.name=='package.json':
                try:
                    obj=json.loads(text)
                    for section in ('dependencies','devDependencies'):
                        for name,version in list(obj.get(section,{}).items())[:300]:
                            dep=node('Dependency',name,version=str(version)[:150],scope='development' if section=='devDependencies' else 'production');edge(fid,dep,'DEPENDS_ON',rel)
                except (ValueError,AttributeError):gaps.append('Unparsed dependency manifest: '+rel)
            for m in re.finditer(r'(?:process\.env\.([A-Z][A-Z0-9_]{2,80})|(?:getenv|environ\.get)\([\'"]([A-Z][A-Z0-9_]{2,80})[\'"])',text):
                name=m[1] or m[2];eid=node('Environment Variable',name,rel,line=text[:m.start()].count('\n')+1);edge(fid,eid,'USES','Environment variable name only; value never retained')
            for m in re.finditer(r'(?i)create\s+table\s+(?:if\s+not\s+exists\s+)?([\w.]+)',text if p.suffix=='.sql' else ''):
                tid=node('Database Table',m[1],rel);edge(fid,tid,'DECLARES','SQL declaration; deployed table unverified')
            for m in re.finditer(r"\.(from|collection|table)\(['\"]([\w.-]{1,100})['\"]\)",text):
                tid=node('Database Table',m[2]);edge(fid,tid,'USES','Literal database/collection reference; operation semantics unverified')
            if re.search(r'(^|/)(middleware|auth|permissions?)\b',rel,re.I):
                # Digest detects changes without retaining security logic or values.
                control=node('Security Control',rel,rel,revision=hashlib.sha256(text.encode()).hexdigest());edge(fid,control,'DECLARES','Security-related filename; effectiveness unverified')
            if rel.startswith('.github/workflows/'):
                cid=node('CI/CD',rel,rel,revision=hashlib.sha256(text.encode()).hexdigest());edge(repo,cid,'TRIGGERS','Workflow configuration')
            if p.name in ('vercel.json','wrangler.toml','firebase.json','Dockerfile'):
                did=node('Deployment',p.name,rel);edge(repo,did,'DEPLOYS_TO','Deployment declaration; live target unverified')
            if p.suffix=='.py':
                try:
                    tree=ast.parse(text);functions={n.name:n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
                    ids={name:node('Function',name,rel,n.lineno) for name,n in list(functions.items())[:100]}
                    for name,n in functions.items():
                        if name not in ids:continue
                        edge(fid,ids[name],'DECLARES','Python AST function declaration')
                        for call in ast.walk(n):
                            if isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id in ids:edge(ids[name],ids[call.func.id],'CALLS','Python AST local name; dynamic binding unverified')
                except SyntaxError:gaps.append('Python AST parse failed: '+rel)
    else:gaps.append('Historical scan predates source graph extraction; metadata-only graph')
    for f in findings:
        fid=node('Finding',f.get('title','Finding'),f.get('file',''),f.get('line',1),fingerprint=f.get('fingerprint'),finding_id=f.get('id'),severity=f.get('severity'),category=f.get('engine'))
        target=file_node(f.get('file','unknown'));edge(target,fid,'HAS_FINDING','Deterministic scanner output')
        if f.get('engine')=='Secrets':
            sid=node('Secret','Credential candidate',f.get('file',''),f.get('line',1),verification='Active status unknown');edge(target,sid,'CONTAINS_SECRET','Redacted scanner finding; no value or cross-repository correlation retained');edge(sid,fid,'HAS_FINDING','Secret candidate, not confirmed active credential')
        if f.get('package'):
            dep=node('Dependency',f['package'],version=f.get('installed_version'),scope=f.get('scope','unknown'));edge(target,dep,'DEPENDS_ON','Pinned manifest advisory match');edge(dep,fid,'HAS_FINDING','Published advisory; vulnerable function use unknown')
    # Keep graph bounded, and explicitly disclose truncation.
    if len(nodes)>2500:gaps.append('Graph capped at 2500 nodes')
    nodes=dict(list(nodes.items())[:2500]);edges={k:e for k,e in edges.items() if e['source'] in nodes and e['target'] in nodes}
    if len(edges)>6000:gaps.append('Graph capped at 6000 edges')
    return {'schema':SCHEMA,'nodes':list(nodes.values()),'edges':list(edges.values())[:6000],'gaps':gaps,'note':'Declarations and static associations; no proof of authorization, data transfer, or exploitability.'}

def graph_diff(before,after):
    a={n['id']:n for n in before.get('nodes',[])};b={n['id']:n for n in after.get('nodes',[])}
    ae={e['id']:e for e in before.get('edges',[])};be={e['id']:e for e in after.get('edges',[])}
    added=[b[k] for k in b.keys()-a.keys()];removed=[a[k] for k in a.keys()-b.keys()]
    changed=[{'before':a[k],'after':b[k]} for k in a.keys()&b.keys() if any(a[k].get(f)!=b[k].get(f) for f in ('revision','version','scope'))]
    risks=[]
    for n in added:
        if n['type'] in ('External API','API Route','Database Table','Auth Provider','Deployment','Secret','Environment Variable'):
            risks.append({'node_id':n['id'],'kind':'added '+n['type'],'severity':'High' if n['type']=='Secret' or 'admin' in n['label'].lower() else 'Medium','reason':'New declaration requires review. Exposure and control effectiveness are unverified.'})
    for n in removed:
        if n['type']=='Security Control':risks.append({'node_id':n['id'],'kind':'removed security control','severity':'High','reason':'Security-related source removed; confirm replacement controls.'})
    for n in changed:
        if n['after']['type']=='Security Control':risks.append({'node_id':n['after']['id'],'kind':'changed security logic','severity':'Medium','reason':'Source digest changed; manual semantic review required.'})
    return {'added_nodes':sorted(added,key=lambda n:n['id']),'removed_nodes':sorted(removed,key=lambda n:n['id']),'changed_nodes':changed,'added_edges':[be[k] for k in be.keys()-ae.keys()],'removed_edges':[ae[k] for k in ae.keys()-be.keys()],'risks':risks,'impact':'HIGH' if any(r['severity']=='High' for r in risks) else 'MEDIUM' if risks else 'LOW'}

def traverse(graph,start,direction='downstream',limit=200):
    links=defaultdict(list)
    for e in graph.get('edges',[]):
        source,target=(e['target'],e['source']) if direction=='upstream' else (e['source'],e['target'])
        links[source].append(target)
    visited={start};queue=deque([(start,[start])]);paths=[]
    while queue and len(visited)<limit:
        node,chain=queue.popleft()
        for target in links[node]:
            if target in visited:continue
            visited.add(target);path=chain+[target];paths.append(path)
            if len(path)<9:queue.append((target,path))
    return {'node_ids':sorted(visited),'paths':paths,'bounded':bool(queue),'note':'Static graph reachability, not proven runtime execution.'}

def prioritize(findings,summary,recurring=None,runtime=None):
    recurring=recurring or {};routes=summary.get('route_inventory',{}).get('routes',[]);out=[]
    runtime_paths=(runtime or {}).get('attack_paths',[])
    for f in findings:
        base=SEVERITY.get(f.get('severity'),45);score=base;reasons=[f"Scanner severity: {f.get('severity','Unknown')} ({base})"]
        links=[r['path'] for r in routes if f.get('file') in r.get('imports',{})]
        if links:score+=8;reasons.append('Linked through a route/import chain (+8); execution unverified')
        observed=[p for p in runtime_paths if p.get('finding_id') in (f.get('id'),f.get('fingerprint')) and 200<=p.get('status',0)<300]
        if observed:score+=8;reasons.append('Associated route responded without supplied credentials (+8); exploitability still unverified')
        count=recurring.get(finding_key(f),0)
        if count>1:score+=min(10,(count-1)*3);reasons.append('Reintroduced in comparable history (+3 per recurrence, capped at 10)')
        production='test-only candidate' if re.search(r'(^|/)(tests?|__tests__|fixtures?)/',f.get('file','')) else f.get('scope','unknown')
        if production in ('test-only candidate','development'):reasons.append('Development/test context detected; production reachability still unknown')
        # Unknown reachability, secret validity and auth do not lower the score.
        score=min(100,score)
        priority='MUST FIX BEFORE DEPLOYMENT' if f.get('severity')=='Critical' or f.get('engine')=='Secrets' else 'FIX SOON' if score>=70 else 'REVIEW' if score>=30 else 'INFORMATIONAL'
        out.append({**f,'risk_score':score,'priority_category':priority,'risk_reasons':reasons,'route_links':links[:10],'production_context':production,'exploitability':'unverified','auth_requirement':'unknown','sensitive_data_access':'unknown','secret_active':'unknown' if f.get('engine')=='Secrets' else None,'recurrences':count})
    return sorted(out,key=lambda f:(-f['risk_score'],f.get('fingerprint','')))

def memory(scans):
    """Input chronological on ONE branch. Absence in partial scans is never resolution."""
    records={};previous_complete=None;timeline=[]
    for s in scans:
        current={finding_key(f):f for f in s.get('findings',[])}
        complete=s.get('status')=='completed'
        for key,f in current.items():
            if key not in records:records[key]={'key':key,'title':f.get('title'),'category':f.get('engine'),'file':f.get('file'),'first_seen':s['created_at'],'last_seen':s['created_at'],'occurrences':1,'observations':0,'reintroduced':0,'state':'observed','events':[],'root_cause':'Unverified; developer investigation required','preventive_control':{'Secrets':'Add pre-commit secret checks and rotate confirmed exposed credentials.','Authentication':'Add ownership and role regression tests.','Dependencies':'Automate reviewed dependency updates.'}.get(f.get('engine'),'Add a targeted security regression test.')}
            rec=records[key]
            if rec['state']=='absent_in_complete_scan':rec['occurrences']+=1;rec['reintroduced']+=1;rec['events'].append({'scan_id':s['id'],'at':s['created_at'],'type':'reintroduced'})
            rec.update(last_seen=s['created_at'],state='observed',observations=rec['observations']+1)
        if complete and previous_complete is not None:
            for key in previous_complete-current.keys():
                if key in records:records[key]['state']='absent_in_complete_scan';records[key]['events'].append({'scan_id':s['id'],'at':s['created_at'],'type':'not_detected','note':'Absence in a complete scan; does not prove remediation.'})
        if complete:previous_complete=set(current)
        timeline.append({'scan_id':s['id'],'at':s['created_at'],'score':s.get('score'),'commit':s.get('commit'),'status':s.get('status'),'findings':len(current)})
    return {'patterns':sorted(records.values(),key=lambda r:(-r['reintroduced'],-r['observations'])),'timeline':timeline,'scope':'One branch; current scanner coverage. Repeated observations are not repeated incidents.'}

def decide(summary,findings,policy,diff=None,runtime=None):
    rules={**DEFAULT_POLICY,**policy};blockers=[];gaps=[]
    def block(rule,reason,refs):blockers.append({'rule':rule,'reason':reason,'finding_refs':refs})
    for f in findings:
        if (rules['block_critical'] and f.get('severity')=='Critical') or (rules['block_high'] and f.get('severity')=='High') or (rules['block_secret'] and f.get('engine')=='Secrets'):
            block('finding_threshold',f.get('title','Finding'),[f.get('fingerprint',f.get('id'))])
    if summary.get('status')!='completed':gaps.append('A complete repository scan is required')
    score=summary.get('score')
    if score is None:gaps.append('Security score unavailable')
    elif score<rules['minimum_score']:block('minimum_score',f"Score {score} is below policy minimum {rules['minimum_score']}",[])
    if rules['block_regression'] and (diff or {}).get('regression'):block('regression','Score decreased between comparable scans; review the linked changes',[])
    if rules['review_external_changes'] and any(n['type']=='External API' for n in (diff or {}).get('added_nodes',[])):block('external_change','New external service declaration requires review',[])
    if runtime and runtime.get('decision')=='NOT READY':block('runtime','Runtime review contains deployment blockers',[])
    if rules['require_runtime']:
        if not runtime or runtime.get('status')!='completed' or runtime.get('source_commit')!=summary.get('commit'):gaps.append('Complete runtime evidence tied to this source commit is required')
    decision='NOT READY' if blockers else 'INCOMPLETE' if gaps else 'READY WITH WARNINGS' if findings or (diff or {}).get('risks') else 'READY'
    return {'decision':decision,'blockers':blockers,'gaps':gaps,'policy':rules,'score':score,'allowed':decision in ('READY','READY WITH WARNINGS'),'explanation_source':'Deterministic evidence and policy; no LLM decision','note':'Readiness is bounded by the performed checks, not a security guarantee.'}
