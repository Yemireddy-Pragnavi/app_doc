"""Bounded, deterministic scanner adapters. Never import or execute repository code."""
import hashlib,json,os,re,subprocess,resource,tomllib
from pathlib import Path
import httpx,yaml
from cvss import CVSS3,CVSS4
from .config import settings
from .security import redact
RULES=Path(__file__).resolve().parent.parent/'rules'
IGNORE={'.git','node_modules','.venv','venv','dist','build','.next','vendor'}
def limits():
    resource.setrlimit(resource.RLIMIT_CPU,(220,220))
    resource.setrlimit(resource.RLIMIT_FSIZE,(128_000_000,128_000_000))
    resource.setrlimit(resource.RLIMIT_NOFILE,(1024,1024))
def command(args,cwd,extra_env=None,allowed=(0,)):
    env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':'/tmp','LANG':'C.UTF-8','GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','SEMGREP_SEND_METRICS':'off'}
    if extra_env:env.update(extra_env)
    # Redirect to a bounded temporary file rather than accumulating unbounded stdout.
    import tempfile
    with tempfile.TemporaryFile() as out:
        p=subprocess.run(args,cwd=cwd,env=env,stdout=out,stderr=subprocess.DEVNULL,timeout=settings().scan_timeout,preexec_fn=limits)
        if p.returncode not in allowed:raise RuntimeError('Scanner process failed')
        out.seek(0);raw=out.read(32_000_001)
        if len(raw)>32_000_000:raise RuntimeError('Scanner output limit exceeded')
        return raw.decode('utf-8',errors='replace')
def source_files(root):
    result=[];total=0
    for base,dirs,files in os.walk(root,followlinks=False):
        dirs[:]=[d for d in dirs if d not in IGNORE and not (Path(base)/d).is_symlink()]
        for name in files:
            p=Path(base)/name
            if p.is_symlink() or not p.is_file():continue
            size=p.stat().st_size;total+=size
            if total>settings().max_source_bytes or len(result)>=settings().max_source_files:raise RuntimeError('Repository source limit exceeded')
            if size<=2_000_000:result.append(p)
    return result

def finding(engine,title,severity,file,line,description,remediation,confidence=.8,cwe=None,evidence='Source evidence omitted to prevent credential disclosure.',**extra):
    fp=hashlib.sha256(f'{engine}|{title}|{file}|{line}'.encode()).hexdigest()[:24]
    return {'fingerprint':fp,'title':redact(title),'engine':engine,'source':{'Code':'Semgrep','Secrets':'Gitleaks','Dependencies':'OSV','Authentication':'Auth pattern analysis'}[engine],'severity':severity,'file':redact(file),'line':int(line or 1),'description':redact(description),'evidence':redact(evidence),'remediation':redact(remediation),'confidence':confidence,'cwe':cwe,'impact':redact(extra.pop('impact',description)),'status':'open',**extra}
def detect(root,files):
    tech=set();evidence={};kinds={}
    mapping={'next':('Next.js','frontend'),'react':('React','frontend'),'express':('Express','backend'),'@supabase/supabase-js':('Supabase','auth'),'firebase':('Firebase','auth'),'stripe':('Stripe','integration'),'openai':('OpenAI','integration'),'pg':('PostgreSQL','database'),'mongoose':('MongoDB','database'),'@aws-sdk/client-s3':('AWS','integration'),'fastapi':('FastAPI','backend'),'django':('Django','backend'),'flask':('Flask','backend'),'psycopg':('PostgreSQL','database')}
    def add(name,kind,path,reason):
        tech.add(name);kinds[name]=kind;evidence.setdefault(name,[])
        if len(evidence[name])<4:evidence[name].append(path+': '+reason)
    for p in files:
        rel=str(p.relative_to(root))
        if p.suffix in ('.ts','.tsx'):tech.add('TypeScript')
        if p.suffix in ('.js','.jsx','.mjs'):tech.add('JavaScript')
        if p.suffix=='.py':tech.add('Python')
        if p.name=='package.json':
            try:
                obj=json.loads(p.read_text());deps={**obj.get('dependencies',{}),**obj.get('devDependencies',{})};tech.add('Node.js')
                for dep,(name,kind) in mapping.items():
                    if dep in deps:add(name,kind,rel,'declared dependency')
            except (ValueError,OSError):pass
        if p.name in ('requirements.txt','pyproject.toml'):
            text=p.read_text(errors='replace').lower()
            for dep,(name,kind) in mapping.items():
                if re.search(r'\b'+re.escape(dep)+r'\b',text):add(name,kind,rel,'declared dependency')
        if p.suffix in ('.js','.jsx','.ts','.tsx','.py'):
            text=p.read_text(errors='replace')
            imports=re.findall(r"(?:from\s+['\"]([^'\"]+)['\"]|require\(['\"]([^'\"]+)['\"]\)|(?:from|import)\s+([a-zA-Z_][\w.]*))",text)
            modules={part for row in imports for part in row if part}
            for dep,(name,kind) in mapping.items():
                if any(mod==dep or mod.startswith(dep+'/') or mod.startswith(dep+'.') for mod in modules):add(name,kind,rel,'module import')
            for marker,name,kind in [('SUPABASE_','Supabase','auth'),('STRIPE_','Stripe','integration'),('OPENAI_','OpenAI','integration'),('FIREBASE_','Firebase','auth')]:
                if re.search(r'(process\.env\.|os\.(?:getenv|environ)[^(]*[\(\[])[^\n]*'+marker,text):add(name,kind,rel,'environment variable name')
            if re.search(r'(^|/)(?:app/api|pages/api|api/routes)/',rel):add('API Routes','backend',rel,'API folder structure')
        for lock,manager in [('package-lock.json','npm'),('pnpm-lock.yaml','pnpm'),('yarn.lock','Yarn'),('poetry.lock','Poetry')]:
            if p.name==lock:tech.add(manager)
        if p.name=='vercel.json':add('Vercel','integration',rel,'deployment configuration')
    ordered=sorted(tech,key=lambda x:(x not in ['Next.js','React','FastAPI','Express'],x))
    components=[{'name':n,'kind':kinds[n],'evidence':'; '.join(evidence[n]),'inferred':True} for n in ordered if n in evidence]
    front=next((c['name'] for c in components if c['kind']=='frontend'),None)
    back=next((c['name'] for c in components if c['kind']=='backend'),None)
    root_name=front or back
    edges=[]
    for c in components:
        source=back if c['kind'] in ['database','auth','integration'] and back else root_name
        if source and source!=c['name']:edges.append({'source':source,'target':c['name'],'evidence':c['evidence'],'inferred':True})
    return ordered,components,edges

def semgrep(root):
    output=command(['semgrep','scan','--config',str(RULES/'security.yaml'),'--json','--metrics','off','--disable-version-check','--no-git-ignore','--exclude','.git','--timeout','20',str(root)],root)
    data=json.loads(output);results=[]
    for r in data.get('results',[]):
        e=r.get('extra',{});m=e.get('metadata',{});path=Path(r['path'])
        try:file=str(path.relative_to(root)) if path.is_absolute() else str(path)
        except ValueError:continue
        results.append(finding('Code',m.get('title',r['check_id'].split('.')[-1]),m.get('severity','Medium'),file,r['start']['line'],e.get('message','Potential insecure code pattern.'),m.get('remediation','Review the code and replace the insecure operation.'),float(m.get('confidence',.8)),m.get('cwe')))
    errors=data.get('errors',[])
    return results,{'status':'partial' if errors else 'completed','note':f'{len(errors)} parse/scan errors. Local Phase 1 rule pack; not exhaustive.','errors':len(errors)}

def gitleaks(root):
    import tempfile
    with tempfile.TemporaryDirectory(prefix='gitleaks-') as tmp:
        report=Path(tmp)/'report.json'
        command(['gitleaks','git',str(root),'--config',str(RULES/'gitleaks.toml'),'--redact=100','--report-format','json','--report-path',str(report),'--exit-code','0','--no-banner'],root)
        data=json.loads(report.read_text()) if report.exists() else []
    results=[]
    for r in data:
        results.append(finding('Secrets',r.get('Description','Potential credential exposed'),'Critical',r.get('File','unknown'),r.get('StartLine',1),'A credential-like value appears in repository history. Validate its type and rotate it if genuine.','Rotate the credential, remove it from source and history, move it to a secret store, and review access logs.',.9,'CWE-798',evidence='[REDACTED CREDENTIAL] — '+r.get('RuleID','secret'),commit=r.get('Commit','')[:40]))
    return results,{'status':'completed','note':'Bounded Git history scan (up to 100 commits); all credential evidence redacted.'}

def auth_checks(root,files):
    results=[]
    for p in files:
        if p.suffix not in ('.js','.jsx','.ts','.tsx','.py'):continue
        rel=str(p.relative_to(root));text=p.read_text(errors='replace')
        if re.search(r'(^|/)(?:tests?|fixtures?|__tests__)(/|$)',rel):continue
        checks=[]
        if re.search(r'(?:jwt\.decode|jwtDecode)\s*\(',text) and not re.search(r'jwt\.verify|verifyJwt|jwtVerify',text):checks.append(('Potential unverified JWT claims','Medium','CWE-347','Verify signature, algorithm, issuer, audience and expiry before trusting claims.',r'(?:jwt\.decode|jwtDecode)\s*\('))
        if 'admin' in rel.lower() and re.search(r'export\s+(?:async\s+)?function\s+(GET|POST|DELETE|PUT)|router\.(get|post|delete)|@\w+\.(get|post|delete)',text) and not re.search(r'getUser|current_user|requireAdmin|authorize|hasRole|isAdmin|checkPermission',text):checks.append(('Potential authorization weakness in admin route','High','CWE-862','Verify session and administrator privileges server-side. Inspect upstream middleware before concluding this is exploitable.',r'admin|export|router|@'))
        if ('use client' in text or re.search(r'(^|/)(?:client|public|frontend)/',rel)) and re.search(r'SERVICE_ROLE|service_role',text):checks.append(('Potential privileged service-role access in client code','High','CWE-798','Keep service-role credentials on a trusted backend. Rotate exposed credentials and inspect the generated client bundle.',r'SERVICE_ROLE|service_role'))
        if re.search(r'(params|body|query)\.(userId|user_id)',text) and not re.search(r'owner|current_user|getUser|session\.user|authorize',text):checks.append(('Potential missing ownership validation','Medium','CWE-639','Compare the requested resource owner against the authenticated user on the server. Inspect shared authorization controls.',r'(params|body|query)\.(userId|user_id)'))
        for title,severity,cwe,fix,pattern in checks:
            match=re.search(pattern,text);line=text[:match.start()].count('\n')+1 if match else 1
            results.append(finding('Authentication',title,severity,rel,line,'A targeted heuristic found a potential weakness. Cross-file middleware and actual reachability have not been verified.',fix,.6,cwe,evidence='Pattern matched in this file; raw source is intentionally not retained.'))
    return results,{'status':'completed','note':'Heuristic local patterns only. Upstream authorization and exploitability are unverified.'}

def dependencies(root,files):
    packages=[];unsupported=[]
    for p in files:
        rel=str(p.relative_to(root))
        try:
            if p.name=='package-lock.json':
                obj=json.loads(p.read_text());entries=obj.get('packages',{})
                if not entries:unsupported.append(rel+' (lockfile v1 not supported)')
                for loc,d in entries.items():
                    if 'node_modules/' in loc and d.get('version'):
                        packages.append((loc.split('node_modules/')[-1],d['version'],'npm',rel,'development' if d.get('dev') else 'production'))
            elif p.name=='requirements.txt':
                for line in p.read_text().splitlines():
                    m=re.match(r'^\s*([\w.-]+)(?:\[[^]]+\])?==([\w.+-]+)',line)
                    if m:packages.append((m[1],m[2],'PyPI',rel,'unknown'))
                    elif line.strip() and not line.lstrip().startswith('#'):unsupported.append(rel+' (unpinned or unsupported requirement)')
            elif p.name=='poetry.lock':
                obj=tomllib.loads(p.read_text())
                for d in obj.get('package',[]):packages.append((d['name'],d['version'],'PyPI',rel,'development' if d.get('category')=='dev' or d.get('groups')==['dev'] else 'unknown'))
            elif p.name=='pnpm-lock.yaml':
                obj=yaml.safe_load(p.read_text())
                for key in obj.get('packages',{}):
                    m=re.match(r'^/?(@?[^()]+?)[@/]([0-9][^()]*)',key)
                    if m:packages.append((m[1],m[2],'npm',rel,'unknown'))
                    else:unsupported.append(rel+' (unparsed package key)')
            elif p.name=='yarn.lock':
                text=p.read_text();found=0
                for m in re.finditer(r'(?m)^([^\s#][^\n]+):\n(?:[ \t]+[^\n]+\n)*?[ \t]+version[ :]+["\']?([^"\'\s]+)',text):
                    spec=m[1].split(',')[0].strip('"\'');name=spec.rsplit('@',1)[0]
                    if name:packages.append((name,m[2],'npm',rel,'unknown'));found+=1
                if not found:unsupported.append(rel+' (unsupported Yarn format)')
        except (ValueError,KeyError,yaml.YAMLError):unsupported.append(rel+' (invalid manifest)')
    packages=list(dict.fromkeys(packages));results=[];errors=0
    if len(packages)>500:unsupported.append('Dependency limit exceeded; first 500 pinned packages checked')
    if not packages:
        return [], {'status':'partial','note':'No supported exact pinned dependency versions found. '+'; '.join(unsupported[:8]),'packages_checked':0}
    with httpx.Client(timeout=20) as c:
        for name,version,ecosystem,file,scope in packages[:500]:
            try:
                r=c.post('https://api.osv.dev/v1/query',json={'package':{'name':name,'ecosystem':ecosystem},'version':version});r.raise_for_status()
                for v in r.json().get('vulns',[]):
                    if v.get('withdrawn'):continue
                    severity='Medium';cvss=None
                    for s in v.get('severity',[]):
                        try:
                            cvss=(CVSS4(s['score']) if s['type']=='CVSS_V4' else CVSS3(s['score'])).scores()[0]
                            severity='Critical' if cvss>=9 else 'High' if cvss>=7 else 'Medium' if cvss>=4 else 'Low'
                        except Exception:continue
                    dbsev=str(v.get('database_specific',{}).get('severity','')).title()
                    if cvss is None and dbsev in ['Critical','High','Medium','Low']:severity=dbsev
                    fixed=[]
                    for a in v.get('affected',[]):
                        if a.get('package',{}).get('name')==name:
                            for ran in a.get('ranges',[]):
                                fixed.extend(e['fixed'] for e in ran.get('events',[]) if 'fixed'in e)
                    results.append(finding('Dependencies',f'{name} {version}: {v["id"]}',severity,file,1,v.get('summary','Published vulnerability affects this pinned dependency.'),'Review '+v['id']+'. '+('Fixed releases listed by the advisory: '+', '.join(fixed)+'. Select the compatible patched release and test.' if fixed else 'No fixed release is listed. Review mitigations and upstream guidance.'),.95,evidence=f'{name}=={version}; advisory {v["id"]}',package=name,installed_version=version,fixed_versions=fixed,advisory=v['id'],aliases=v.get('aliases',[]),scope=scope,severity_estimated=cvss is None and not dbsev))
            except (httpx.HTTPError,ValueError):errors+=1
    if not packages:unsupported.append('No supported exact pinned dependency versions found')
    return results,{'status':'partial' if errors or unsupported else 'completed','note':f'{min(len(packages),500)} pinned packages queried; {errors} failed queries. '+'; '.join(unsupported[:8]),'packages_checked':min(len(packages),500)-errors}

def normalize(findings,complete=True):
    unique={}
    for f in findings:
        # Fingerprint remains stable for scan-to-scan comparison, separate from database ID.
        unique[f['fingerprint']]=f
    findings=list(unique.values())
    for f in findings:
        base={'Critical':10,'High':7,'Medium':4,'Low':1}[f['severity']]
        exposure=1.2 if re.search(r'(^|/)(public|client|api)/',f['file']) else 1.0
        reachability=.8;context=.7 if f.get('scope')=='development' else 1.0
        f['risk']=round(base*f['confidence']*reachability*exposure*context,2)
        f['risk_factors']={'severity':base,'confidence':f['confidence'],'reachability':reachability,'exposure':exposure,'application_context':context,'estimated':['reachability','exposure','application_context']}
        f['priority']='Must Fix' if f['risk']>=4.7 or f['severity']=='Critical' and f['confidence']>=.8 else 'Fix Soon' if f['risk']>=2.5 else 'Review' if f['risk']>=1 else 'Informational'
    findings.sort(key=lambda f:f['risk'],reverse=True)
    score=max(0,round(100-sum(f['risk']*2.5 for f in findings))) if complete else None
    return findings,score
