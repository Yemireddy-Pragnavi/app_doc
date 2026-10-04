"""Conservative review of supported repository-declared cloud/BaaS configuration.
Never treats declarations as confirmation of the deployed management-plane state.
"""
import json
import re
from .runtime import item

RULESET = 'cloud-config-v1'


def review_cloud(root, files):
    findings, inspected, errors, providers = [], [], [], set()
    def add(rule, title, severity, path, evidence, fix):
        f = item(rule, title, severity, path, evidence, fix)
        f.update(source='Repository configuration', confidence='Declared configuration; deployment unverified')
        findings.append(f)
    selected = [p for p in files if p.suffix in ('.sql', '.rules', '.json', '.yaml', '.yml')]
    for p in selected[:500]:
        rel = p.relative_to(root).as_posix()
        if re.search(r'(^|/)(tests?|fixtures?|node_modules)(/|$)', rel):
            continue
        text = p.read_text(errors='replace')
        if p.suffix == '.sql' and ('supabase/' in rel or 'auth.uid' in text or 'auth.jwt' in text):
            providers.add('Supabase'); inspected.append(rel)
            # Only explicit unsafe statements: absence in one migration says nothing
            # about the final schema. Remove comments before heuristic inspection.
            sql = re.sub(r'/\*[\s\S]*?\*/|--[^\n]*', '', text)
            if re.search(r'\bdisable\s+row\s+level\s+security\b', sql, re.I):
                add('rls-disabled', 'Migration explicitly disables row-level security', 'High', rel,
                    'A DISABLE ROW LEVEL SECURITY statement is present. Later migrations and deployed grants are not resolved.',
                    'Review migration order and keep RLS enabled on API-exposed tables. Test grants and row policies with each client role.')
            for statement in sql.split(';'):
                if re.search(r'\bcreate\s+policy\b', statement, re.I) and re.search(r'\b(?:using|with\s+check)\s*\(\s*true\s*\)', statement, re.I):
                    add('rls-unrestricted', 'Policy contains an unrestricted row predicate', 'Medium', rel,
                        'A policy uses a literal true predicate. Public read access can be intentional; effective roles/grants need review.',
                        'Confirm the operation and target roles. Use ownership predicates for private rows and test both allowed and denied access.')
            if re.search(r'auth\.jwt\s*\(\s*\)[\s\S]{0,80}user_metadata', sql, re.I):
                add('jwt-metadata', 'Policy may trust user-editable metadata', 'High', rel,
                    'A JWT expression references user_metadata.', 'Do not base authorization on user-editable metadata. Use controlled claims or database authorization checks.')
        elif p.name in ('firestore.rules', 'storage.rules'):
            providers.add('Firebase'); inspected.append(rel)
            rules = re.sub(r'/\*[\s\S]*?\*/|//[^\n]*', '', text)
            for match in re.finditer(r'allow\s+([\w\s,]+)\s*:\s*if\s+true\s*;', rules):
                write = bool(re.search(r'\b(write|create|update|delete)\b', match[1]))
                add('firebase-write' if write else 'firebase-read', 'Firebase rule allows unconditional '+('writes' if write else 'reads'), 'High' if write else 'Medium', rel,
                    'An allow rule has the literal condition true; its match scope requires review.',
                    'Restrict writes to authorized owners and validate fields. Intentionally public reads should be scoped and documented.')
        elif p.suffix == '.json' and p.name not in ('package-lock.json', 'package.json'):
            # CloudFormation JSON and Firebase RTDB exports; no general JSON execution.
            try:
                obj = json.loads(text)
            except ValueError:
                if p.name in ('database.rules.json','firebase.json'):
                    errors.append({'path': rel, 'reason': 'Unsupported or malformed JSON configuration.'})
                continue
            if not isinstance(obj, dict):continue
            if p.name == 'database.rules.json':
                providers.add('Firebase'); inspected.append(rel)
                def walk(node, depth=0):
                    if not isinstance(node,dict) or depth>20:return
                    for k,v in node.items():
                        if k in ('.read','.write') and (v is True or v == 'true'):
                            add('rtdb'+k,'Realtime Database allows unconditional '+k[1:], 'High' if k=='.write' else 'Medium',rel,'A literal true access rule is declared.','Restrict the rule by authenticated ownership and validate allowed data.')
                        elif isinstance(v,dict):walk(v,depth+1)
                walk(obj.get('rules',{}))
            resources=obj.get('Resources',{})
            if isinstance(resources,dict):
                for resource in resources.values():
                    if not isinstance(resource,dict) or resource.get('Type')!='AWS::S3::Bucket':continue
                    providers.add('AWS S3'); inspected.append(rel)
                    props=resource.get('Properties',{}); block=props.get('PublicAccessBlockConfiguration',{})
                    if props.get('AccessControl') in ('PublicRead','PublicReadWrite'):
                        add('s3-acl','S3 template requests public object access','High',rel,'A public ACL is explicitly declared. Account-level blocking and effective access are unverified.','Use private access with signed URLs or document intentional public hosting. Verify account and bucket public-access blocking.')
                    if any(block.get(k) is False for k in ('BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets')):
                        add('s3-block','S3 public-access blocking explicitly relaxed','Medium',rel,'At least one PublicAccessBlockConfiguration flag is false.','Review effective account/bucket settings and keep all applicable public-access blocking controls enabled.')
        elif p.suffix in ('.yaml','.yml') and re.search(r'AWS::|google_|supabase|firebase',text,re.I):
            errors.append({'path':rel,'reason':'Cloud YAML is outside this rule pack. Supply/review a supported JSON configuration; no clean verdict inferred.'})
    if len(selected)>500:errors.append({'path':'repository','reason':'Configuration file inspection limit reached.'})
    unique={f['id']:f for f in findings}
    return {'ruleset':RULESET,'status':'partial' if errors else 'completed' if inspected else 'not_detected',
            'providers':sorted(providers),'files':sorted(set(inspected)), 'findings':list(unique.values()),'errors':errors,
            'deployment_verified':False,'note':'Supported declarative checks only. Review the live provider settings separately; absent files do not prove a secure cloud configuration.'}
