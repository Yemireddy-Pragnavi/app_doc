import base64,tempfile,json
from pathlib import Path
from celery import Celery
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import select
from .config import settings
from .db import Session,Scan,Repository,User,Finding,Event,RuntimeScan,artifact
from .security import decrypt
from .scanners import command,source_files,detect,semgrep,gitleaks,dependencies,auth_checks,normalize
celery=Celery('security_doctor',broker=settings().redis_url)
celery.conf.update(broker_connection_timeout=3,broker_transport_options={'socket_connect_timeout':3,'socket_timeout':3},task_publish_retry=False,task_serializer='json',accept_content=['json'],result_serializer='json',worker_prefetch_multiplier=1,task_acks_late=False,task_soft_time_limit=1700,task_time_limit=1800,worker_max_tasks_per_child=1)
STAGES=['Fetching repository','Detecting technology stack','Mapping project structure','Scanning source code','Checking credentials','Analyzing dependencies','Reviewing authentication logic','Correlating findings','Calculating deployment readiness']
@celery.task(name='app.worker.run_scan')
def run_scan(scan_id):
    with Session() as db:
        scan=db.get(Scan,scan_id)
        if not scan or scan.status!='queued':return
        from .operations import reconcile_stale
        reconcile_stale(db,scan.user_id)
        db.refresh(scan)
        if scan.status!='queued':return
        repo=db.get(Repository,scan.repository_id);user=db.get(User,scan.user_id)
        def stage(n):
            scan.stage=n;scan.status='running';db.add(Event(scan_id=scan.id,data={'stage':n,'label':STAGES[n],'status':'running'}));db.commit()
        branch=scan.data.get('branch') or repo.data.get('default_branch','main')
        try:
            with tempfile.TemporaryDirectory(prefix='asd-scan-') as tmp:
                root=Path(tmp)/'source';stage(0)
                token=decrypt(user.encrypted_token)
                auth=base64.b64encode(('x-access-token:'+token).encode()).decode()
                # Exact GitHub origin, no submodules, no shell, no LFS smudge or hooks.
                command(['git','-c','core.hooksPath=/dev/null','-c','filter.lfs.smudge=','-c','filter.lfs.required=false','clone','--depth','100','--single-branch','--branch',branch,'--no-recurse-submodules','--','https://github.com/'+repo.full_name+'.git',str(root)],tmp,{'GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'http.https://github.com/.extraheader','GIT_CONFIG_VALUE_0':'Authorization: Basic '+auth,'GIT_LFS_SKIP_SMUDGE':'1'})
                del token,auth
                # Reject links before any scanner reads the checkout.
                for p in root.rglob('*'):
                    if p.is_symlink():p.unlink()
                files=source_files(root);stage(1)
                technologies,components,edges=detect(root,files);stage(2)
                commit=command(['git','rev-parse','HEAD'],root).strip()
                from .cloud_review import review_cloud
                from .reachability import route_inventory
                cloud_review=review_cloud(root,files)
                routes=route_inventory(root,files)
                repo.data={**repo.data,'technologies':technologies,'last_commit':commit}
                scan.data={**scan.data,'technologies':technologies,'components':components,'edges':edges,'commit':commit};db.commit()
                for t in technologies:artifact(db,'detected_technologies',scan.id,{'name':t})
                for c in components:artifact(db,'application_components',scan.id,c)
                for e in edges:artifact(db,'application_edges',scan.id,e)
                all_findings=[];coverage={}
                adapters=[('Code',3,lambda:semgrep(root)),('Secrets',4,lambda:gitleaks(root)),('Dependencies',5,lambda:dependencies(root,files)),('Authentication',6,lambda:auth_checks(root,files))]
                for name,n,run in adapters:
                    stage(n)
                    try:found,status=run();all_findings+=found;coverage[name]=status
                    except SoftTimeLimitExceeded:raise
                    except Exception:coverage[name]={'status':'failed','note':'Engine unavailable, timed out, or returned invalid output. Check worker configuration.'}
                stage(7);complete=all(v['status']=='completed' for v in coverage.values())
                findings,score=normalize(all_findings,complete);stage(8)
                previous=next((s for s in db.scalars(select(Scan).where(Scan.repository_id==repo.id,Scan.id!=scan.id,Scan.created_at<scan.created_at,Scan.status.in_(['completed','partial'])).order_by(Scan.created_at.desc())) if s.data.get('branch',repo.data.get('default_branch'))==branch),None)
                old=set(f.data['fingerprint'] for f in db.scalars(select(Finding).where(Finding.scan_id==previous.id))) if previous else set()
                new=set(f['fingerprint'] for f in findings)
                for f in findings:
                    f.update(repository_id=repo.id,scan_id=scan.id,created_at=scan.created_at)
                    db.add(Finding(scan_id=scan.id,user_id=user.id,data=f))
                    if f['engine'] in ['Secrets','Dependencies']:artifact(db,'secret_findings' if f['engine']=='Secrets' else 'dependency_findings',scan.id,f)
                decision='INCOMPLETE' if not complete else 'NOT READY' if any(f['priority']=='Must Fix' for f in findings) else 'READY WITH WARNINGS' if findings else 'READY'
                summary={'decision':decision,'summary':f'{len(findings)} findings identified. '+('Review engine failures or unsupported manifests before assessing readiness.' if not complete else 'Fix deployment blockers first, then review lower-confidence findings.'),'cloud_review':cloud_review,'route_inventory':routes,'summary_source':'Deterministic template','coverage':coverage,'technologies':technologies,'components':components,'edges':edges,'commit':commit,'branch':branch,'diff':{'new':len(new-old),'resolved':len(old-new) if complete and previous and previous.status=='completed' else None,'comparable':bool(complete and previous and previous.status=='completed'),'previous_score':previous.score if previous else None},'disclaimer':'This assessment represents identified risks from the performed security checks and is not a guarantee that the application contains no vulnerabilities.'}
                from .lifecycle import build_graph,configuration_findings
                summary['security_graph']=build_graph(summary,findings+configuration_findings(summary),root,files)
                from .reports import store_report
                try:summary['report_storage']=store_report(user.id,scan.id,{**summary,'score':score,'findings':findings})
                except Exception:summary['report_storage']={'status':'failed','note':'Normalized report remains available in the database.'}
                scan.status='completed' if complete else 'partial';scan.score=score;scan.stage=9;scan.data=summary
                repo.data={**repo.data,'score':score,'last_scan':scan.created_at}
                artifact(db,'scan_summaries',scan.id,summary);artifact(db,'security_scores',scan.id,{'score':score,'decision':decision})
                db.add(Event(scan_id=scan.id,data={'stage':9,'label':'Assessment stored','status':scan.status}));db.commit()
        except Exception:
            db.rollback();scan=db.get(Scan,scan_id);scan.status='failed';scan.score=None;scan.data={**scan.data,'decision':'INCOMPLETE','error':'Repository scan could not finish. Check repository access, worker tools, and resource limits. Source files were removed.'};db.commit()


@celery.task(name='app.worker.run_runtime', soft_time_limit=240, time_limit=270)
def run_runtime(scan_id):
    from .runtime import scan_runtime, target_url
    from urllib.parse import urlsplit
    from .reports import store_report
    with Session() as db:
        scan = db.get(RuntimeScan, scan_id)
        if not scan or scan.status != 'queued':
            return
        from .operations import reconcile_stale
        reconcile_stale(db, scan.user_id)
        db.refresh(scan)
        if scan.status != 'queued':
            return
        scan.status = 'running'
        db.commit()
        try:
            target = target_url(scan.data['target_url'])
            allowed = {h.strip().lower() for h in settings().runtime_allowed_hosts.split(',') if h.strip()}
            if urlsplit(target).hostname not in allowed:
                raise ValueError('Host is not authorized in worker configuration')
            source = db.get(Scan, scan.source_scan_id)
            if not source or source.user_id != scan.user_id or source.repository_id != scan.repository_id:
                raise ValueError('Invalid repository assessment')
            static = [{**f.data, 'id': f.id} for f in db.scalars(select(Finding).where(Finding.scan_id == source.id))]
            baseline = {'id': source.id, 'status': source.status, 'decision': source.data.get('decision', 'INCOMPLETE'), 'commit': source.data.get('commit'), 'branch': source.data.get('branch'), 'created_at': source.created_at}
            result = scan_runtime(target, scan.data.get('paths', []), baseline, static)
            from .launch_review import complete_review
            result = complete_review(result, source.data, static, scan.data)
            try:
                result['report_storage'] = store_report(scan.user_id, 'runtime-' + scan.id, result)
            except Exception:
                result['report_storage'] = {'status': 'failed', 'note': 'Report remains in the database.'}
            scan.status = result['status']
            scan.data = {**scan.data, **result}
            db.commit()
        except Exception:
            db.rollback()
            scan = db.get(RuntimeScan, scan_id)
            scan.status = 'failed'
            scan.data = {**scan.data, 'decision': 'INCOMPLETE', 'error': 'Runtime scan failed or timed out. Check the allowed host, public HTTPS connectivity and worker health.'}
            db.commit()


@celery.task(name='app.worker.reconcile_jobs')
def reconcile_jobs():
    from .operations import reconcile_stale
    with Session() as db:
        return reconcile_stale(db)

celery.conf.beat_schedule = {'recover-stale-scans': {'task': 'app.worker.reconcile_jobs', 'schedule': 60.0}}
