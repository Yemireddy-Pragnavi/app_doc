"""Combine all Phase 2 evidence without modifying Phase 1 scan scores."""
from .runtime import item, launch_verdict
from .reachability import correlate_routes
from .browser_bridge import observe_browser


def complete_review(report, source, static_findings, options, browser_runner=observe_browser):
    report={**report,'findings':list(report['findings']),'errors':list(report['errors']),'coverage':dict(report['coverage'])}
    def gap(area,reason):report['errors'].append({'path':area,'reason':reason})
    browser=browser_runner(report['target_url']) if options.get('browser',True) else {'status':'skipped','note':'Browser observation was not requested.','observations':[]}
    report['browser']=browser
    report['coverage']['browser']=browser['status']
    if browser['status']!='completed':gap('browser',browser.get('note','Browser inspection was incomplete.'))
    for issue in browser.get('issues',[]):
        finding=item(issue['rule'],issue['title'],issue['severity'],'/',issue['evidence'],issue['remediation'])
        finding['source']='Isolated browser observation';report['findings'].append(finding)
    cloud=source.get('cloud_review',{'status':'unavailable','findings':[],'note':'Rescan the repository to collect cloud configuration evidence.'})
    report['cloud_review']=cloud
    report['coverage']['cloud_configuration']=cloud['status']
    if options.get('cloud_applicable',True):
        if cloud['status'] not in ('completed',):gap('cloud',cloud.get('note','Cloud review incomplete.'))
        report['findings'].extend(cloud.get('findings',[]))
        for error in cloud.get('errors',[]):gap(error['path'],error['reason'])
    else:
        report['coverage']['cloud_configuration']='Declared not applicable by reviewer; deployment not independently checked'
        # Known configuration findings are retained even when user says N/A.
        report['findings'].extend(cloud.get('findings',[]))
    source_commit=source.get('commit','')
    declared=options.get('deployment_commit','')
    matched=bool(source_commit and declared and source_commit.lower()==declared.lower())
    report['deployment_identity']={'repository_commit':source_commit,'declared_deployment_commit':declared,'matches':matched,'verification':'Reviewer declaration; deployment provenance not independently verified'}
    if not matched:gap('deployment','Enter the full staging commit matching the selected repository assessment. A mismatch prevents a ready verdict.')
    observations=report['observations']+browser.get('observations',[])
    inventory=source.get('route_inventory',{})
    report['attack_paths']=correlate_routes(inventory,static_findings,observations)
    if inventory.get('status')=='partial':gap('source-map',inventory.get('note','Route graph coverage limited.'))
    report['coverage']['correlation']='Literal/dynamic route patterns and bounded local imports; inferred, not exploit validation'
    report['findings']=list({f['id']:f for f in report['findings']}.values())
    report['findings'].sort(key=lambda f: {'Critical':0,'High':1,'Medium':2,'Low':3}.get(f['severity'],4))
    report['status']='partial' if report['errors'] else 'completed'
    report['decision']=launch_verdict(report['repository_assessment'],report['findings'],not report['errors'])
    report['must_fix']=[{'title':f['title'],'source':f.get('source',f.get('engine','Repository scanner')),'location':f.get('path',f.get('file','')),'remediation':f.get('remediation','Review finding evidence.')} for f in static_findings+report['findings'] if f.get('priority')=='Must Fix']
    report['disclaimer']='Repository rules, bounded HTTP/browser observations and supported cloud declarations. Inferred paths and reviewer-supplied deployment identity are not proof of exploitability or complete cloud security.'
    return report
