import type {Finding} from './data';
/** Manual triage never changes the immutable scan's launch decision. */
export function launchDecision(score:number|null,findings:Finding[],status?:string){
 if(status==='failed')return 'SCAN FAILED';
 if(status==='partial')return 'INCOMPLETE';
 if(score===null)return 'NOT ASSESSED';
 if(findings.some(f=>f.priority==='Must Fix'))return 'NOT READY';
 return findings.length?'READY WITH WARNINGS':'READY';
}
export function matchesFinding(f:Finding,filter:string,query:string){return (filter==='All'||f.severity===filter||f.engine===filter||f.priority===filter||(filter==='Fixed'&&f.status==='fixed'))&&(f.title+' '+f.file).toLowerCase().includes(query.toLowerCase())}
