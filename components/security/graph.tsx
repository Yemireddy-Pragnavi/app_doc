'use client';
import {useMemo,useState} from 'react';
import {ReactFlow,Background,Controls,BackgroundVariant,MarkerType,Node,Edge} from '@xyflow/react';
import {useReducedMotion} from 'framer-motion';
import {Code2,Database,FolderGit2,Globe,KeyRound,Server,X} from 'lucide-react';
import '@xyflow/react/dist/style.css';
import {demoRepo} from './data';
export type MapComponent={name:string;evidence?:string;kind?:string;inferred?:boolean};
export type MapEdge={source:string;target:string;evidence?:string;inferred?:boolean};
const classify=(name:string)=>/PostgreSQL|MongoDB|MySQL|SQLite/.test(name)?'database':/Supabase|Firebase|Auth|Clerk/.test(name)?'auth':/Next.js|React|Vue|Svelte/.test(name)?'frontend':/Express|FastAPI|Django|Flask|Node.js|API Routes/.test(name)?'backend':'integration';
const icons={database:Database,auth:KeyRound,frontend:Code2,backend:Server,integration:Globe,repository:FolderGit2};
export function ApplicationGraph({active=false,technologies=demoRepo.technologies,components=[],edges:inferredEdges=[]}:{active?:boolean;technologies?:string[];components?:MapComponent[];edges?:MapEdge[]}){
 const reduced=useReducedMotion();const [selected,setSelected]=useState<MapComponent|null>(null);
 const {nodes,edges}=useMemo(()=>{
  const actual=components.length?Array.from(new Map(components.map(c=>[c.name,c])).values()):technologies.filter(t=>!['TypeScript','JavaScript','Python','npm','pnpm','Yarn','Poetry'].includes(t)).map(name=>({name,kind:classify(name),evidence:'Package manifest; relationship inferred',inferred:true}));
  const nodes:Node[]=[{id:'repository',position:{x:220,y:0},data:{label:<div className="flow-label"><FolderGit2 size={19}/><span>GitHub repository<small>Source & configuration</small></span></div>},className:'flow-repository',sourcePosition:'bottom' as any}];
  const useEdges=inferredEdges.length?inferredEdges:actual.map(c=>({source:'repository',target:c.name,evidence:'Declared in repository',inferred:true}));
  actual.forEach((c,i)=>{const kind=c.kind||classify(c.name);const Icon=icons[kind as keyof typeof icons]||Globe;nodes.push({id:c.name,position:{x:(i%3)*215,y:135+Math.floor(i/3)*140},data:{component:c,label:<div className="flow-label"><Icon size={19}/><span>{c.name}<small>{kind}</small></span></div>},className:'flow-tech '+(active&&!reduced?'flow-scanning':''),ariaLabel:c.name+' '+kind})});
  const ids=new Set(nodes.map(n=>n.id));const edges:Edge[]=useEdges.filter(e=>ids.has(e.source)&&ids.has(e.target)&&e.source!==e.target).map((e,i)=>({id:'edge-'+i,source:e.source,target:e.target,animated:active&&!reduced,style:{stroke:'#b8759b',strokeWidth:1.7},markerEnd:{type:MarkerType.ArrowClosed,color:'#b8759b'},data:{evidence:e.evidence}}));
  if(actual.length&&inferredEdges.length) edges.unshift({id:'root',source:'repository',target:actual[0].name,animated:active&&!reduced,style:{stroke:'#b8759b'}});
  return {nodes,edges};
 },[technologies,components,inferredEdges,active,reduced]);
 return <div className={'application-flow '+(active?'is-scanning':'')}><ReactFlow nodes={nodes} edges={edges} fitView fitViewOptions={{padding:.22}} minZoom={.3} maxZoom={2} nodesDraggable={false} nodesConnectable={false} zoomOnScroll={false} panOnScroll={false} onNodeClick={(_,node)=>setSelected((node.data.component as MapComponent)||{name:'GitHub repository',evidence:'Source manifests, imports, environment variable names and folder structure.'})}><Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#6d476d"/><Controls showInteractive={false}/></ReactFlow>{selected&&<div className="map-inspector" role="status"><button onClick={()=>setSelected(null)} aria-label="Close node details"><X size={15}/></button><strong>{selected.name}</strong><p>{selected.evidence||'Inferred from repository configuration.'}</p><small>Inferred relationship · runtime access is not verified</small></div>}<span className="map-caption">Drag to pan · Zoom with controls · Select a node</span></div>
}
