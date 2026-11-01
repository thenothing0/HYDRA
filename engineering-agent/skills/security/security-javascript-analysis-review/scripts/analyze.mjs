// Offline AST inventory. Input JavaScript is parsed, never imported or evaluated.
import fs from 'node:fs';
import crypto from 'node:crypto';
import {parse, version} from './vendor/acorn.mjs';
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
const args=process.argv.slice(2);
if(args.length!==3 || args[1]!=='--output') { console.error('Usage: node analyze.mjs INPUT.js --output NEW.json'); process.exit(2); }
try {
 const [input,,output]=args;
 if(fs.lstatSync(input).isSymbolicLink() || fs.statSync(input).size>2*1024*1024) throw Error('input');
 if(fs.existsSync(output)) throw Error('output');
 const bytes=fs.readFileSync(input), source=bytes.toString('utf8');
 let tree,comments=[],mode;
 for(const sourceType of ['module','script']) {
  const collected=[];
  try {tree=parse(source,{ecmaVersion:'latest',sourceType,locations:true,onComment:collected});comments=collected;mode=sourceType;break;} catch {}
 }
 if(!tree) { console.error('Parse failed: unsupported/invalid syntax. No complete inventory produced; use a compatible parser for JSX/TypeScript.');process.exit(2); }
 function callee(n) {
  if(n?.type==='Identifier') return n.name;
  if(n?.type==='MemberExpression') {
   const base=callee(n.object), key=n.computed?literal(n.property):n.property?.name;
   return base && typeof key==='string'?base+'.'+key:null;
  }
  return null;
 }
 function literal(n) {
  if(n?.type==='Literal' && typeof n.value==='string') return n.value;
  if(n?.type==='TemplateLiteral' && n.expressions.length===0) return n.quasis[0].value.cooked;
  if(n?.type==='BinaryExpression' && n.operator==='+') {
   const a=literal(n.left),b=literal(n.right); return a!==null && b!==null?a+b:null;
  }
  return null;
 }
 function value(n) {
  const v=literal(n);
  if(v===null) return {resolved:false,expression_type:n?.type||'missing',reason:'nonliteral; no binding, template-expression or interprocedural resolution attempted'};
  return {resolved:true,value:v.split('?')[0]+(v.includes('?')?'?<redacted>':''),literal_sha256:hash(v),query_redacted:v.includes('?')};
 }
 const candidates=[],stack=[tree];let nodes=0;
 while(stack.length) {
  const n=stack.pop(); if(!n || typeof n!=='object') continue;
  if(++nodes>250000) throw Error('node budget');
  if(n.type==='CallExpression' || n.type==='NewExpression') {
   const c=callee(n.callee);
   let kind,index=0,method=null;
   if(c==='fetch'||c==='window.fetch'||c==='globalThis.fetch') {
    kind='fetch-call';method='GET';
    const options=n.arguments[1];
    if(options?.type==='ObjectExpression') {
     const p=options.properties.find(x=>!x.computed&&(x.key?.name||x.key?.value)==='method');
     if(p) method=literal(p.value); if(options.properties.some(x=>x.type==='SpreadElement')) method=null;
    } else if(options) method=null;
   } else if(c && /\.(get|post|put|patch|delete|head|options|open)$/.test(c)) {
    kind='method-call-candidate';method=c.split('.').at(-1).toUpperCase();
    if(method==='OPEN') {method=literal(n.arguments[0]);index=1;kind='open-call-candidate';}
   } else if(c==='URL'||c==='WebSocket'||c==='EventSource') kind='url-constructor-candidate';
   if(kind) candidates.push({kind,callee:c,line:n.loc.start.line,column:n.loc.start.column,method,...value(n.arguments[index]),qualification:'candidate only; receiver identity, reachability, credentials and authorization not inferred'});
  }
  if(n.type==='ImportExpression') candidates.push({kind:'dynamic-import',line:n.loc.start.line,column:n.loc.start.column,...value(n.source),qualification:'inventory only; no module fetched or executed'});
  for(const [k,v] of Object.entries(n)) {
   if(k==='loc')continue;
   if(Array.isArray(v)) stack.push(...v.filter(x=>x&&typeof x==='object'));
   else if(v&&typeof v==='object') stack.push(v);
  }
 }
 const maps=comments.filter(c=>/^[#@]\s*sourceMappingURL\s*=/.test(c.value.trim())).map(c=>{
  const locator=c.value.trim().replace(/^[#@]\s*sourceMappingURL\s*=\s*/,'');
  return {line:c.loc.start.line,locator_sha256:hash(locator),kind:locator.startsWith('data:')?'inline':/^https?:/.test(locator)?'remote':'relative',fetched:false};
 });
 const result={schema_version:'1.0',parser:{name:'acorn',version,source_type:mode},input_sha256:hash(bytes),input_bytes:bytes.length,candidates:candidates.sort((a,b)=>a.line-b.line||a.column-b.column),source_maps:maps,executed_input:false,network_requests:0,limits:['Literal-only call inventory, not vulnerability detection, symbol resolution, AST data flow or route-registration proof.','No JSX/TypeScript plugins. Unsupported syntax fails rather than claiming clean coverage.','Source-map locator values are hashed, query values redacted; review other output metadata before sharing.']};
 fs.writeFileSync(output,JSON.stringify(result,null,2)+'\n',{flag:'wx'});
 console.log(JSON.stringify({output_created:true,candidates:result.candidates.length,input_executed:false,network_requests:0}));
} catch {console.error('Rejected: check input size/type, parser budget and new output path. No input JavaScript was executed.');process.exit(2);}
