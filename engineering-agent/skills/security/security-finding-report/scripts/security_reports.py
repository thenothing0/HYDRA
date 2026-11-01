"""Offline per-finding reporting and disclosure handoff. No network or submission.
Python 3.10+, stdlib. Validation checks assertions/bytes, not truth or authority.
"""
import argparse
from datetime import datetime,timezone,timedelta
import hashlib,json,os
from pathlib import Path
import re,shutil,tempfile
from urllib.parse import urlsplit

PLATFORMS={'hackerone':'hackerone.com','bugcrowd':'bugcrowd.com','intigriti':'intigriti.com','yeswehack':'yeswehack.com','vendor':None}
REQUIRED=('title','asset','vulnerability','summary','preconditions','expected','observed','impact','root_cause','remediation','severity_rationale','confidence')
class Invalid(ValueError): pass
def need(ok,message):
    if not ok: raise Invalid(message)
def text(x): return isinstance(x,str) and bool(x.strip())
def stamp(s):
    try: result=datetime.fromisoformat(s.replace('Z','+00:00'))
    except (ValueError,AttributeError): raise Invalid('invalid timestamp')
    need(result.utcoffset() is not None,'timestamp needs UTC offset'); return result
def https(url):
    need(text(url) and not any(ch.isspace() or ord(ch)<32 for ch in url),'invalid source/submission URL characters')
    try: p=urlsplit(url)
    except ValueError: raise Invalid('invalid URL')
    need(p.scheme=='https' and p.hostname and p.username is None and p.password is None,'source/submission URLs require HTTPS without credentials')
    return p
def artifact(root,e):
    need(isinstance(e,dict) and text(e.get('path')) and e.get('redacted') is True,'evidence must be explicitly reviewed/redacted')
    rel=Path(e['path']); p=(root/rel).resolve()
    need(not rel.is_absolute() and '..' not in rel.parts and p.is_relative_to(root.resolve()) and p.is_file(),'evidence must be an existing file within input folder')
    need(hashlib.sha256(p.read_bytes()).hexdigest()==e.get('sha256'),'evidence hash mismatch')
    return p
def safe_id(value):
    need(isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',value) is not None,'use opaque safe IDs')
    need(value.upper() not in {'CON','PRN','AUX','NUL',*[f'COM{i}' for i in range(1,10)],*[f'LPT{i}' for i in range(1,10)]},'reserved output ID')
    return value

def route_assessment(f,root,now=None):
    now=now or datetime.now(timezone.utc); route=f.get('route') or {}
    need(isinstance(route,dict),'route must be an object')
    platform=route.get('platform',f.get('draft_platform','vendor'))
    need(platform in PLATFORMS,'unsupported platform; use vendor for a documented direct channel')
    reasons=[]
    if route.get('status')!='verified': reasons.append('disclosure route is not verified')
    if route.get('asset')!=f['asset']: reasons.append('route is not bound to this exact affected asset')
    if route.get('program_status')!='active': reasons.append('program is not documented active')
    for key in ('ownership_verified','asset_in_scope','vulnerability_in_scope','access_verified'):
        if route.get(key) is not True: reasons.append(key+' is not established')
    if not text(route.get('scope_rationale')): reasons.append('asset/type scope rationale missing')
    checked=route.get('checked_at')
    if checked:
        dt=stamp(checked)
        if dt>now+timedelta(minutes=5) or now-dt>timedelta(days=7): reasons.append('route policy check is stale or future-dated')
    else: reasons.append('route policy check time missing')
    url=route.get('submission_url')
    if url:
        if platform=='vendor' and url.startswith('mailto:'):
            p=urlsplit(url)
            need('@' in p.path and not p.query and not p.fragment and not any(ch.isspace() for ch in url),'invalid published contact URI')
        else:
            p=https(url); host=p.hostname.lower(); expected=PLATFORMS[platform]
            if expected and not (host==expected or host.endswith('.'+expected)): reasons.append('submission host does not match selected platform')
    else: reasons.append('published submission channel missing')
    sources=route.get('sources',[]); need(isinstance(sources,list),'route sources must be an array')
    roles=set(); files=[]
    for s in sources:
        need(isinstance(s,dict),'invalid route source'); https(s.get('url','')); checked_source=stamp(s.get('checked_at',''))
        if checked_source>now+timedelta(minutes=5) or now-checked_source>timedelta(days=7): reasons.append('supporting policy source is stale or future-dated')
        roles.add(s.get('role')); files.append(artifact(root,s))
    if 'owner-policy' not in roles: reasons.append('official owner-channel evidence missing')
    if platform!='vendor' and 'program-policy' not in roles: reasons.append('current program-policy evidence missing')
    required=route.get('required_custom_fields',[]); need(isinstance(required,list) and all(text(k) for k in required),'invalid custom-field list')
    fields=f.get('program_fields',{}); need(isinstance(fields,dict),'program_fields must be an object')
    for key in required:
        if not text(fields.get(key)): reasons.append('required custom field missing: '+key)
    return {'platform':platform,'status':'documented' if not reasons else 'unresolved','blockers':reasons,'route':route,'source_files':files}

def validate(data,root,now=None):
    need(isinstance(data,dict) and data.get('schema_version')=='1.0','unsupported report schema')
    findings=data.get('findings'); need(isinstance(findings,list),'findings must be an array')
    ids=set(); result=[]
    for f in findings:
        need(isinstance(f,dict),'finding must be an object'); ident=safe_id(f.get('id'))
        need(ident not in ids,'duplicate finding ID'); ids.add(ident)
        need(all(text(f.get(k)) for k in REQUIRED),'finding missing required narrative fields')
        need(f.get('content_reviewed') is True,'review report text for sensitive data before creating distributable bundle')
        need(f.get('status') in ('confirmed','suspected','unverified','patched-unverified','fixed','not-reproduced'),'invalid finding status')
        need(f.get('severity') in ('critical','high','medium','low','informational','undetermined'),'invalid severity')
        steps=f.get('steps',[]); need(isinstance(steps,list) and all(text(s) for s in steps),'steps must be text array')
        requests=f.get('requests',[]); need(isinstance(requests,list) and all(isinstance(s,str) for s in requests),'requests must be an array of redacted text')
        evidence=f.get('evidence',[]); need(isinstance(evidence,list),'evidence must be an array')
        eids=set(); files=[]
        for e in evidence:
            eid=safe_id(e.get('id')); need(eid not in eids,'duplicate evidence ID in finding'); eids.add(eid); files.append(artifact(root,e))
        route=route_assessment(f,root,now)
        blockers=list(route['blockers'])
        if f['status'] not in ('confirmed','fixed'): blockers.append('finding validity remains unresolved')
        if not evidence: blockers.append('no saved supporting evidence')
        if len(steps)<2: blockers.append('reproduction steps incomplete')
        if f['severity']=='undetermined': blockers.append('severity rationale needs a resolved selection for the receiving form')
        if not text(f.get('limitations')): blockers.append('tested limits/coverage statement missing')
        result.append({'finding':f,'route':route,'files':files,'blockers':blockers})
    return result

def plain(x):
    value=str(x).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('\r',' ').replace('\n',' ')
    return re.sub(r'([\\`*_[\]{}()#!~|])',r'\\\1',value)
def fence(value):
    longest=max([len(x) for x in re.findall(r'`+',value)]+[2]); marker='`'*(longest+1)
    return marker+'text\n'+value+'\n'+marker
def section(title,value): return ['## '+title,'',plain(value),'']

def render(f,platform,blockers,route):
    lines=['# '+plain(f['title']),'', 'Draft ID: '+f['id'],'', 'Handoff state: '+('needs-review' if blockers else 'complete-fields-route-documented')+'; **not submitted**.','']
    if blockers: lines+=['Open items:']+['- '+plain(x) for x in blockers]+['']
    if platform=='bugcrowd': labels=('Overview','Walkthrough and POC','Vulnerability Evidence','Demonstrated Impact')
    elif platform=='intigriti': labels=('Vulnerability details','Reproduction steps','Supporting evidence','Impact')
    elif platform=='yeswehack': labels=('Description','Reproduction','Proof of concept and evidence','Security impact')
    else: labels=('Summary','Steps to reproduce','Supporting evidence','Impact')
    lines+=section('Affected asset / endpoint',f['asset'])
    lines+=section('Vulnerability and severity',f['vulnerability']+'; '+f['severity']+' — '+f['severity_rationale'])
    lines+=section(labels[0],f['summary'])+section('Preconditions',f['preconditions'])
    lines+=['## '+labels[1],'']
    lines += [f'{i}. '+plain(step) for i,step in enumerate(f.get('steps',[]),1)] or ['Not supplied.']
    lines+=['']
    for request in f.get('requests',[]): lines+=[fence(request),'']
    lines+=section('Expected result',f['expected'])+section('Observed result',f['observed'])
    lines+=section(labels[3],f['impact'])+section('Root cause',f['root_cause'])+section('Recommended remediation',f['remediation'])
    lines+=['## '+labels[2],'']
    for e in f.get('evidence',[]):
        lines+=['- '+e['id']+': '+plain(e.get('description','reviewed evidence'))+'; saved attachment '+plain(e['bundle_file'])+'; SHA-256 '+e['sha256']]
    lines+=['']+section('Confidence and testing limits',f['confidence']+' — '+f.get('limitations','Not supplied.'))
    lines+=['## Disclosure destination','']
    if route.get('submission_url'): lines+=['Published channel: '+route['submission_url'],'']
    lines+=['Platform profile: '+platform+'. Recheck the live program template, language, scope and required fields before any submission.','']
    for source in route.get('sources',[]): lines+=['- '+source['url']+' (checked '+plain(source['checked_at'])+')']
    if f.get('related_findings'): lines+=['','Related issue IDs (not merged): '+plain(', '.join(f['related_findings']))]
    return '\n'.join(lines)+'\n'

def fields(f,platform,route,blockers):
    base={'title':f['title'],'asset':f['asset'],'vulnerability':f['vulnerability'],'severity':f['severity'],'severity_rationale':f['severity_rationale'],'program_custom_fields':f.get('program_fields',{})}
    if platform=='hackerone': base.update(asset_type=f.get('asset_type','verify in live form'),weakness=f.get('cwe',f['vulnerability']),proof_of_concept='report.md',impact=f['impact'])
    elif platform=='bugcrowd': base.update(target=f['asset'],vrt_classification=f.get('vrt','unmapped; select evidence-supported current VRT'),description='report.md')
    elif platform=='intigriti': base.update(endpoint=f['asset'],vulnerability_type=f['vulnerability'],details='report.md',impact=f['impact'],recommended_solution=f['remediation'])
    elif platform=='yeswehack': base.update(bug_details=f['vulnerability'],description='report.md',cvss=f.get('cvss','not calculated; review live severity inputs'))
    return {'profile':platform,'kind':'human-handoff-fields-not-an-API-payload','not_submitted':True,'submission_url':route.get('submission_url'),'blockers':blockers,'fields':base}

def bundle(data,root,output,now=None):
    records=validate(data,root,now); output=output.resolve(); need(not output.exists(),'output directory already exists')
    output.parent.mkdir(parents=True,exist_ok=True)
    stage=Path(tempfile.mkdtemp(prefix='.report-stage-',dir=str(output.parent)))
    index=[]; root_ids={}
    try:
        for record in records:
            f=json.loads(json.dumps(record['finding'])); ident=f['id']; folder=stage/ident; folder.mkdir()
            (folder/'attachments').mkdir(); (folder/'routing-evidence').mkdir()
            for e,path in zip(f.get('evidence',[]),record['files']):
                filename=e['id']+path.suffix.lower(); destination=folder/'attachments'/filename
                shutil.copyfile(path,destination); e['bundle_file']='attachments/'+filename
            route=json.loads(json.dumps(record['route']['route']))
            for i,(source,path) in enumerate(zip(route.get('sources',[]),record['route']['source_files']),1):
                filename='source-'+str(i)+'.txt'; shutil.copyfile(path,folder/'routing-evidence'/filename); source['path']='routing-evidence/'+filename
            platform=record['route']['platform']
            (folder/'report.md').write_text(render(f,platform,record['blockers'],route),encoding='utf-8')
            (folder/'submission-fields.json').write_text(json.dumps(fields(f,platform,route,record['blockers']),indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
            (folder/'route.json').write_text(json.dumps({'assessment':record['route']['status'],'route':route,'not_submitted':True,'limits':'Source assertions and scope judgment need human/agent review; hashes do not establish authority.'},indent=2)+'\n',encoding='utf-8')
            rootid=f.get('root_cause_id'); related=root_ids.setdefault(rootid,[]) if text(rootid) else []
            related.append(ident)
            index.append({'id':ident,'report':ident+'/report.md','platform':platform,'handoff':'needs-review' if record['blockers'] else 'complete-fields-route-documented','blockers':record['blockers'],'not_submitted':True})
        (stage/'index.json').write_text(json.dumps({'schema_version':'1.0','findings':index,'potential_shared_root_causes':{k:v for k,v in root_ids.items() if len(v)>1},'limits':'One folder per input finding. Shared causes are flagged, never silently merged or submitted.'},indent=2)+'\n',encoding='utf-8')
        os.replace(stage,output)
        return {'reports':len(index),'output':str(output),'submitted':0}
    finally:
        if stage.exists():
            need(stage.resolve().parent==output.parent and stage.name.startswith('.report-stage-'),'unexpected cleanup location')
            shutil.rmtree(stage)

def inspect_securitytxt(value,now=None):
    now=now or datetime.now(timezone.utc); fields={}
    for line in value.splitlines():
        line=line.strip()
        if not line or line.startswith(('#','-----')) or ':' not in line: continue
        key,item=line.split(':',1)
        if key.lower() in ('contact','expires','policy','canonical','preferred-languages','encryption'):
            fields.setdefault(key.lower(),[]).append(item.strip())
    status='candidate-only'
    try:
        if len(fields.get('expires',[]))!=1 or not fields.get('contact'): status='invalid-or-incomplete'
        elif stamp(fields['expires'][0])<=now: status='expired'
    except Invalid: status='invalid-or-incomplete'
    return {'status':status,'fields':fields,'routing_verified':False,'authorization_granted':False,'note':'Local pointer extraction only; origin, signature, canonical location, ownership, policy and contact must be verified separately. Expired pointers are not current route evidence.'}

def main():
    p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest='command',required=True)
    for name in ('check','bundle','securitytxt'):
        a=sub.add_parser(name); a.add_argument('input',type=Path)
        if name!='check': a.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    try:
        if args.command=='securitytxt':
            need(not args.output.exists(),'output exists')
            result=inspect_securitytxt(args.input.read_text(encoding='utf-8'))
            with args.output.open('x',encoding='utf-8') as f: f.write(json.dumps(result,indent=2)+'\n')
            result={'parsed':True,'routing_verified':False,'submitted':0}
        else:
            data=json.loads(args.input.read_text(encoding='utf-8')); root=args.input.resolve().parent
            result=bundle(data,root,args.output) if args.command=='bundle' else {'findings':len(validate(data,root)),'truth_verified':False,'submitted':0}
        print(json.dumps(result))
    except Invalid as error: p.exit(2,'Rejected: '+str(error)+'\n')
    except (OSError,ValueError,KeyError,TypeError): p.exit(2,'Rejected: invalid input, evidence or destination; no reports submitted.\n')
if __name__=='__main__': main()
