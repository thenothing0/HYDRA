"""Evidence workflow helper. No scanning or target discovery.

collect: issue explicitly listed GET/HEAD requests inside exact origins.
check: validate report consistency and local evidence hashes, not factual truth.
render: produce Markdown only after check passes. Python 3.10+, stdlib only.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request

class Invalid(ValueError): pass

def require(condition, message):
    if not condition: raise Invalid(message)

def read_json(path):
    require(Path(path).stat().st_size <= 2_000_000, 'JSON input exceeds 2 MB')
    return json.loads(Path(path).read_text(encoding='utf-8'))

def text(value): return isinstance(value,str) and bool(value.strip())

def local_file(root, relative):
    require(text(relative), 'evidence path must be nonempty')
    rel=Path(relative)
    require(not rel.is_absolute() and '..' not in rel.parts, 'evidence path must stay within report folder')
    result=(root/rel).resolve()
    require(result.is_relative_to(root.resolve()) and result.is_file(), 'evidence must be an existing file inside report folder')
    return result

def id_map(items,label):
    require(isinstance(items,list),label+' must be a list')
    result={}
    for item in items:
        require(isinstance(item,dict) and re.fullmatch(r'[A-Za-z0-9_-]{1,64}',str(item.get('id',''))) is not None,label+' needs simple non-sensitive object IDs')
        require(item['id'] not in result,'duplicate '+label+' ID')
        result[item['id']]=item
    return result

def validate(report, root):
    require(isinstance(report,dict),'assessment must be an object')
    require(report.get('schema_version')=='1.0','unsupported assessment schema')
    for key in ('run_id','target','authorization','limitations'):
        require(text(report.get(key)), 'missing '+key)
    require(re.fullmatch(r'A(?:0[1-9]|10)',str(report.get('category',''))) is not None,'invalid OWASP category')
    require(report.get('mode') in ('code-review','bug-bounty','mixed'),'invalid mode')
    evidence=id_map(report.get('evidence'),'evidence')
    coverage=id_map(report.get('coverage'),'coverage')
    findings=id_map(report.get('findings'),'finding')
    require(bool(coverage),'assessment requires a coverage ledger')
    for ident,e in evidence.items():
        require(e.get('kind') in ('code-trace','http-metadata','test-output','configuration','other'),'invalid evidence kind')
        require(text(e.get('description')) and text(e.get('collected_at')),'evidence requires description and collection time')
        try: stamp=datetime.fromisoformat(e['collected_at'].replace('Z','+00:00'))
        except ValueError: raise Invalid('evidence collection time must be ISO 8601')
        require(stamp.utcoffset() is not None,'evidence time must include UTC offset')
        require(e.get('redacted') is True,'evidence must be reviewed for sensitive data before delivery')
        actual=hashlib.sha256(local_file(root,e.get('path')).read_bytes()).hexdigest()
        require(e.get('sha256')==actual,'evidence hash mismatch: '+ident)
    def refs(ids, mapping, label, nonempty=False):
        require(isinstance(ids,list),label+' references must be a list')
        require(not nonempty or bool(ids),label+' references cannot be empty')
        require(all(isinstance(i,str) and i in mapping for i in ids),'unknown '+label+' reference')
    for c in coverage.values():
        require(text(c.get('boundary')),'coverage needs a boundary')
        require(c.get('status') in ('tested','not-tested','not-applicable'),'invalid coverage status')
        if c['status']=='tested':
            refs(c.get('evidence_ids'),evidence,'coverage evidence',True)
            require(text(c.get('result')),'tested coverage needs observed result')
        else: require(text(c.get('reason')),'untested/not-applicable coverage requires a reason')
    for f in findings.values():
        require(f.get('status') in ('confirmed','suspected','unverified','patched-unverified','fixed','not-reproduced'),'invalid finding status')
        require(f.get('severity') in ('critical','high','medium','low','informational','undetermined'),'invalid severity')
        require(f.get('category')==report['category'],'finding category must match assessment')
        if f.get('cwe') is not None:
            require(re.fullmatch(r'CWE-[0-9]+',str(f['cwe'])) is not None,'invalid CWE identifier')
        for key in ('title','expected','observed','preconditions','impact','root_cause','remediation','severity_rationale','confidence'):
            require(text(f.get(key)),'finding missing '+key)
        refs(f.get('evidence_ids'),evidence,'finding evidence',f['status'] in ('confirmed','fixed','patched-unverified'))
        refs(f.get('coverage_ids'),coverage,'finding coverage',True)
        if f['status'] in ('confirmed','fixed'):
            require(any(coverage[i]['status']=='tested' for i in f['coverage_ids']),'confirmed/fixed finding needs tested coverage')
            require(text(f.get('reachability')) and text(f.get('false_positive_check')),'confirmed/fixed finding needs reachability and false-positive check')
        if f['status']=='fixed':
            require(text(f.get('fixed_build')),'fixed finding requires tested build')
            tests=f.get('retests')
            require(isinstance(tests,list),'fixed finding needs retests')
            for kind in ('negative','positive','side-effect'):
                matching=[t for t in tests if isinstance(t,dict) and t.get('kind')==kind and t.get('result')=='pass']
                require(bool(matching),'fixed finding lacks passing '+kind+' retest')
                for t in matching:
                    refs(t.get('evidence_ids'),evidence,'retest evidence',True)
                    require(any(evidence[i]['kind'] in ('test-output','http-metadata') for i in t['evidence_ids']),'retest needs recorded execution evidence')
                    require(t.get('tested_build')==f['fixed_build'],'retest build must match fixed build')
                    require(text(t.get('expected')) and text(t.get('observed')),'retest needs expected and observed outcomes')
    return {'findings':len(findings),'evidence':len(evidence),'tested_boundaries':sum(c['status']=='tested' for c in coverage.values()),'uncovered_boundaries':sum(c['status']=='not-tested' for c in coverage.values())}

def canonical_origin(url):
    require(text(url) and not any(ch.isspace() or ord(ch)<32 for ch in url),'invalid URL whitespace')
    try:
        p=urllib.parse.urlsplit(url); port=p.port
    except ValueError: raise Invalid('invalid URL port')
    require(p.scheme in ('http','https') and bool(p.hostname),'only HTTP(S) URLs are supported')
    require(p.username is None and p.password is None and not p.fragment,'URL credentials and fragments are forbidden')
    host=p.hostname.lower()
    require(not host.endswith('.'),'trailing-dot hostnames are not supported')
    try: host=host.encode('idna').decode('ascii')
    except UnicodeError: raise Invalid('invalid hostname')
    if ':' in host: host='['+host+']'
    default=443 if p.scheme=='https' else 80
    return p.scheme+'://'+host+(':'+str(port) if port and port!=default else '')

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None

def plan(manifest,root):
    require(isinstance(manifest,dict),'manifest must be an object')
    require(text(manifest.get('authorization')),'record existing authorization and scope before collection')
    origins=manifest.get('origins'); require(isinstance(origins,list) and bool(origins),'explicit origins required')
    allowed=set()
    for origin in origins:
        p=urllib.parse.urlsplit(origin)
        require(p.path in ('','/') and not p.query,'scope origins cannot include paths/query')
        allowed.add(canonical_origin(origin))
    budget=manifest.get('max_requests',5); interval=manifest.get('min_interval_seconds',1)
    require(type(budget) is int and 1<=budget<=20,'budget must be 1..20')
    require(type(interval) in (float,int) and .2<=interval<=60,'interval must be .2..60 seconds')
    requests=manifest.get('requests'); require(isinstance(requests,list) and 0<len(requests)<=budget,'request list exceeds budget or is empty')
    profiles={}
    if manifest.get('headers_file'):
        profiles=read_json(local_file(root,manifest['headers_file']))
        require(isinstance(profiles,dict),'header profiles must be an object')
    compiled=[]; labels=set()
    allowed_headers={'authorization','cookie','accept','user-agent','origin'}
    for r in requests:
        require(isinstance(r,dict) and re.fullmatch(r'[A-Za-z0-9_-]{1,64}',str(r.get('id',''))) is not None,'request ID must be a simple non-sensitive label')
        require(r['id'] not in labels,'duplicate request ID'); labels.add(r['id'])
        require(r.get('method','GET') in ('GET','HEAD'),'only explicitly listed GET/HEAD are supported')
        require(canonical_origin(r.get('url')) in allowed,'request outside exact origin scope')
        require(not (urllib.parse.urlsplit(r['url']).scheme=='http' and (r.get('profile'))),'credential profiles require HTTPS')
        profile=r.get('profile')
        require(profile is None or profile in profiles,'unknown credential profile')
        headers=profiles.get(profile,{})
        require(isinstance(headers,dict),'header profile must be an object')
        for key,value in headers.items():
            require(isinstance(key,str) and key.lower() in allowed_headers,'unsupported request header')
            require(isinstance(value,str) and '\r' not in value and '\n' not in value,'invalid request header value')
        compiled.append((r,headers))
    return compiled,float(interval)

def collect(manifest, root):
    compiled,interval=plan(manifest,root)
    # Disable ambient proxies; do not forward credentials via machine proxy config.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    records=[]
    for i,(item,headers) in enumerate(compiled):
        if i: time.sleep(interval)
        p=urllib.parse.urlsplit(item['url'])
        record={'id':item['id'],'origin':canonical_origin(item['url']),'path_sha256':hashlib.sha256(p.path.encode()).hexdigest(),'query_field_count':len(urllib.parse.parse_qsl(p.query,keep_blank_values=True)),'method':item.get('method','GET'),'collected_at':datetime.now(timezone.utc).isoformat()}
        req=urllib.request.Request(item['url'],headers=headers,method=record['method'])
        try:
            try: response=opener.open(req,timeout=10)
            except urllib.error.HTTPError as e: response=e
            with response:
                raw=response.read(65537); clipped=len(raw)>65536; raw=raw[:65536]
                record.update(status=response.status,body_sample_sha256=hashlib.sha256(raw).hexdigest(),sample_bytes=len(raw),truncated=clipped,redirect_not_followed=300<=response.status<400)
                record['response_header_names']=sorted(set(k.lower() for k in response.headers.keys()))
                # No header values, body, query values, tokens or redirect destinations are persisted.
        except (urllib.error.URLError,TimeoutError,OSError,http.client.HTTPException):
            record['transport_error']='request failed; details omitted to avoid credential disclosure'
            records.append(record)
            break
        records.append(record)
        if record.get('status') in (429,503): break
    return {'schema_version':'1.0','kind':'http-metadata-only','records':records,'note':'No body or header values retained. A hash is not proof of vulnerability. GET may still have effects; inspect each listed endpoint and use synthetic records. Redirects/retries are disabled; rate-limit/unavailability or transport failure stops collection.'}

def clean(value):
    # Render user-authored fields as inert text in Markdown tables/lines.
    value=str(value).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('\r',' ').replace('\n',' ')
    return re.sub(r'([\\`*_[\]{}()#!~|])',r'\\\1',value)

def render(report,summary):
    lines=['# Security assessment','', 'Run: '+clean(report['run_id']),'','Target: '+clean(report['target']),'','Mode: '+report['mode']+'; category: '+report['category'],'','Scope / existing authorization: '+clean(report['authorization']),'', 'This report passed consistency/hash checks; the checker does not verify factual truth.','', '## Findings','']
    for f in report['findings']:
        lines+=['### '+clean(f['id']+' — '+f['title']),'']
        for key in ('status','cwe','severity','severity_rationale','preconditions','expected','observed','impact','root_cause','remediation','confidence','reachability','false_positive_check','fixed_build'):
            if key in f: lines += ['- '+key.replace('_',' ').capitalize()+': '+clean(f[key])]
        lines+=['- Evidence IDs: '+clean(', '.join(f['evidence_ids'])),'']
        for retest in f.get('retests',[]):
            lines+=['- Retest: '+clean(json.dumps(retest,ensure_ascii=False))]
        if f.get('retests'): lines.append('')
    lines+=['## Coverage','','| Boundary | Status | Result / reason |','|---|---|---|']
    for c in report['coverage']: lines.append('| '+clean(c['boundary'])+' | '+c['status']+' | '+clean(c.get('result',c.get('reason','')))+' |')
    lines+=['','## Evidence','','| ID | File | SHA-256 |','|---|---|---|']
    for e in report['evidence']: lines.append('| '+clean(e['id'])+' | '+clean(e['path'])+' | '+e['sha256']+' |')
    lines+=['','## Limits','',clean(report['limitations']),'']
    return '\n'.join(lines)

def save_new(path,value):
    # Refuse to clobber an existing evidence artifact.
    with Path(path).open('x',encoding='utf-8') as f: f.write(value)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    subs=parser.add_subparsers(dest='command',required=True)
    for name in ('check','render','collect'):
        sub=subs.add_parser(name); sub.add_argument('input',type=Path)
        if name in ('render','collect'): sub.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        obj=read_json(args.input); root=args.input.resolve().parent
        if args.command=='collect':
            require(not args.output.exists(),'output already exists')
            save_new(args.output,json.dumps(collect(obj,root),indent=2)+'\n')
            print('Metadata collected; review coverage and evidence before reporting.')
        else:
            summary=validate(obj,root)
            if args.command=='render': save_new(args.output,render(obj,summary))
            print(json.dumps({'result':'consistent','limits':'not a truth or vulnerability detector',**summary}))
    except Invalid as error:
        parser.exit(2,'Rejected: '+str(error)+'\n')
    except (OSError,ValueError,KeyError,TypeError):
        # Do not print exception contents that could contain input secrets.
        parser.exit(2,'Input rejected or operation failed. Check scope, references, hashes, statuses, paths, and output destination.\n')

if __name__=='__main__': main()
