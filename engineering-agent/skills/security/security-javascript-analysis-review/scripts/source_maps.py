"""Bounded offline source-map content inventory/extraction; no URL/file source resolution."""
import argparse,hashlib,json,os
from pathlib import Path

class Rejected(ValueError): pass
def audit(path):
 p=Path(path)
 if p.is_symlink() or p.stat().st_size>4*1024*1024: raise Rejected('input boundary')
 raw=p.read_bytes()
 try: doc=json.loads(raw)
 except (ValueError,UnicodeError,RecursionError): raise Rejected('invalid JSON')
 records=[]; contents={};budget=0
 def walk(d,depth=0):
  nonlocal budget
  if depth>8 or not isinstance(d,dict) or type(d.get('version')) is not int or d['version']!=3: raise Rejected('unsupported map')
  if 'sections' in d:
   if 'sources' in d or not isinstance(d['sections'],list) or len(d['sections'])>2000: raise Rejected('mixed/index map or section budget')
   for section in d['sections']:
    if not isinstance(section,dict): raise Rejected('invalid section')
    offset=section.get('offset')
    if not isinstance(offset,dict) or any(type(offset.get(k)) is not int or offset[k]<0 for k in ('line','column')): raise Rejected('invalid offset')
    if 'url' in section:
     if 'map' in section or not isinstance(section['url'],str): raise Rejected('invalid external section')
     if len(records)>=2000: raise Rejected('section budget')
     records.append({'kind':'external-section','url_sha256':hashlib.sha256(section['url'].encode()).hexdigest(),'fetched':False})
    elif 'map' in section: walk(section['map'],depth+1)
    else: raise Rejected('missing section map')
   return
  sources=d.get('sources'); data=d.get('sourcesContent')
  if not isinstance(sources,list) or any(not isinstance(x,str) for x in sources): raise Rejected('invalid sources')
  if len(sources)>2000 or len(records)+len(sources)>2000: raise Rejected('source budget')
  if data is not None and (not isinstance(data,list) or len(data)!=len(sources) or any(x is not None and not isinstance(x,str) for x in data)): raise Rejected('content alignment')
  for i,name in enumerate(sources):
   content=None if data is None else data[i]
   ident=f'source-{len(records):05d}'
   row={'id':ident,'source_label_sha256':hashlib.sha256(name.encode()).hexdigest(),'embedded':content is not None,'source_label_used_as_path':False}
   if content is not None:
    encoded=content.encode('utf-8');budget+=len(encoded)
    if budget>8*1024*1024: raise Rejected('embedded byte budget')
    row.update(sha256=hashlib.sha256(encoded).hexdigest(),bytes=len(encoded));contents[ident+'.txt']=encoded
   records.append(row)
 walk(doc)
 return {'schema_version':'1.0','input_sha256':hashlib.sha256(raw).hexdigest(),'records':records,'network_requests':0,'executed_content':False,'limits':'Embedded-content inventory only. Mapping VLQ positions, sourceRoot/file URL resolution, compiler source fidelity and secret classification are not validated. External section URLs are never followed.'},contents

def export(path,out):
 result,contents=audit(path); out=Path(out)
 if out.exists() or out.is_symlink(): raise Rejected('output exists')
 # All parsing/budget checks finish before any output is created. Opaque filenames only.
 out.mkdir()
 for name,raw in contents.items():
  with (out/name).open('xb') as f:f.write(raw)
 with (out/'inventory.json').open('x',encoding='utf-8') as f:json.dump(result,f,indent=2);f.write('\n')
 return result

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('input',type=Path);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
 try:
  result=export(args.input,args.output)
  print(json.dumps({'created':True,'sources':len(result['records']),'network_requests':0,'input_executed':False}))
 except (Rejected,OSError,ValueError,RecursionError,UnicodeError):parser.exit(2,'Rejected: invalid/oversized map, unsafe input or output exists. No URLs are fetched or source labels used as paths.\n')
if __name__=='__main__':main()
