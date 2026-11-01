"""Owned loopback HTTP fixtures. Edge/handler decisions are modeled in one process."""
import contextlib,http.client,http.server,json,posixpath,sys,threading,unittest,urllib.parse
from pathlib import Path

OBSERVATIONS=[]
@contextlib.contextmanager
def application(mode):
 state={'credits':0}
 class Handler(http.server.BaseHTTPRequestHandler):
  def log_message(self,*args):pass
  def do_POST(self):self.handle_request()
  def do_GET(self):self.handle_request()
  def handle_request(self):
   raw=urllib.parse.urlsplit(self.path).path
   canonical=posixpath.normpath(urllib.parse.unquote(raw))
   actor=self.headers.get('X-Lab-Actor','user')
   role=actor if mode!='header-trust-bug' else self.headers.get('X-Internal-Role',actor)
   protected=canonical.startswith('/admin/')
   edge_protected=raw.startswith('/admin/') if mode=='normalization-bug' else protected
   before=state['credits'];status=200
   if canonical=='/soft-deny':body={'error':'denied'}
   elif edge_protected and role!='admin':status=403;body={'error':'denied'}
   elif protected:
    if mode=='fixed' and actor!='admin':status=403;body={'error':'denied'}
    elif canonical=='/admin/credit' and self.command=='POST':
     state['credits']+=1;body={'credit_committed':True}
    else:body={'protected_fixture':'private-canary'}
   else:body={'public':'welcome'}
   encoded=json.dumps(body).encode()
   OBSERVATIONS.append(dict(mode=mode,actor=actor,raw_path=raw,canonical=canonical,status=status,body=body,credits_before=before,credits_after=state['credits']))
   self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(encoded)));self.end_headers();self.wfile.write(encoded)
 server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
 worker=threading.Thread(target=lambda:server.serve_forever(poll_interval=.01),daemon=True);worker.start()
 def request(path,actor='user',method='GET',extra=None):
  c=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=2)
  try:
   c.request(method,path,headers={'X-Lab-Actor':actor,**(extra or {})});r=c.getresponse()
   return r.status,json.loads(r.read(16384))
  finally:c.close()
 try:yield request,state
 finally:server.shutdown();server.server_close();worker.join(timeout=2)

class BoundaryTests(unittest.TestCase):
 def test_denied_baseline_has_no_commit(self):
  with application('normalization-bug') as (req,state):
   self.assertEqual(req('/admin/credit',method='POST')[0],403);self.assertEqual(state['credits'],0)
 def test_normalization_bug_commits_for_same_denied_actor(self):
  with application('normalization-bug') as (req,state):
   self.assertEqual(req('/admin/credit',method='POST')[0],403)
   self.assertTrue(req('/public/../admin/credit',method='POST')[1]['credit_committed']);self.assertEqual(state['credits'],1)
 def test_fixed_normalization_denies_before_commit(self):
  with application('fixed') as (req,state):
   self.assertEqual(req('/public/../admin/credit',method='POST')[0],403);self.assertEqual(state['credits'],0)
 def test_header_trust_bug_grants_protected_data(self):
  with application('header-trust-bug') as (req,state):
   self.assertEqual(req('/admin/report')[0],403)
   self.assertEqual(req('/admin/report',extra={'X-Internal-Role':'admin'})[1]['protected_fixture'],'private-canary')
 def test_fixed_ignores_untrusted_internal_role(self):
  with application('fixed') as (req,state):
   self.assertEqual(req('/admin/credit',method='POST',extra={'X-Internal-Role':'admin'})[0],403);self.assertEqual(state['credits'],0)
 def test_entitled_actor_keeps_required_function(self):
  with application('fixed') as (req,state):
   self.assertTrue(req('/admin/credit',actor='admin',method='POST')[1]['credit_committed']);self.assertEqual(state['credits'],1)
 def test_success_status_soft_denial_is_not_protected_data(self):
  with application('fixed') as (req,state):
   status,body=req('/soft-deny');self.assertEqual(status,200);self.assertNotIn('protected_fixture',body);self.assertEqual(state['credits'],0)
 def test_public_success_is_not_admin_bypass(self):
  with application('fixed') as (req,state):
   status,body=req('/public');self.assertEqual(status,200);self.assertEqual(body,{'public':'welcome'});self.assertEqual(state['credits'],0)

if __name__=='__main__':
 record=None
 if '--record' in sys.argv:
  i=sys.argv.index('--record');record=Path(sys.argv[i+1]);del sys.argv[i:i+2]
  if record.exists():raise SystemExit('Record exists; refusing overwrite')
 program=unittest.main(verbosity=2,exit=False)
 if record:
  with record.open('x',encoding='utf-8') as f:json.dump({'kind':'local-synthetic-http-observations','edge_model':'same-process decision model; not a real nginx/Envoy deployment','remote_targets':False,'observations':OBSERVATIONS},f,indent=2);f.write('\n')
 raise SystemExit(0 if program.result.wasSuccessful() else 1)
