// Isolated Chromium integration test; no user profile or external site is used.
import {mkdtemp, cp, readFile, writeFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {spawn} from 'node:child_process';
import http from 'node:http';
import assert from 'node:assert/strict';
const [modulePath, executablePath, python] = process.argv.slice(2);
if (!python) throw new Error('Usage: node tools/test_browser_extension.mjs PLAYWRIGHT_MODULE CHROMIUM_EXE PYTHON_EXE');
const imported = await import(pathToFileURL(modulePath));
const {chromium} = imported.default || imported;
const root = await mkdtemp(path.join(tmpdir(), 'hydra-browser-e2e-'));
const server = http.createServer((req,res) => {
  res.setHeader('X-Frame-Options','DENY');
  res.end(req.url.startsWith('/ping') ? 'pong' : `<h1>Local fixture</h1><input id="marker"><input type="password" value="private-fixture-password"><button id="apply">Apply</button><p id="result"></p><script>document.querySelector('#apply').onclick=()=>{document.querySelector('#result').textContent=document.querySelector('#marker').value;fetch('/ping?token=private-query')}</script>`);
});
let backend, context;
const wait = async fn => { for(let i=0;i<100;i++){try{const value=await fn();if(value)return value;}catch{} await new Promise(r=>setTimeout(r,100));}throw new Error('Timed out'); };
try {
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const origin=`http://127.0.0.1:${server.address().port}`;
  const extension=path.join(root,'extension');
  await cp(path.resolve('extensions/hydra-browser'),extension,{recursive:true});
  const manifest=JSON.parse(await readFile(path.join(extension,'manifest.json'),'utf8'));
  // Only the fixture host permission is pregranted; production asks the user.
  manifest.host_permissions.push(origin+'/*');
  await writeFile(path.join(extension,'manifest.json'),JSON.stringify(manifest));
  backend=spawn(python,['-m','hydra','browser','start','--workspace',root,'--allow-origin',origin,'--port','0','--allow-actions'],{stdio:'ignore',windowsHide:true});
  const config=await wait(async()=>JSON.parse(await readFile(path.join(root,'.hydra/browser/connection.json'),'utf8')));
  context=await chromium.launchPersistentContext(path.join(root,'profile'),{headless:true,executablePath,args:[`--disable-extensions-except=${extension}`,`--load-extension=${extension}`]});
  const worker=context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  const id=new URL(worker.url()).host;
  const target=await context.newPage(); await target.goto(origin);
  const tabId=await worker.evaluate(async url=>(await chrome.tabs.query({})).find(t=>t.url===url+'/').id,origin);
  const popup=await context.newPage(); await popup.goto(`chrome-extension://${id}/popup.html`);
  await popup.locator('#bridge').fill(config.url); await popup.locator('#token').fill(config.token); await popup.locator('#connect').click();
  await wait(()=>worker.evaluate(async()=>(await chrome.storage.session.get('connectionStatus')).connectionStatus==='paired'));
  const paired=await popup.evaluate(tab_id=>chrome.runtime.sendMessage({type:'pair_tab',tab_id}),tabId); assert.equal(paired.ok,true);
  const command=async(action,args={})=>{const response=await fetch(config.url+'/command',{method:'POST',headers:{Authorization:'Bearer '+config.token,'Content-Type':'application/json'},body:JSON.stringify({action,arguments:args})});const result=await response.json();if(!response.ok)throw new Error(JSON.stringify(result));return result;};
  assert.equal((await command('tabs')).result.tabs.length,1);
  const initial=await command('snapshot',{tab_id:tabId});assert.ok(!JSON.stringify(initial).includes('private-fixture-password'));
  await command('network_start',{tab_id:tabId});
  await command('fill',{tab_id:tabId,selector:'#marker',value:'HYDRA verified'});
  await command('click',{tab_id:tabId,selector:'#apply'});
  await target.waitForFunction(()=>document.querySelector('#result').textContent==='HYDRA verified');
  const after=await command('snapshot',{tab_id:tabId});assert.ok(JSON.stringify(after).includes('HYDRA verified'));
  const network=await wait(async()=>{const r=await command('network_events',{tab_id:tabId});return r.result.events.some(e=>e.url.endsWith('/ping'))&&r;});
  assert.ok(!JSON.stringify(network).includes('private-query'));
  await assert.rejects(command('navigate',{tab_id:tabId,url:'https://example.com/'}));
  const result={passed:true,checks:['real extension pairing','paired tabs','DOM snapshot','password omission','fill and click','passive network metadata','query omission','out-of-scope navigation refusal'],limitations:['Fixture host permission pregranted in isolated test profile','Screenshot and interactive permission prompt require manual browser verification']};
  await writeFile(path.resolve('output/browser-e2e.json'),JSON.stringify(result,null,2));
  console.log(JSON.stringify(result));
} finally {
  if(context)await context.close();
  if(backend){backend.kill();await new Promise(r=>backend.exitCode!==null?r():backend.once('exit',r));}
  await new Promise(r=>server.close(r));
  if(path.dirname(root)===tmpdir() && path.basename(root).startsWith('hydra-browser-e2e-'))await rm(root,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
