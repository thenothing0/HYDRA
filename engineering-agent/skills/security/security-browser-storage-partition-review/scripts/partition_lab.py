"""Observe storage in owned loopback contexts; no external target argument exists."""
import argparse
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import sys
import threading


def launch_with_checked_privacy(pw, args, no_sandbox):
    """Remove automation defaults that disable storage isolation, then inspect again."""
    browser = pw.chromium.launch(headless=True, chromium_sandbox=not no_sandbox, args=args)
    try:
        session = browser.new_browser_cdp_session()
        initial = session.send('Browser.getBrowserCommandLine')['arguments']
        session.detach()
        ignored = []
        replacement = []
        removed = []
        for argument in initial:
            if argument.startswith('--disable-features='):
                features = argument.split('=', 1)[1].split(',')
                privacy = [f for f in features if 'storagepartition' in f.lower() or 'cookiecontrol' in f.lower() or 'partitionedcookie' in f.lower()]
                if privacy:
                    ignored.append(argument)
                    removed.extend(privacy)
                    rest = [f for f in features if f not in privacy]
                    if rest:
                        replacement.append('--disable-features=' + ','.join(rest))
        if ignored:
            browser.close()
            browser = pw.chromium.launch(headless=True, chromium_sandbox=not no_sandbox, ignore_default_args=ignored, args=args + replacement)
        session = browser.new_browser_cdp_session()
        effective = session.send('Browser.getBrowserCommandLine')['arguments']
        session.detach()
        disabled = [f for a in effective if a.startswith('--disable-features=') for f in a.split('=',1)[1].split(',')]
        if any('storagepartition' in f.lower() or 'cookiecontrol' in f.lower() or 'partitionedcookie' in f.lower() for f in disabled):
            raise RuntimeError('Browser still has a storage-privacy disabling argument; experiment aborted')
        if '--disable-web-security' in effective:
            raise RuntimeError('Unexpected disabled origin security; experiment aborted')
        return browser, {'automation_privacy_overrides_removed': removed, 'effective_disabled_features': disabled, 'effective_argument_check': 'passed'}
    except Exception:
        browser.close()
        raise


def run_lab(no_sandbox=False):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError('Playwright is unavailable; no package installation was attempted') from exc
    marker = 'OWNED_PARTITION_FIXTURE_' + secrets.token_hex(12)
    key = 'owned_partition_probe'

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            host = self.headers.get('Host', '').split(':')[0]
            if host not in ('a.skill-site-a.test', 'b.skill-site-b.test'):
                self.send_error(403)
                return
            if self.path == '/a/write':
                body = '<!doctype html><title>Owned A writer</title><script>localStorage.setItem(' + json.dumps(key) + ',' + json.dumps(marker) + ');</script>'
            elif self.path == '/a/read':
                body = '''<!doctype html><title>Owned A reader</title><script>
let observation;
try {const value=localStorage.getItem(KEY);observation={state:value===null?'empty':'present',matches:value===MARKER};}
catch(e){observation={state:'blocked',error:e.name};}
parent.postMessage({kind:'owned-partition-result',observation}, B_ORIGIN);
</script>'''.replace('KEY', json.dumps(key)).replace('MARKER', json.dumps(marker)).replace('B_ORIGIN', json.dumps(b_origin))
            elif self.path == '/b':
                body = '''<!doctype html><title>Owned B embedder</title><iframe id="embed"></iframe><script>
window.ownedResult=null;
const f=document.getElementById('embed');
addEventListener('message', e=>{
 if(e.origin===A_ORIGIN && e.source===f.contentWindow && e.data?.kind==='owned-partition-result') window.ownedResult=e.data.observation;
});
f.src=A_ORIGIN+'/a/read';
</script>'''.replace('A_ORIGIN', json.dumps(a_origin))
            elif self.path == '/a/control':
                body = '<!doctype html><title>Owned A control</title>'
            else:
                self.send_error(404)
                return
            raw = body.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    port = server.server_address[1]
    a_origin = f'http://a.skill-site-a.test:{port}'
    b_origin = f'http://b.skill-site-b.test:{port}'
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    result = {'fixture': 'owned reserved .test sites served only on loopback', 'started_utc': datetime.now(timezone.utc).isoformat(), 'a_origin': a_origin, 'b_origin': b_origin, 'storage_api': 'localStorage', 'marker_sha256': hashlib.sha256(marker.encode()).hexdigest()}
    try:
        with sync_playwright() as pw:
            browser_args = ['--enable-automation', '--host-resolver-rules=MAP a.skill-site-a.test 127.0.0.1, MAP b.skill-site-b.test 127.0.0.1', '--no-proxy-server']
            if no_sandbox:
                browser_args.append('--no-sandbox')
            browser, privacy_setup = launch_with_checked_privacy(pw, browser_args, no_sandbox)
            try:
                result['browser_version'] = browser.version
                result['process_sandbox_disabled'] = no_sandbox
                result['privacy_setup'] = privacy_setup
                context = browser.new_context()
                page = context.new_page()
                page.goto(a_origin + '/a/write', wait_until='load', timeout=10000)
                result['top_level_before'] = page.evaluate('(args)=>localStorage.getItem(args.key)===args.marker', {'key': key, 'marker': marker})
                page.goto(b_origin + '/b', wait_until='load', timeout=10000)
                page.wait_for_function('window.ownedResult !== null', timeout=10000)
                result['embedded_under_b'] = page.evaluate('window.ownedResult')
                page.goto(a_origin + '/a/control', wait_until='load', timeout=10000)
                result['top_level_after'] = page.evaluate('(args)=>localStorage.getItem(args.key)===args.marker', {'key': key, 'marker': marker})
                if not result['top_level_before'] or not result['top_level_after']:
                    result['decision'] = 'inconclusive: top-level positive control failed'
                elif result['embedded_under_b']['state'] == 'blocked':
                    result['decision'] = 'embedded storage blocked in this fixture'
                elif result['embedded_under_b'].get('matches'):
                    result['decision'] = 'marker visible across these fixture contexts'
                else:
                    result['decision'] = 'marker isolated across these fixture contexts'
                context.close()
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    result['limitations'] = 'A synthetic HTTP fixture on two distinct reserved .test sites, not a universal browser guarantee, HTTPS comparison, real-session proof or target assessment. Browser DNS overrides map only these fixture names to loopback and bypass proxies; no origin or storage-privacy controls were disabled. If selected, --no-sandbox disables the process sandbox only for this owned fixture.'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--no-sandbox', action='store_true', help='Only for hosts that cannot run the Chromium process sandbox; does not disable origin or storage controls')
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output already exists; choose a new path')
    try:
        result = run_lab(args.no_sandbox)
        with args.output.open('x', encoding='utf-8') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')
        print(json.dumps(result, indent=2))
    except Exception as exc:
        print('Uncompleted local fixture: ' + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
