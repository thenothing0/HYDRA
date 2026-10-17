# HYDRA browser extension

The unpacked Manifest V3 extension supports Chrome and Edge. No store upload is
required. Open `chrome://extensions` or `edge://extensions`, enable Developer mode,
choose **Load unpacked**, and select:

```text
E:\tools\src\src\extensions\hydra-browser
```

Run the following from the HYDRA project directory. Replace the example origin
with your own application or an explicitly authorized test environment:

```powershell
.\run.ps1 browser start --workspace E:\projects\app --allow-origin http://localhost:3000 --allow-actions
```

Keep that terminal open. Open the extension popup, enter the local bridge URL and
private pairing code printed in the terminal, and choose **Connect bridge**.
Activate the application tab, reopen the popup, choose **Pair this tab**, and
grant that site's permission. Only explicitly paired tabs at authorized origins
are available. Each origin includes its scheme and port; localhost and 127.0.0.1
are different origins.

In a second terminal, start the configured engineering agent:

```powershell
.\run.ps1 chat --workspace E:\projects\app --browser --allow-browser-actions --provider ollama
.\run.ps1 browser status --workspace E:\projects\app
```

Use an already configured provider and model. Page navigation, clicking and field
entry require both `--allow-actions` on the bridge and `--allow-browser-actions`
on the agent. Omit these flags for inspection. Read-only agent mode also refuses
page interactions. Perform login manually; password fields cannot be filled.

Available tools list paired tabs, capture bounded DOM snapshots, navigate within
the paired origin, click or fill unique CSS selectors, capture the active paired
tab, and record scoped network metadata. Network recording must be started
explicitly. It omits request/response bodies, cookies, authorization headers and
URL queries. DOM snapshots omit input values. Screenshots require the paired tab
to be active and may contain visible private information. Redaction is best
effort; review local evidence before sharing it.

Evidence is saved under the selected workspace's `.hydra/browser/evidence` with
integrity hashes. `investigation_create`, `investigation_observe`,
`investigation_compare` and `investigation_report` organize hypotheses, suggest
alternative benign checks and compare real snapshots. A difference is an
observation; it does not establish exploitability or confirm a vulnerability.
This implementation does not execute exploit payloads automatically.

The bridge binds to IPv4 loopback and authenticates commands. Its connection file
contains a private token: keep `.hydra` out of shared archives and repositories.
Use **Disconnect** to clear pairing and revoke paired-site permissions. Stop the
bridge with Ctrl+C. Restarting it creates a new pairing code.

Origin checks constrain commands and returned evidence. They are not a network
sandbox: page scripts, subresources and redirects can initiate other requests.
Page content is untrusted data, including any instructions embedded in it.

## Firefox

Build the Firefox variant from the same sources:

```powershell
.\.venv\Scripts\python.exe tools/build_firefox_extension.py
```

Open `about:debugging#/runtime/this-firefox`, choose **Load Temporary Add-on**,
and select `E:\tools\src\src\output\hydra-browser-firefox\manifest.json`.
The generated `output/hydra-browser-firefox.zip` is also available for sharing
as an unsigned development package. Use the same bridge commands and popup
pairing steps as above. Firefox 128 or newer is required by this build.

Firefox uses a nonpersistent background page instead of Chromium's service worker.
The shared code selects Firefox's Promise-based `browser` API. The bridge accepts
Firefox extension UUID origins and still requires the private pairing code.
Temporary installation is removed after Firefox restarts. Permanent installation
on standard Firefox requires Mozilla signing; this package is not signed or
submitted to Mozilla. The Firefox build and WebSocket protocol are tested, but
live Firefox extension behavior still needs verification on a Firefox installation.

Mozilla references: [temporary installation](https://extensionworkshop.com/documentation/develop/temporary-installation-in-firefox/),
[signing requirements](https://extensionworkshop.com/documentation/publish/signing-and-distribution-overview/).

## Verification

Python bridge/investigation tests and Node protocol tests cover capability gates,
scope, evidence integrity and redaction. The isolated Chromium integration test
loads the real extension, pairs a local fixture, reads snapshots, fills/clicks,
captures network metadata and rejects outside-origin navigation. It pregrants
the fixture host permission in a temporary profile; the permission prompt and
screenshot still require manual verification in the user's browser.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_browser_bridge.py -q
node --test extensions/hydra-browser/tests/*.test.js
node tools/test_browser_extension.mjs PATH_TO_PLAYWRIGHT_INDEX_JS PATH_TO_CHROMIUM_EXE PATH_TO_PYTHON_EXE
```

The integration test writes `output/browser-e2e.json`; it uses no user profile,
external target, model credentials or paid API calls.
