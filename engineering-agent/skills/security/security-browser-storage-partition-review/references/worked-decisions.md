# Worked decisions

These are authored synthetic scenarios, not executed findings or target observations. Use their discriminators, not their expected verdicts, when new evidence differs.


### Seeded in the wrong partition
The tester opens B, embeds A, and uses automation to plant a value in the frame before triggering an XSS. The payload reads that value. This proves access to that frame's storage, not the victim's first-party login storage.

### Decisive isolation result
Top-level A reads marker M. Embedded A under B reads null. Returning to A reads M again. Under the recorded profile, this supports isolation for that API/context pair. It does not say that cookies, every browser or prior storage-access grants behave identically.

### Local fixture scope
The optional lab uses only loopback pages and synthetic markers. A successful run validates the experiment wiring and reports its browser's observation. It is not a bank exploit or an authentication-impact proof.

### Automation defaults change the hypothesis
The author's explicit flags contain only `--no-sandbox`, but the effective command line also disables `ThirdPartyStoragePartitioning`. A marker becomes visible under the other site. Inspect and correct the automation default, then rerun the paired controls. Do not call the first run an ordinary-browser storage-isolation result. The process sandbox and storage isolation are separate controls.
