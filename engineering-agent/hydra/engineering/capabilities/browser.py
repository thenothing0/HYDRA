"""BrowserCapability handlers and public tool contracts."""

SCHEMAS = {
    "browser_tabs": {},
    "browser_snapshot": {"tab_id": "operator-paired tab id"},
    "browser_navigate": {"tab_id": "paired tab", "url": "same-origin authorized URL"},
    "browser_click": {
        "tab_id": "paired tab",
        "selector": "unique CSS selector from snapshot",
    },
    "browser_fill": {
        "tab_id": "paired tab",
        "selector": "non-secret text input",
        "value": "test text",
    },
    "browser_screenshot": {"tab_id": "currently active paired tab"},
    "browser_network_start": {"tab_id": "paired tab"},
    "browser_network_events": {"tab_id": "paired tab"},
    "browser_network_stop": {"tab_id": "paired tab"},
    "investigation_create": {
        "url": "authorized URL",
        "category": "authorization|input_validation|session|headers|navigation",
        "hypothesis": "explicit unverified claim",
    },
    "investigation_observe": {
        "case_id": "case id",
        "evidence_ids": ["real browser evidence id"],
        "interpretation": "inference, not confirmed impact",
    },
    "investigation_compare": {
        "case_id": "case id",
        "baseline_id": "snapshot evidence",
        "variant_id": "independent snapshot evidence",
    },
    "investigation_report": {},
}


class BrowserCapability:
    schemas = SCHEMAS

    def __init__(self, runtime):
        self.runtime = runtime

    async def execute(self, tool, args):
        if tool in SCHEMAS:
            if not self.runtime.browser_enabled:
                raise PermissionError(
                    "Browser capability was not enabled for this session"
                )
            if tool.startswith("investigation_"):
                from hydra.browser.investigation import InvestigationStore

                store = InvestigationStore(self.runtime.workspace.root)
                if tool == "investigation_create":
                    return store.create(
                        args["url"], args["category"], args["hypothesis"]
                    )
                if tool == "investigation_observe":
                    return store.observe(
                        args["case_id"], args["evidence_ids"], args["interpretation"]
                    )
                if tool == "investigation_compare":
                    return store.compare(
                        args["case_id"], args["baseline_id"], args["variant_id"]
                    )
                return store.report()
            from hydra.browser.bridge import BrowserClient, MUTATIONS

            action = tool.removeprefix("browser_")
            if action in MUTATIONS and (
                self.runtime.read_only or not self.runtime.allow_browser_actions
            ):
                raise PermissionError(
                    "Page interactions require --allow-browser-actions and a writable session"
                )
            return await BrowserClient(self.runtime.workspace.root).execute(
                action, args
            )
