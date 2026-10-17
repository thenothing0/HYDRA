import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {httpOrigin, cleanUrl, bridgeUrl, redact, ACTIONS, pageSnapshot, interact} from "../protocol.js";

test("origins reject privileged browser URLs and URL credentials", () => {
  assert.equal(httpOrigin("https://example.com:443/path"), "https://example.com");
  for (const url of ["chrome://settings", "file:///private", "https://user:key@example.com", "javascript:alert(1)"]) {
    assert.throws(() => httpOrigin(url));
  }
});
test("URL evidence discards query secrets and fragments", () => {
  assert.equal(cleanUrl("https://example.com/a?token=private#secret"), "https://example.com/a");
});
test("bridge cannot connect to remote hosts", () => {
  assert.equal(bridgeUrl("http://127.0.0.1:8911"), "http://127.0.0.1:8911");
  for (const url of ["http://attacker.example:8911", "http://127.0.0.1:8911/?token=x", "http://name:key@127.0.0.1:8911"]) {
    assert.throws(() => bridgeUrl(url));
  }
});
test("credential-looking text is redacted", () => {
  assert.equal(redact("Authorization Bearer abc password=abc"), "Authorization Bearer [REDACTED] password=[REDACTED]");
});
test("manifest is MV3, has no debugger/cookie permission or automatic content script", () => {
  const manifest = JSON.parse(fs.readFileSync(new URL("../manifest.json", import.meta.url)));
  assert.equal(manifest.manifest_version, 3);
  assert(!manifest.permissions.includes("cookies"));
  assert(!manifest.permissions.includes("debugger"));
  assert(!manifest.permissions.includes("tabs"));
  assert(!manifest.content_scripts);
  assert(!manifest.externally_connectable);
  assert.deepEqual(manifest.host_permissions, ["http://127.0.0.1/*"]);
  assert.equal(ACTIONS.has("evaluate"), false);
});
test("snapshot executes as a serialized function without importing privileged APIs", () => {
  const restored = new Function("return (" + pageSnapshot.toString() + ")")();
  assert.equal(typeof restored, "function");
  assert(!pageSnapshot.toString().includes("document.cookie"));
  assert(!pageSnapshot.toString().includes("localStorage"));
});
test("interaction refuses non-unique selectors and password fields", () => {
  const saved = globalThis.document;
  try {
    globalThis.document = {querySelectorAll: () => []};
    assert.throws(() => interact("click", "#missing", ""), /exactly one/);
    globalThis.document = {querySelectorAll: () => [{tagName: "INPUT", type: "password", getClientRects: () => [1]}]};
    assert.throws(() => interact("fill", "#password", "private"), /non-secret/);
  } finally { globalThis.document = saved; }
});
