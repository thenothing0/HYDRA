import {ACTIONS, MUTATIONS, httpOrigin, cleanUrl, bridgeUrl, redact, pageSnapshot, interact} from "./protocol.js";
const chrome = globalThis.browser || globalThis.chrome;

let socket = null;
let heartbeat = null;
let scope = [];
let allowActions = false;
const network = new Map();
const selected = new Map();

async function restoreTabs() {
  const {pairedTabs = {}} = await chrome.storage.session.get("pairedTabs");
  for (const [id, origin] of Object.entries(pairedTabs)) selected.set(Number(id), origin);
}

async function persistTabs() {
  await chrome.storage.session.set({pairedTabs: Object.fromEntries(selected)});
}

async function scopedTab(id) {
  if (!selected.has(id)) throw new Error("This tab was not paired by the operator");
  const tab = await chrome.tabs.get(id);
  if (!scope.includes(httpOrigin(tab.url)) || httpOrigin(tab.url) !== selected.get(id)) throw new Error("Tab is outside its authorized origin");
  return tab;
}

async function execute(action, args) {
  if (!ACTIONS.has(action)) throw new Error("Unsupported browser action");
  if (MUTATIONS.has(action) && !allowActions) throw new Error("Bridge is inspection-only");
  if (action === "tabs") {
    const tabs = [];
    for (const id of selected.keys()) {
      try { const tab = await scopedTab(id); tabs.push({tab_id: id, url: cleanUrl(tab.url), title: redact(tab.title).slice(0, 300)}); } catch { /* closed or out of scope */ }
    }
    return {tabs};
  }
  const tab = await scopedTab(args.tab_id);
  if (action === "snapshot") {
    const results = await chrome.scripting.executeScript({target: {tabId: tab.id}, func: pageSnapshot});
    await scopedTab(tab.id);
    const result = results[0]?.result;
    if (!result || !scope.includes(httpOrigin(result.url))) throw new Error("Page navigated outside scope");
    return result;
  }
  if (action === "navigate") {
    if (httpOrigin(args.url) !== selected.get(tab.id) || !scope.includes(httpOrigin(args.url))) throw new Error("Navigation outside paired origin");
    await chrome.tabs.update(tab.id, {url: args.url});
    return {url: cleanUrl(args.url), performed: "navigation requested", note: "Read a new snapshot after loading; redirects are rechecked"};
  }
  if (["click", "fill"].includes(action)) {
    if (typeof args.selector !== "string" || args.selector.length > 500) throw new Error("A bounded CSS selector is required");
    if (action === "fill" && (typeof args.value !== "string" || args.value.length > 2000)) throw new Error("Field text must be at most 2000 characters");
    await chrome.scripting.executeScript({target: {tabId: tab.id}, func: interact, args: [action, args.selector, args.value || ""]});
    return {url: cleanUrl(tab.url), performed: action, note: "Inspect a fresh snapshot to observe the outcome"};
  }
  if (action === "screenshot") {
    const active = await chrome.tabs.query({active: true, windowId: tab.windowId});
    if (active[0]?.id !== tab.id) throw new Error("Activate the paired tab before capturing it");
    const image = await chrome.tabs.captureVisibleTab(tab.windowId, {format: "jpeg", quality: 60});
    const after = await chrome.tabs.query({active: true, windowId: tab.windowId});
    if (after[0]?.id !== tab.id || (await scopedTab(tab.id)).url !== tab.url) throw new Error("Tab changed during capture; image discarded");
    if (image.length > 1500000) throw new Error("Screenshot exceeds evidence size limit");
    return {url: cleanUrl(tab.url), image, format: "jpeg"};
  }
  if (action === "network_start") { network.set(tab.id, []); return {url: cleanUrl(tab.url), recording: true}; }
  if (action === "network_events") return {url: cleanUrl(tab.url), recording: network.has(tab.id), events: network.get(tab.id) || [], note: "Metadata only; no request bodies, cookies or credentials"};
  if (action === "network_stop") { const events = network.get(tab.id) || []; network.delete(tab.id); return {url: cleanUrl(tab.url), events, recording: false}; }
  throw new Error("Unhandled action");
}

function capture(details) {
  const events = network.get(details.tabId);
  if (!events || !selected.has(details.tabId)) return;
  try {
    if (httpOrigin(details.url) !== selected.get(details.tabId) || !scope.includes(httpOrigin(details.url))) return;
    const allowedHeaders = new Set(["content-type", "content-security-policy", "x-frame-options", "strict-transport-security", "x-content-type-options", "cache-control", "referrer-policy"]);
    events.push({request_id: details.requestId, url: cleanUrl(details.url), method: details.method,
      status: details.statusCode, type: details.type, time: details.timeStamp,
      response_headers: (details.responseHeaders || []).filter(h => allowedHeaders.has(h.name.toLowerCase()))
        .map(h => ({name: h.name.toLowerCase(), value: redact(h.value || "").slice(0, 2000)}))});
    if (events.length > 200) events.splice(0, events.length - 200);
  } catch { /* only scoped HTTP metadata */ }
}

async function connect() {
  if (socket && [WebSocket.OPEN, WebSocket.CONNECTING].includes(socket.readyState)) return;
  const config = await chrome.storage.local.get(["bridge", "token"]);
  if (!config.bridge || !config.token) return;
  await restoreTabs();
  const base = bridgeUrl(config.bridge);
  const ws = new WebSocket(base.replace("http:", "ws:") + "/extension");
  socket = ws;
  ws.onopen = () => ws.send(JSON.stringify({token: config.token}));
  ws.onmessage = async event => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === "paired") {
        scope = data.origins.map(httpOrigin); allowActions = Boolean(data.allow_actions);
        await chrome.storage.session.set({connectionStatus: "paired", origins: scope, allowActions});
        clearInterval(heartbeat);
        heartbeat = setInterval(() => { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({type: "ping"})); }, 20000);
        return;
      }
      if (!data.id) return;
      try {
        const result = await execute(data.action, data.arguments || {});
        if (Number.isInteger(data.arguments?.tab_id)) result.tab_id = data.arguments.tab_id;
        ws.send(JSON.stringify({id: data.id, result}));
      }
      catch (error) { ws.send(JSON.stringify({id: data.id, error: error.message})); }
    } catch { /* invalid bridge message: no action */ }
  };
  ws.onclose = () => {
    if (socket !== ws) return;
    clearInterval(heartbeat); scope = []; allowActions = false; network.clear();
    chrome.storage.session.set({connectionStatus: "disconnected", origins: []});
    if (socket === ws) socket = null;
  };
}

chrome.webRequest.onHeadersReceived.addListener(capture, {urls: ["http://*/*", "https://*/*"]}, ["responseHeaders"]);
chrome.tabs.onRemoved.addListener(id => { selected.delete(id); network.delete(id); persistTabs(); });
chrome.alarms.onAlarm.addListener(alarm => { if (alarm.name === "reconnect") connect(); });
chrome.runtime.onInstalled.addListener(() => { chrome.alarms.create("reconnect", {periodInMinutes: 1}); connect(); });
chrome.runtime.onStartup.addListener(() => { selected.clear(); network.clear(); connect(); });
chrome.runtime.onMessage.addListener((message, sender, respond) => {
  if (sender.id !== chrome.runtime.id || !sender.url?.startsWith(chrome.runtime.getURL(""))) return false;
  (async () => {
    if (message.type === "connect") {
      const bridge = bridgeUrl(message.bridge);
      if (typeof message.token !== "string" || message.token.length < 32) throw new Error("Enter the bridge pairing code");
      if (socket) { socket.close(); socket = null; }
      await chrome.storage.local.set({bridge, token: message.token}); await connect();
      return {ok: true, note: "Connecting; refresh status in a moment"};
    }
    if (message.type === "pair_tab") {
      if (!scope.length) throw new Error("Connect the local bridge first");
      const tab = await chrome.tabs.get(message.tab_id);
      const tabOrigin = httpOrigin(tab.url);
      if (!scope.includes(tabOrigin)) throw new Error("This origin is not authorized by the bridge");
      if (!await chrome.permissions.contains({origins: [tabOrigin + "/*"]})) throw new Error("Grant this site's permission using Pair this tab");
      selected.set(tab.id, tabOrigin); await persistTabs();
      return {ok: true, note: "Only this tab is paired"};
    }
    if (message.type === "disconnect") {
      const permissions = [...new Set(selected.values())].map(value => value + "/*");
      await chrome.storage.local.remove(["token"]); selected.clear(); network.clear(); await persistTabs();
      if (permissions.length) await chrome.permissions.remove({origins: permissions});
      if (socket) socket.close(); return {ok: true};
    }
    if (message.type === "status") return {...await chrome.storage.session.get(["connectionStatus", "origins", "allowActions"]), pairedTabs: [...selected.keys()]};
    throw new Error("Unknown popup operation");
  })().then(respond, error => respond({error: error.message}));
  return true;
});
connect();
