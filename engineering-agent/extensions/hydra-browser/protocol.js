export const ACTIONS = new Set(["tabs", "snapshot", "navigate", "click", "fill", "screenshot", "network_start", "network_stop", "network_events"]);
export const MUTATIONS = new Set(["navigate", "click", "fill"]);

export function httpOrigin(value) {
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) throw new Error("HTTP(S) URL without credentials required");
  return url.origin;
}

export function cleanUrl(value) {
  const url = new URL(value);
  httpOrigin(value);
  return url.origin + url.pathname;
}

export function bridgeUrl(value) {
  const url = new URL(value);
  if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || url.username || url.password || url.search || url.hash || url.pathname !== "/") {
    throw new Error("Bridge must be http://127.0.0.1:PORT");
  }
  return url.origin;
}

export function redact(value) {
  return String(value).replace(/Bearer\s+[^\s"']+/gi, "Bearer [REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[REDACTED JWT]")
    .replace(/((?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*)[^\s,;]+/gi, "$1[REDACTED]");
}

// This function is serialized by chrome.scripting; keep all dependencies local.
export function pageSnapshot() {
  const safeUrl = value => { try { const u = new URL(value, location.href); return ["http:", "https:"].includes(u.protocol) ? u.origin + u.pathname : "[non-http]"; } catch { return "[invalid]"; } };
  const scrub = value => String(value || "").replace(/Bearer\s+[^\s"']+/gi, "Bearer [REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[REDACTED JWT]")
    .replace(/((?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*)[^\s,;]+/gi, "$1[REDACTED]");
  const selector = element => {
    if (element.id) return "#" + CSS.escape(element.id);
    const parts = [];
    for (let current = element; current && current !== document.body && parts.length < 7; current = current.parentElement) {
      const siblings = Array.from(current.parentElement?.children || []);
      parts.unshift(current.tagName.toLowerCase() + ":nth-child(" + (siblings.indexOf(current) + 1) + ")");
    }
    return "body > " + parts.join(" > ");
  };
  const visible = element => Boolean(element.getClientRects().length) && getComputedStyle(element).visibility !== "hidden";
  // No input/textarea values, HTML source, storage, cookies or auth headers.
  const elements = Array.from(document.querySelectorAll("a,button,input,select,textarea,[role=button]"))
    .filter(visible).slice(0, 120).map(element => ({
      selector: selector(element), tag: element.tagName.toLowerCase(), type: element.getAttribute("type") || "",
      name: scrub(element.getAttribute("name") || "").slice(0, 100),
      label: scrub(element.getAttribute("aria-label") || element.getAttribute("placeholder") ||
        (["A", "BUTTON"].includes(element.tagName) ? element.innerText : "")).slice(0, 180),
      ...(element.tagName === "A" ? {href: safeUrl(element.href)} : {}), disabled: Boolean(element.disabled)
    }));
  const texts = [];
  const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT);
  let node;
  let length = 0;
  while ((node = walker.nextNode()) && length < 12000) {
    const parent = node.parentElement;
    if (!parent || parent.closest("script,style,noscript,input,textarea,select,[hidden],[aria-hidden=true]")) continue;
    if (!visible(parent)) continue;
    const text = scrub(node.textContent).trim();
    if (text) { texts.push(text); length += text.length; }
  }
  return {url: safeUrl(location.href), title: scrub(document.title).slice(0, 300), text: texts.join("\n").slice(0, 12000),
    elements, forms: Array.from(document.forms).slice(0, 30).map(form => ({
      action: safeUrl(form.action), method: form.method.toUpperCase(),
      fields: Array.from(form.elements).slice(0, 60).map(field => ({name: scrub(field.name).slice(0, 100), type: field.type || field.tagName.toLowerCase()}))
    }))};
}

export function interact(action, selector, value) {
  const matches = document.querySelectorAll(selector);
  if (matches.length !== 1) throw new Error("Selector must match exactly one element");
  const element = matches[0];
  if (!element.getClientRects().length || element.disabled) throw new Error("Element is not visible/enabled");
  if (action === "click") { element.click(); return {performed: "click"}; }
  if (!["INPUT", "TEXTAREA"].includes(element.tagName) || element.type === "password" || element.type === "file" || element.type === "hidden") {
    throw new Error("Only non-secret text fields may be filled; sign in manually");
  }
  const prototype = element.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(prototype, "value").set.call(element, value);
  element.dispatchEvent(new Event("input", {bubbles: true}));
  element.dispatchEvent(new Event("change", {bubbles: true}));
  return {performed: "fill"};
}
