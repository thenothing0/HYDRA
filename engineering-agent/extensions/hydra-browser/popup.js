import {httpOrigin} from "./protocol.js";
const chrome = globalThis.browser || globalThis.chrome;
const status = document.querySelector("#status");
const show = result => { status.textContent = result.error || result.note || JSON.stringify(result, null, 2); };
async function send(message) { try { show(await chrome.runtime.sendMessage(message)); } catch (error) { show({error: error.message}); } }
document.querySelector("#connect").onclick = () => send({type: "connect", bridge: document.querySelector("#bridge").value, token: document.querySelector("#token").value});
document.querySelector("#refresh").onclick = () => send({type: "status"});
document.querySelector("#disconnect").onclick = () => send({type: "disconnect"});
document.querySelector("#pair").onclick = async () => {
  try {
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    const allowed = await chrome.permissions.request({origins: [httpOrigin(tab.url) + "/*"]});
    if (!allowed) throw new Error("Site permission was declined");
    await send({type: "pair_tab", tab_id: tab.id});
  } catch (error) { show({error: error.message}); }
};
const stored = await chrome.storage.local.get("bridge");
if (stored.bridge) document.querySelector("#bridge").value = stored.bridge;
send({type: "status"});
