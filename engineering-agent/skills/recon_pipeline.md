# Skill: Full Recon Pipeline

You are performing comprehensive reconnaissance on a target domain.

## Steps

1. **Check tools** — Run `check_tools` to verify all security tools are available

2. **Subdomain Enumeration**
   - Run `subfinder_scan` on the target domain
   - Run `amass_enum` with `passive=true` for deeper results
   - Merge and deduplicate all discovered subdomains

3. **HTTP Probing**
   - Take all unique subdomains and run `httpx_probe` with `status_code=true`, `title=true`, `tech_detect=true`
   - Note which subdomains are alive and their HTTP status codes
   - Pay attention to 403 (potential bypass), 401 (auth endpoints), 302 (redirects)

4. **Endpoint Discovery**
   - Run `katana_crawl` on the top 10 most interesting live hosts (depth=3, js_crawl=true)
   - Run `gau_urls` on the main domain for historical URLs
   - Look for API endpoints, admin panels, file upload forms, login pages

5. **Technology Fingerprinting**
   - Run `whatweb_detect` on the main domain and key subdomains
   - Run `wafw00f_detect` to identify WAF presence
   - Note the tech stack: CMS, framework, server, language

6. **Port Scanning** (if authorized)
   - Run `nmap_scan` with `scan_type="service"` on key hosts
   - Look for non-standard ports, exposed services

## Output Format

Present a structured summary:
```
## Recon Summary for [domain]

### Subdomains: [count] discovered, [count] alive
[table of alive subdomains with status codes and titles]

### Interesting Endpoints
[list of endpoints worth investigating]

### Technology Stack
[detected technologies]

### WAF Detection
[WAF status]

### Attack Surface Notes
[interesting observations and next steps]
```
