# Skill: Vulnerability Hunting

You are performing a thorough vulnerability scan on discovered targets.

## Prerequisites
- Recon must be completed first (subdomains, live hosts, endpoints known)
- WAF detection should be done to adjust scanning approach

## Steps

1. **Nuclei Broad Scan**
   - Run `nuclei_scan` on each live host with `severity="medium,high,critical"`
   - Start with default templates to get a broad picture
   - Note: If WAF detected, use `rate_limit=50` to avoid blocking

2. **Tag-Specific Scans** (based on tech stack)
   - If WordPress detected: `nuclei_scan` with `tags="wordpress"`
   - If Apache/Nginx: `nuclei_scan` with `tags="apache"` or `tags="nginx"`
   - If login page found: `nuclei_scan` with `tags="default-login,brute-force"`
   - For API endpoints: `nuclei_scan` with `tags="api,graphql,swagger"`
   - Always run: `nuclei_scan` with `tags="cve,exposure,misconfiguration"`

3. **Directory Fuzzing**
   - Run `ffuf_fuzz` on main targets for hidden directories
   - If interesting paths found, run recursive fuzzing
   - Look for: admin panels, backup files, config files, .git exposure

4. **Parameter Fuzzing** (advanced)
   - For endpoints with parameters, use `ffuf_fuzz` with `fuzz_mode="parameter"`
   - Fuzz common parameter names: id, user, file, page, url, redirect, path

5. **Analysis**
   - For each finding, assess:
     - Is it a true positive or false positive?
     - What is the actual impact?
     - Can findings be chained together?
   - Save validated findings with `save_finding`

## Severity Assessment Guidelines

- **Critical**: Can lead to RCE, full account takeover, or database compromise
- **High**: Significant data exposure, stored XSS in sensitive context
- **Medium**: Reflected XSS, CSRF on important actions, info disclosure
- **Low**: Missing security headers, version disclosure
- **Info**: Technology detection, DNS information

## False Positive Indicators
- Generic information disclosures without sensitive data
- Version detections that don't map to known CVEs
- Headers that are informational but not exploitable
- Template matches on error pages
