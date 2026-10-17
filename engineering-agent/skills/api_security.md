# Skill: API Security Testing

You are testing APIs for security vulnerabilities. APIs often have weaker security controls than web UI and are a prime target for bug bounties.

## Discovery Phase

### Find API Endpoints
1. Run `katana_crawl` with `js_crawl=true` — JS files often contain API routes
2. Run `gau_urls` — historical API endpoints may still be active
3. Run `ffuf_fuzz` targeting common API paths:
   - `/api/FUZZ`
   - `/api/v1/FUZZ`
   - `/api/v2/FUZZ`
   - `/v1/FUZZ`
   - `/graphql`
   - `/swagger.json`, `/openapi.json`
   - `/.well-known/openid-configuration`

### Look for API Documentation
- `/swagger-ui/`, `/api-docs/`, `/docs/`
- `/swagger.json`, `/swagger.yaml`
- `/openapi.json`, `/openapi.yaml`
- `/graphql` (introspection query)
- `/redoc`

## Vulnerability Testing

### 1. Broken Object Level Authorization (BOLA/IDOR)
- Identify endpoints that use IDs: `/api/users/123`, `/api/orders/456`
- Try accessing other users' resources by changing IDs
- Test both sequential IDs and UUIDs
- Check if unauthenticated access is possible

### 2. Broken Authentication
- Test for default credentials on API admin endpoints
- Check if API keys are exposed in JS files or responses
- Test token expiration and rotation
- Look for JWT vulnerabilities (none algorithm, weak secret)

### 3. Excessive Data Exposure
- Compare API response fields to what the UI shows
- Look for sensitive data in responses: emails, tokens, internal IDs
- Check verbose error messages that leak stack traces

### 4. Rate Limiting
- Test if critical endpoints have rate limiting
- Check: login, password reset, OTP verification, API key generation
- Use `ffuf_fuzz` to test rate limiting thresholds

### 5. Mass Assignment
- Look for PUT/PATCH endpoints
- Try adding extra fields: `role`, `admin`, `verified`, `balance`
- Compare request vs expected parameters

### 6. Injection
- Run `nuclei_scan` with `tags="api,injection"`
- Test SQL injection in API parameters
- Test NoSQL injection for MongoDB-backed APIs
- Test SSRF in URL parameters

### 7. GraphQL-Specific
If `/graphql` endpoint found:
- Test introspection: `{__schema{types{name,fields{name}}}}`
- Look for sensitive mutations
- Test for batch query attacks
- Check for field-level authorization

## Nuclei Tags for APIs
```
nuclei_scan with tags="api,graphql,swagger,jwt,cors,exposure"
```

## Report Template for API Findings
When reporting API vulnerabilities, always include:
- The exact HTTP request (method, URL, headers, body)
- The response demonstrating the vulnerability
- Impact specific to the API context
- Which authentication/authorization check is missing
