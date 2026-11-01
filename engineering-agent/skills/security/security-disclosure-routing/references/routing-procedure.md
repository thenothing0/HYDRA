# Disclosure decision procedure

Keep a per-finding candidate table with asset/product, responsible owner, channel, original owner-policy URL, program-policy URL, explicit asset/type match, exclusions, active/access state, preferred language, required fields, check time and decision/reason. The final route needs source-backed scope and ownership, not just a program with a similar company name.

Classify the defect’s authority boundary: deployment/operator configuration, upstream product code, hosted SaaS, integration or provider platform. The company whose branding appears on a service may not own the defective component. Verify cross-company ownership rather than copying one route to all findings.

Search official security/VDP pages and the owner-linked program. Use platform search/public directories as leads. Review exact asset entries, wildcard semantics and exclusions explicitly; do not infer that all subdomains, acquisitions, mobile backends or third-party hosted resources are covered. Preserve the reason a candidate was rejected.

For security.txt discovery, prefer the exact origin's standardized well-known location, retain its source URL/redirect history and check Expires and policy pointers. An unsigned, expired, stale, unexpected-origin or conflicting pointer needs further verification. Parent host pointers do not automatically cover child hosts. The offline parser does not verify signatures or provenance.

Do not guess a security@ address, contact platform support as the vulnerability recipient, bypass invitations/KYC/access, select by potential reward, or send to multiple platforms to resolve ambiguity. If no channel can be verified, give the user a neutral draft and the exact remaining ownership/policy question. If the user later authorizes transmission, re-read policy and use the chosen actual channel.

Primary contact-file reference: [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116.html). Consult its actual field/provenance rules; the helper implements pointer extraction only. Checked 2026-10-27.
