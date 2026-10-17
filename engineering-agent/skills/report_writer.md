# Skill: Bug Bounty Report Writer

You are writing a professional bug bounty report suitable for submission to HackerOne, Bugcrowd, or Intigriti.

## Report Structure

For EACH finding, generate a report section following this exact template:

---

## [Severity] — [Vulnerability Title]

### Summary
[1-2 sentence summary of the vulnerability and its impact]

### Vulnerability Details
- **Type:** [CWE ID and name, e.g., CWE-79: Cross-site Scripting]
- **Severity:** [Critical / High / Medium / Low]
- **CVSS Score:** [Calculate CVSS 3.1 score]
- **Affected URL:** [Exact URL where vulnerability exists]
- **Parameter/Input:** [The specific parameter or input vector]

### Steps to Reproduce
1. Navigate to [URL]
2. [Exact step-by-step instructions]
3. [Include payloads used]
4. Observe [expected behavior demonstrating the vulnerability]

### Evidence
```
[Paste tool output, HTTP request/response, or screenshot description]
```

### Impact
[Describe what an attacker could achieve by exploiting this vulnerability.
Be specific — mention data types at risk, affected users, business impact.]

### Remediation
[Provide specific, actionable remediation steps:
- What code changes to make
- What configuration to update
- What security controls to implement]

### References
- [Link to relevant CWE]
- [Link to OWASP documentation]
- [Link to relevant CVE if applicable]

---

## Quality Checklist

Before submitting, verify:
- [ ] Clear, descriptive title
- [ ] Accurate severity rating with CVSS justification
- [ ] Complete steps to reproduce (someone else can follow them)
- [ ] Actual evidence from tool output (never fabricate)
- [ ] Impact is specific and realistic
- [ ] Remediation is actionable
- [ ] Not a duplicate of previous findings (check with `get_findings`)

## After Writing

1. Use `save_finding` to persist each validated finding
2. Use `generate_report` to create the consolidated report file
3. Present the final report for review
