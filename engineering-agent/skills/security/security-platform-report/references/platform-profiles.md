# Platform handoff profiles

Checked 2026-10-27. These are local writing profiles, not API schemas. Always inspect the program's current live template and required fields. Do not hardcode attachment limits or infer eligibility from a platform name.

| Profile | Prepare | Classification / unresolved fields |
|---|---|---|
| HackerOne | Asset/type, weakness, concise proof of concept, steps, impact and program custom fields | Evidence-supported severity and weakness; verify template/form |
| Bugcrowd | Target, overview, walkthrough/POC, evidence and demonstrated impact | Current applicable VRT classification and contextual severity; do not invent a priority |
| Intigriti | Selected asset, endpoint, issue type, reproduction details, impact and useful solution | Prefer English unless the program says otherwise; use supported severity/CVSS inputs |
| YesWeHack | Required bug metadata, detailed reproduction, impact and remediation in the program template | Review live severity inputs and account/program availability |
| Direct VDP / vendor | Subject/title, exact product/asset and prerequisites, minimal reproduction, impact, evidence, remediation and contact context | Use the owner's published channel, language and any encryption instructions |

The official HackerOne guide reviewed on 2026-10-27 describes severity selection for programs that require it, with program opt-out possible. An unresolved severity can remain a local draft; do not invent a selection to make a required live field pass. The current YesWeHack guide also describes account verification as an access prerequisite with a Dojo exception; verify actual program/account availability when preparing a real handoff. Neither condition prevents local report writing.

## Original platform references

- [HackerOne reporting](https://docs.hackerone.com/en/articles/8473994-submitting-reports)
- [Bugcrowd researcher reporting](https://docs.bugcrowd.com/researchers/reporting-managing-submissions/reporting-a-bug/)
- [Intigriti report guidance](https://kb.intigriti.com/en/articles/5379086-how-to-write-and-submit-a-good-report)
- [YesWeHack hunter reporting](https://helpcenter.yeswehack.io/en/articles/586823-submit-a-vulnerability-report)

The prose, steps and impact still need a reviewer; a profile name cannot make an unsupported claim appropriate. The local helper does not log into a platform, open an external draft, upload attachments or submit.
