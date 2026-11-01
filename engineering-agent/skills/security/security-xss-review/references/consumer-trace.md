# Find the browser interpretation that matters

## Context changes the review

| Final consumer | Resolve before choosing a test/repair |
|---|---|
| Text node | Is the value assigned as text or reparsed as markup later? |
| HTML/rich content | Which sanitizer and policy run after the last transformation? |
| Attribute | Is it data, navigation, an event handler, or another interpreted value? |
| URL/navigation | Which schemes/origins and parser result does the consumer accept? |
| Script/template expression | Is input becoming source or remaining data in a supported serializer? |

Follow the last consumer, not just the first escape call. A decode/reparse/template step can change the context. Conversely, a dangerous-looking value that reaches only textContent may remain inert.

## Controlled runtime observation

Use a local browser page and a disposable synthetic account/viewer. Pick a harmless DOM/runtime marker and observe it at the actual sink; do not send credentials or page data to external collectors. For stored content, distinguish the author viewing their own data from a separately controlled victim/tenant role receiving it through the ordinary feature. Preserve browser/origin and enforced CSP/Trusted Types behavior.

If an enforced policy blocks the attempted execution, state that observed restriction. Do not claim execution happened; source analysis can still identify a risky boundary or a different supported defect. A report should not silently assume a weaker policy than the tested deployment.

## Repair and regression

Use a safe text/DOM API where the feature requires text. Where it requires rich content, verify the specific sanitizer/policy and avoid unsafe transformations after sanitization. Context-specific encoding is not interchangeable across HTML, JavaScript and URLs. Test ordinary punctuation/international text or allowed formatting and the exact original source-to-consumer path.

An alert screenshot without delivery/actor/consumer context is incomplete evidence. A complete source proof can be useful when runtime access is absent, but preserve which browser interpretation and delivery prerequisites remain unexecuted.
