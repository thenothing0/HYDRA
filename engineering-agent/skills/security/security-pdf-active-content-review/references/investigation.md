# Investigation: PDF active-content handling across generation, preview and recipient context

## Trace in the actual implementation

Trace lower-trust document content into an actual supported viewer capability such as navigation or embedded action; separate inert bytes from executed behavior.

## Implementation decisions

Separate generator trust, server preview conversion and recipient viewer capabilities. JavaScript, embedded files and external actions may be ignored, blocked or require user interaction in the deployed viewer. An active-content object in PDF syntax is not proof it executes; use a harmless local marker and record the exact viewer/version and necessary interaction.

## Operational method

Select the actual PDF object/action trigger and product rule: for example document-open action, link action, embedded attachment or script action are different consumers. Retain the original and transformed object inventory, preview renderer and final downloaded viewer/version. Compare a harmless allowed document with a prohibited inert action marker through the real transformation. An object remaining in syntax is not proof it runs in a viewer that ignores or prompts for it.

## Discriminating verification

Use a local synthetic PDF and an owned harmless destination/marker in a constrained viewer fixture; compare intended passive content and the prohibited active behavior.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An action dictionary or script string in a PDF is not proof a recipient viewer executes it; viewer protections may reject it.

## Repair acceptance

Remove or constrain prohibited active features in the actual publication/preview path, verifying legitimate rendering and rejected behavior.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://opensource.adobe.com/dc-acrobat-sdk-docs/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
