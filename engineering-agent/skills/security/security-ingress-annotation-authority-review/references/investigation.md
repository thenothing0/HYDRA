# Investigation: Ingress annotations/templates controlling privileged proxy behavior

## Trace in the actual implementation

Trace an allowed ingress writer field into routing, file access or configuration evaluated by a higher-privilege controller.

## Implementation decisions

Identify the installed ingress controller and enabled annotation/template features. The same annotation name can be ignored by a different controller. Separate permission to create Ingress objects from ability to alter global controller configuration; only trace input into generated configuration when a lower-trust actor can set it and the controller actually consumes it.

## Operational method

For ingress-nginx, collect the effective controller ConfigMap, snippet enablement, risk admission settings and installed controller version. Retain the generated configuration or rejection diagnostic for the specific annotation. A submitted annotation that is ignored or rejected does not reach the proxy parser. Compare a harmless admitted annotation with the disputed privileged directive in an isolated renderer, and keep permission to edit the controller ConfigMap separate from permission to create an Ingress.

## Discriminating verification

Use an isolated controller fixture and inert routing marker; compare permitted routing and one policy-forbidden annotation effect.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Controller support for powerful annotations is not tenant escalation unless a lower-trust writer can reach the protected effect.

## Repair acceptance

Constrain annotations/ingress writers and generated configuration, retesting intended routes and rejected privileged directives.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
