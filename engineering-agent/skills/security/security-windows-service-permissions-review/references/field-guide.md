# Windows service configuration and file authority — decision procedure

## Establish the boundary

Map the service identity and intended editors to the effective service-object DACL, configuration/registry permissions and binary/dependency path ACLs. Record the actual unprivileged token and inherited group rights.

## Smallest decisive verification

Prefer read-only effective-access evidence. If needed use an owner-created disposable service/configuration stub with no privileged executable action. Establish the editable setting/file and the required trigger statically; never overwrite or restart a production service for proof.

## Reject or narrow unsupported conclusions

An unquoted path or readable binary alone does not prove escalation. The claimed actor must control the relevant candidate path/configuration and the privileged service must actually consume it under the stated trigger.

If the boundary is absent, record not-applicable and the reason. If an artifact/access requirement is missing, name that missing decisive check and keep the hypothesis unverified. Observed behavior must match the claimed actor/build/resource; a fixture only proves its encoded boundary. Stop on unexpected unrelated effects or degradation.

## Repair acceptance

Remove unintended edit authority at each evidenced object/file boundary and preserve required operators. Retest the effective low-privilege token, intended maintenance path and configuration consumption without changing real system services.

## Evidence worksheet

service account/config; effective token/groups; DACL and file/parent ACL evidence; controlled setting/path; trigger prerequisites; read-only versus replica proof; operator control

Each result should explain the intended policy, caller control, actual consumer, result and competing explanation. Severity follows the evidenced consequence and prerequisites, not the technique label.
