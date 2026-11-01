# Primitive contract, key identity and verification before use

Analyst decision guide for this family. Use the questions relevant to the actual skill/target; this is not a certification checklist or evidence that any check occurred.

Identify the exact cryptographic primitive/API and stored format rather than judging an algorithm label. Trace key origin/identity, version, nonce/salt/context, verification and data use across persistence, rotation, restart and multiple writers. TLS encryption, certificate-chain trust and service identity are separate checks.

Use fake keys/passwords and local fixtures; never validate a leaked real credential by trying it against a service. Derive a supported invariant: representable key/nonce uniqueness for this primitive, authenticated metadata, rejection before plaintext use or a versioned password verifier. Record deployment capacity when assessing KDF parameters.

A random-looking value is not entropy proof, and equal nonces under different keys do not prove same-key reuse. A private CA or absent pinning may be intended. Hash presence does not establish a suitable password KDF, nor does UI masking remove a secret from storage.

Prefer supported primitives and lifecycle fixes. Retest legitimate old/new formats, wrong tag/context/peer, rotation and migration boundaries. A fixture's cryptographic property is not evidence that production uses the same key or reaches the vulnerable consumer.

## Evidence before conclusion

- primitive/library/runtime and exact format
- key identity/lifecycle without key material
- nonce/salt/AAD/reference-identity requirement
- verification-before-use and actual source/runtime evidence
- valid data, rotation/migration and rejected-context controls

Use the technique-specific guide and current primary runtime/provider documentation for details. If a decisive requirement is unavailable, record the missing artifact and narrower supported conclusion.
