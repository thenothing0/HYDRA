# Synthetic laboratory — scope

Run `python scripts/verify_lab.py` from this skill folder with Python 3.10+. It uses the standard library, tiny locally generated inputs and no network service or real credential. Read the source first; examples are fixtures, not production libraries.

Covered: An intentionally unsafe pickle decoder invokes an inert in-memory constructor; a constrained JSON path preserves valid data and rejects object bytes, extra fields and wrong primitive types.

Not covered: No production serializer, object gadget chain, network entry point, runtime exploitability or remote code execution was tested. JSON format alone does not enforce the business/authority contract.

A passing test establishes only the encoded property/control. It does not show that an agent discovered a vulnerability or that the target application shares the fixture defect. The intentionally unsafe contrast remains in the deserialization training script; its only effect is an in-memory marker. No commands or persistent effects are used.
