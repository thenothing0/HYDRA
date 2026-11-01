# Synthetic laboratory — scope

Run `python scripts/verify_lab.py` from this skill folder with Python 3.10+. It uses the standard library, tiny locally generated inputs and no network service or real credential. Read the source first; examples are fixtures, not production libraries.

Covered: Normal local ZIP extraction, denied traversal/absolute paths/link entries, complete supported-entry preflight and a small expanded-size budget.

Not covered: No real untrusted archive, TAR/special file support, concurrent filesystem attack, TOCTOU resistance, permission model or production decompression performance was tested.

A passing test establishes only the encoded property/control. It does not show that an agent discovered a vulnerability or that the target application shares the fixture defect. The intentionally unsafe contrast remains in the deserialization training script; its only effect is an in-memory marker. No commands or persistent effects are used.
