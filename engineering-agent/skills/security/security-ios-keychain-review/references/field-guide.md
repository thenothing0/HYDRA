# iOS Keychain item accessibility and sharing authority — decision procedure

## Establish the boundary

Map each sensitive item and account to creation/query/update/deletion attributes, accessibility and access-control requirements. Record signed release entitlements and actual access groups rather than inferring authority from source configuration.

## Smallest decisive verification

Use an owned test app/device with synthetic items and an explicit lock/passcode/background-use threat model. Compare rightful access with the prohibited device/app/account state; simulator or jailbroken inspection must retain its prerequisites.

## Reject or narrow unsupported conclusions

A broad-looking group or item surviving app removal is not automatically a disclosure. Establish which signed identity/device state can retrieve it and whether that contradicts the product contract; user-interface gating is separate from item access control.

If the boundary is absent, record not-applicable and the reason. If an artifact/access requirement is missing, name that missing decisive check and keep the hypothesis unverified. Observed behavior must match the claimed actor/build/resource; a fixture only proves its encoded boundary. Stop on unexpected unrelated effects or degradation.

## Repair acceptance

Apply appropriate platform attributes and narrow sharing/account queries while preserving required background/recovery flows. Retest locked/unlocked states, account changes and authorized sharing on the relevant OS/build.

## Evidence worksheet

OS/device/build signing; item purpose and attributes; access groups; actor/account and device state; synthetic retrieval result; lock/background/recovery contract and valid control

Each result should explain the intended policy, caller control, actual consumer, result and competing explanation. Severity follows the evidenced consequence and prerequisites, not the technique label.
