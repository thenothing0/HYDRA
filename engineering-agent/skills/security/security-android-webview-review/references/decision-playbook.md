# Signed app identity, device state and platform capabilities

Analyst decision guide for this family. Use the questions relevant to the actual skill/target; this is not a certification checklist or evidence that any check occurred.

Record release build, OS/API, signing/entitlements, app identity and device state. Distinguish another app/UID, a web frame, the rightful user, a backup recipient and a rooted/debug observer. A privileged inspection prerequisite must not be recast as an ordinary remote attacker.

Trace exported components, URL routing, WebView bridges, storage/backup or Keychain items into the actual sensitive operation. Use owned devices/emulators, synthetic items and inert native effects; inspect merged/signed configuration rather than only source defaults.

Public components, custom URL schemes, JavaScript-enabled views and intentional app-group sharing can be valid features. Opening a screen or reading a value through root/debug tools does not prove a production authorization failure. Establish caller/device/account policy and the actual protected data/action.

Repair the platform boundary and downstream operation authority, preserving required background, inter-app and recovery flows. Retest legitimate users/callers, denied states, lifecycle/account switching and release-equivalent behavior; distinguish emulator evidence from physical-device assurance.

## Evidence before conclusion

- release/OS/signing and actor/device threat model
- merged manifest/entitlements/item/bridge policy
- caller/content/account-to-native-operation trace
- synthetic effect and privileged-inspection prerequisites
- normal platform integration and denied-state controls

Use the technique-specific guide and current primary runtime/provider documentation for details. If a decisive requirement is unavailable, record the missing artifact and narrower supported conclusion.
