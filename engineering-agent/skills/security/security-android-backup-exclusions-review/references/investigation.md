# Investigation: Android backup/device-transfer rules for declared sensitive app data

## Trace in the actual implementation

Determine which files participate in actual backup and device transfer paths, separating platform versions and debug tooling.

## Implementation decisions

Branch on Android version, cloud backup versus device-to-device transfer and the installed build rules. A single allowBackup value does not describe every transport/version. Determine whether the threat model grants backup extraction access and whether restored data remains useful under keystore/account binding, without collecting production app backups.

## Operational method

Resolve OS/target build and supported transport before selecting fullBackupContent or dataExtractionRules and its applicable cloud/device-transfer/cross-platform section. Missing rules in a supported mode can differ from an explicit exclusion; allowBackup=false is not a universal guarantee across OEM transfer paths. Retain the effective build rules and an owned synthetic backup/restore artifact for the selected mode. Do not infer current cross-platform behavior from an old two-transport fixture.

## Discriminating verification

Use an emulator/test account and synthetic secret marker; inspect an owned supported backup or restored app without extracting real-user data.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A file in private app storage is not automatically excluded from every transfer; unsupported adb backup behavior cannot prove current platform exposure.

## Repair acceptance

Exclude or protect sensitive persisted data under the actual backup modes and verify legitimate restoration.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://developer.android.com/identity/data/autobackup)
- [Additional implementation reference](https://developer.android.com/identity/data/autobackup)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
