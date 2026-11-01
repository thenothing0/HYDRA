# Worked decisions

These are authored synthetic scenarios, not executed findings or target observations. Use their discriminators, not their expected verdicts, when new evidence differs.


### UI-only gate
Only administrators see the publish form. The exported action trusts a posted document ID and writes using a privileged database client without checking the caller. An owned non-admin invokes the known action and changes a synthetic document. This is an invocation-time authorization failure.

### Reached but denied
The same action is callable, but its data layer checks the actor's tenant and rejects the other owned tenant before a write. A visible action ID and a 200 response containing the rejection are not a bypass.

### Stale render state
A form was rendered while membership existed. Membership is removed before submission; the action checks current membership and rejects. An encrypted old closure is not a defect by itself.
