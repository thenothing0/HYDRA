# Worked decisions

These are authored synthetic scenarios, not executed findings or target observations. Use their discriminators, not their expected verdicts, when new evidence differs.


### Browser configuration, unknown grants
A value is assigned to `window.vendorConfig.apiKey`; the SDK exposes getSessionId(). This supports client initialization use. It does not demonstrate access to historical reports, and it does not prove those grants are absent. Preserve both distinctions.

### Excessive authority with owned records
An owner-approved test collection key retrieves a synthetic report belonging to a second owned tenant, despite the documented collection-only role. Preserve both actors, the authorized control and the returned synthetic marker. Report the excessive query authority, not merely that the key was visible.

### Public script response
A script URL returns 200 without any key, and returns the same bytes when a key parameter is present. That response cannot validate the credential. Do not convert the successful download into an observed grant.
