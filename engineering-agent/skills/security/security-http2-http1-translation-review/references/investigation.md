# Investigation: HTTP/2 internal request normalization and HTTP/1 serialization agreement

## Trace in the actual implementation

Resolve how the intermediary translates lengths, prohibited fields, trailers and stream boundaries into backend messages. Keep parser hypotheses tied to the actual deployed chain.

## Implementation decisions

A frontend rejection with zero bytes forwarded stops the proposed chain. Otherwise correlate HTTP/2 DATA length, translated HTTP/1 framing, legal trailers, connection reuse and actual backend boundaries. A second ordinary request is not proof of desynchronization; establish an unexpected boundary caused by the challenged stream in an isolated backend, without shared-user traffic.

## Operational method

Trace four concrete artifacts: decoded H2 header/DATA events, normalized internal request, serialized H1 bytes and backend parser boundaries on the same isolated connection. Resolve pseudo-header authority versus Host, content-length versus DATA accounting and trailer forwarding in the translator implementation. Frontend rejection with zero forwarded bytes disproves that path. Attribute any unexpected boundary to one transformation step; do not treat a second ordinary request or generic two-hop discrepancy as H2 translation proof.

## Discriminating verification

In an isolated translator/parser fixture correlate one H2 stream, its normalized request and exact H1 serialization with backend boundaries. Compare a legitimate equal-length control with one bounded rejected or differently normalized input; do not involve shared connections/users.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Different status codes or a malformed-header rejection are not request smuggling without a second parsed message/effect.

## Repair acceptance

Normalize or reject ambiguous translation and retest the exact framing pair plus normal multiplexed traffic.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.rfc-editor.org/rfc/rfc9112)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
