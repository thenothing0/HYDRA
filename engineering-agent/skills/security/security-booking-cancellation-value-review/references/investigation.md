# Investigation: Booking cancellation eligibility and refund/credit conservation

## Trace in the actual implementation

Trace the cancellation actor, effective time and booking version into both inventory release and financial consequence.

## Implementation decisions

Record whose clock/timezone controls the deadline and whether the booking version includes rescheduling or partial fulfillment. A late request may be permitted by explicit grace or operator override. Verify financial credit and inventory release independently rather than reading only a cancellation status.

## Operational method

Write the cancellation matrix for unused, partially fulfilled, rescheduled and expired bookings using the actual grace/penalty policy. Bind the approved booking version and authoritative timezone/deadline to the refund and inventory release. Repeat the same synthetic cancellation delivery and verify both credit and released inventory stay within that matrix; one successful status without either committed effect is insufficient.

## Discriminating verification

Use owned sandbox bookings; compare valid cancellation with a late or foreign cancellation and inspect credit plus booking state.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A canceled UI label without credit or resource effect is insufficient; honor actual grace and timezone policy.

## Repair acceptance

Make cancellation and associated credit/release transitions consistent and verify deadlines, retries and partial failures.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
