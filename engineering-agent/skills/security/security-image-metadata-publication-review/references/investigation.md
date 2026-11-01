# Investigation: Sensitive image metadata retained through transformation and public delivery

## Trace in the actual implementation

Follow protected metadata through original, resized and cached variants. Establish whether the publisher intentionally authorizes the destination audience to receive it.

## Implementation decisions

Inspect the delivered derivative, original-download path and CDN cache separately. Stripping visible EXIF fields may leave thumbnails, XMP or other containers; a server filename is not necessarily original metadata. Confirm a synthetic classified field survives the actual public delivery path, and distinguish deliberately published attribution from private location/device data.

## Discriminating verification

Use an owned image with synthetic location/identity metadata and compare public/authorized output variants; do not collect real-user location data.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Metadata presence is not automatically a confidentiality violation; public photographer attribution and owner-requested original downloads can be intended.

## Repair acceptance

Strip/protect sensitive fields according to policy across variants, preserving intended attribution and image quality.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://exiftool.org/TagNames/EXIF.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
