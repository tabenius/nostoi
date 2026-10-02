# S3 and R2 failure diagnostics

Failed PUT, GET and retention requests report their operation and HTTP status,
recognized S3 XML error code, bounded request/host IDs and bucket region when
available. The existing `Error::S3(String)` interface is preserved. R2's S3 XML
errors use the same diagnostic path.

## Clock and credentials

`RequestTimeTooSkewed` and `RequestExpired` advise synchronizing the host clock.
`SignatureDoesNotMatch` also suggests checking credentials, endpoint, region and
signed headers. `ExpiredToken`/`InvalidToken` advise refreshing session credentials;
`AccessDenied` suggests reviewing credentials, bucket policy and permissions.
Missing keys/buckets and wrong-region responses have specific configuration hints.

When a parseable XML `ServerTime` or HTTP `Date` is present, the client compares
it to the **actual SigV4 timestamp on the final send attempt**, reporting whole
seconds ahead of or behind the server. XML `RequestTime`, if present, must match
that signed timestamp; it is never used as the local clock. An invalid XML server
time may fall back to a valid HTTP date. Missing/invalid dates or mismatched request
times yield no skew estimate. No acceptance window or safety margin is inferred.

This is an approximate, server-reported comparison, **not a trusted time source**:
network delay, intermediary dates and a misconfigured server can affect it. The
client neither adjusts its clock nor retries a 403. Synchronize the host clock
using the operating system's time service, then investigate configuration and
credentials if the error persists.

## Bounded, non-reflective reporting

Error bodies are read up to 16 KiB plus one overflow-detection byte. Oversized,
unreadable or non-UTF-8 error bodies supply no XML metadata; HTTP status and header
metadata remain available. Successful response reading is unchanged.

A small dependency-free recognizer accepts direct text children of an `Error`
root, including namespace-prefixed tags and an XML declaration. It requires
balanced matching tags and rejects duplicate requested fields, entities, DTDs,
CDATA and nested content. It is deliberately not a general XML parser: unsupported
documents still yield HTTP-status diagnostics. This avoids adding an SDK or XML
dependency for this minimal known shape. Tests exercise prefixed XML, malformed
and oversized bodies, duplicate tags and entity/nesting attacks.

Only known error codes are rendered. Remote messages, canonical requests,
authorization headers, reflected credentials and raw XML are never printed.
IDs and regions must be at most 128 ASCII bytes using letters, digits or
`-_.+/=`; values containing configured access keys, secrets or session tokens,
or authorization-related markers, are omitted. Header values take precedence
over XML counterparts. Transport/body-read failures use fixed descriptions
rather than printing potentially reflective library errors. Unrecognized error
codes receive status-based hints without exposing the remote code.

This is conservative metadata filtering, not a general-purpose secret detector:
arbitrary transformations of secrets in server-controlled identifiers cannot be
recognized. Server IDs and region metadata are untrusted correlation hints.

## Retry and durable-outbox semantics

Retry behavior is unchanged: GET and conditional PUT allow up to three attempts
on transport errors or HTTP 429/500/502/503/504, with fresh signing each time.
Unconditional PUT is not retried. Diagnostics never call the signing clock again.

A definite initial 403 is `Error::S3`; a PUT rejection following an ambiguous
transport/5xx attempt remains `Error::UploadUncertain`, with the final response's
bounded diagnostics and an explicit ambiguity qualifier. Exhausted 5xx PUTs
remain uncertain. Existing conditional 412 handling and retention 404 (`None`)
are preserved. Higher-level `AnchorUnconfirmed` wrapping remains intact, so an
uploaded object whose retention cannot be confirmed is not reported as absent.
Only the final attempt's response metadata is reported.
