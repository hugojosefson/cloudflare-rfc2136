# ACME DNS-01 support for the Cloudflare RFC 2136 bridge

Current decisions, test results, and remaining work are in
[the work record](implementation-notes.md). The source review below describes
the original revision.

## Purpose and status

This proposal adds ACME DNS-01 challenge updates to the bridge. Cloudflare
remains the public authoritative DNS provider. The bridge receives authenticated
DNS UPDATE messages and translates them into Cloudflare API requests. It does
not become a public DNS server.

Source review date: 2026-09-16. Reviewed revision:
[e77cf7a](https://github.com/47star/cloudflare-rfc2136/commit/e77cf7a6a947f86b9bdb93d954b5b8c9b9d89cf3).
The changes below are proposals. No implementation or certificate issuance test
supports a claim of compatibility. All example names use the reserved domain
`example.com`. This document contains no deployment credentials or private
network data.

## Required outcome

An ACME issuer must support this sequence:

1. Add TXT value `value-a` at `_acme-challenge.example.com.`.
2. Add TXT value `value-b` at the same name without removing `value-a`.
3. Remove `value-a` without changing `value-b`.
4. Do each operation again without unintended changes.

These values are illustrative text, not actual challenge values. The
[DNS-01 specification](https://www.rfc-editor.org/rfc/rfc8555.html#section-8.4)
defines the actual digest and record name. Concurrent orders can use the same
record name. Cleanup for one order must not remove a different order's proof.

## Current code and required changes

| Source                                        | Current behavior                                             | Proposed change                                                               |
| --------------------------------------------- | ------------------------------------------------------------ | ----------------------------------------------------------------------------- |
| [Record model](src/cloudflare/model.rs)       | `DnsRecordKind` contains only A and AAAA.                    | Add TXT and its API representation.                                           |
| [UPDATE parser](src/dns/rfc2136.rs)           | Rejects TXT. Groups additions into `Upsert` operations.      | Decode TXT additions and removals with their RFC 2136 meanings.               |
| [Name validation](src/dns/validation.rs)      | Rejects all names with an underscore at the start.           | Accept the exact `_acme-challenge` label for approved TXT operations.         |
| [Cloudflare client](src/cloudflare/client.rs) | `upsert_rrset` replaces existing values. Lists one API page. | Add TXT values without replacement. Read all result pages.                    |
| [Request handler](src/dns/mod.rs)             | Executes changes through the shared Cloudflare client.       | Route TXT operations through the new behavior and control concurrent updates. |
| [Configuration](src/config.rs)                | No ACME-specific permission setting.                         | Add an explicit opt-in for ACME TXT updates.                                  |

## 1. Permission and compatibility policy

The proposed setting is `ENABLE_ACME_TXT`, with a default of `false`. This is a
new setting, not an existing option. Opt-in keeps the current DDNS permissions
unchanged for existing installations.

When the setting is enabled, a TXT operation must satisfy all these conditions:

- The request passes TSIG authentication.
- The UPDATE zone equals `DNS_ZONE`.
- The owner name is in that zone and in `ALLOWED_RECORD_SUFFIX`, using DNS label
  boundaries.
- The first label equals `_acme-challenge`, ignoring DNS name case.
- The operation uses an accepted class, TTL, and TXT representation.

The checks must apply to additions and removals. For example,
`_acme-challenge.host.example.com.` can be accepted.
`_acme-challenge.host.example.com.evil.example.` must fail a suffix check for
`example.com.`.

Keep the existing rejection of zone-apex owner names, wildcard owner names,
unrelated underscore names, and unsupported record types. An ACME challenge for
`*.example.com` uses `_acme-challenge.example.com`, not an owner name containing
`*`. Do not accept A or AAAA updates at underscore names as a side effect.

Identify the record type before applying the type-specific owner policy. Keep
name normalization and zone-boundary checks shared. Keep the TXT permission
exception explicit.

Initially keep the current A and AAAA behavior. A general correction to DDNS
replacement semantics can be a different change. Document that this is a
constrained UPDATE adapter, not a full RFC 2136 authoritative server.

## 2. TXT decoding and UPDATE operations

Add a TXT variant to `DnsRecordKind`, its API type string, and the `RecordType`
conversion. Add TXT decoding to `record_content` or a dedicated function. DNS-01
values are case-sensitive. Do not lowercase their content or remove whitespace
from it.

The initial feature can accept a single ASCII TXT character-string, which is
sufficient for ACME DNS-01. Reject unsupported multi-string or non-ASCII input
before an API request. Do not silently concatenate or replace bytes. General TXT
encoding support can follow with explicit round-trip tests.

The implementation must distinguish these operations:

| Wire operation                               | Required behavior                                                       |
| -------------------------------------------- | ----------------------------------------------------------------------- |
| Class IN, type TXT, with content             | Add the specified value. Keep other values at the same name.            |
| Class NONE, type TXT, TTL zero, with content | Remove only records with the specified value.                           |
| Class ANY, type TXT, TTL zero, empty RDATA   | This requests removal of the full TXT record set. See the policy below. |
| Class ANY, type ANY                          | Reject name-wide removal.                                               |
| Nonempty prerequisite section                | Keep the current explicit rejection.                                    |
| Invalid class, TTL, or RDATA                 | Reject the UPDATE before changing Cloudflare records.                   |

For the first ACME feature, reject full-set TXT removal. It cannot identify the
challenge value that the sender intends to clean up. Do not silently reinterpret
it as removal of the last value seen. That fails after restarts and with
concurrent orders. Any future full-set removal feature must have an explicit
policy and tests for the RFC behavior.

Keep operations in their required sequence. An add followed by a removal must
not become a removal followed by an add. Add and removal meanings come from
[RFC 2136, sections 2.5 and 3.4](https://www.rfc-editor.org/rfc/rfc2136.html).

## 3. Cloudflare API behavior

Use a TXT-specific addition path. Do not use `upsert_rrset` for TXT additions.
That existing function can use an existing record ID for a different value and
remove other records. Those actions conflict with concurrent ACME challenges.

For an addition, use this sequence:

1. List all TXT records for the exact normalized owner name.
2. If the requested content exists, return success without changing other
   values.
3. If the content is missing, make a TXT record for it.

For cleanup, use this sequence:

1. List all TXT records for the exact normalized owner name.
2. Select only record IDs with content equal to the requested value.
3. Remove those records and keep all other values unchanged.
4. If no matching record exists, return success.

Read pagination metadata from the API response. Collect the matching IDs before
removals so pagination does not skip shifted records. The
[list-records API](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/)
documents the response and query fields. Extend `ApiEnvelope` or add a paginated
response type as necessary.

Use Cloudflare's TXT content representation, not Rust debug output or DNS
presentation text. Test request and response content normalization, with
quotation behavior, against the documented API contract. Keep unrelated TXT
values unchanged if they use a different representation. Send the `proxied`
field for TXT only if the API explicitly accepts it. Keep A and AAAA
serialization unchanged.

Use a Cloudflare TTL in the permitted range. The handler currently applies
`DEFAULT_TTL`. It does not use the UPDATE record's TTL. Document that policy. An
API success does not prove that public DNS contains the record.

## 4. Concurrency, retries, and failures

Use shared synchronization for each normalized zone, owner name, and record type
during read-and-write operations. A local race between concurrent additions of
the same value must not cause duplicate records. Operations on different values
must work independently.

A process-local lock does not synchronize multiple bridge instances. Document a
single-writer deployment for the first feature, unless shared coordination is
implemented and tested. Do not claim distributed atomicity from a local mutex.

Return `NOERROR` only after the required API operations succeed. Return an error
for API refusal, timeout, or rate limiting. Report a failure in any part of a
multi-operation UPDATE. Cloudflare API calls do not automatically make the full
DNS UPDATE atomic. Make retries safe and document this adapter limitation.

Return success for cleanup retries and missing records. Do not remove unrelated
records because of a duplicate, API error, or retry. Keep API tokens, TSIG
secrets, and authorization headers out of logs and error responses.

Keep authenticated UDP and TCP support. Keep request IDs, response codes, and
TSIG response signatures. Use dummy credentials for tests. Retrieve deployment
credentials at runtime without command-line arguments or environment files on
disk.

## 5. Integration work in the ACME proxy

The intended public integration is
[acme-proxy/acme-proxy](https://github.com/acme-proxy/acme-proxy). Source
reviewed:
[f005ffa](https://github.com/acme-proxy/acme-proxy/commit/f005ffa4a32b1868976d9c48b504f7b00e8786ec).
These findings apply to that project. Do not add undocumented workarounds to the
bridge for them.

### Cleanup must send the exact value

The proxy's
[RFC 2136 updater](https://github.com/acme-proxy/acme-proxy/blob/f005ffa4a32b1868976d9c48b504f7b00e8786ec/src/signer/relay/dns01.rs)
uses `append` for additions, but `delete_txt` calls
`update_message::delete_rrset`. The cleanup call removes the full record set
rather than the supplied value.

Change the proxy to send class NONE cleanup with the specified TXT RDATA. Use
`update_message::delete_by_rdata` with a TXT `RecordSet`. Check the actual wire
encoding in a test. A stub test of the `DnsUpdater` trait is not sufficient. The
bridge cannot reconstruct the missing value from an empty class ANY request.
This upstream change is necessary for concurrent challenges at one name.

### Public DNS propagation before CA validation

The proxy's
[DNS-01 flow](https://github.com/acme-proxy/acme-proxy/blob/f005ffa4a32b1868976d9c48b504f7b00e8786ec/src/signer/relay/flow.rs)
publishes the record and then triggers CA validation without an explicit DNS
propagation wait in that path. Add or check bounded polling of public TXT
answers before CA validation starts. Keep this wait in the issuer. The bridge
must report API update success without waiting for public propagation.

The updater has a ten-second exchange timeout. The bridge permits fifteen
seconds for each API request. Align the timeout budgets and test slow API
responses. One logical update can use multiple API calls.

### Response authentication needs a check

The reviewed updater checks the response ID and response code but does not
validate the response TSIG in its `send` function. Its UDP path also receives
without checking the sender address. Record response authentication and peer
validation as upstream work. Signed bridge responses alone do not give
verification at the sender.

## 6. Test plan and acceptance criteria

Use a mock Cloudflare API for automated tests. Add an injectable API base URL or
transport at a test boundary. Use dummy accounts for the test suite.

Required cases are:

| Test group  | Required evidence                                                                                                                       |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Permission  | Opt-in disabled rejects TXT. Enabled permits only approved challenge names. Incorrect zone, suffix, type, or TSIG causes no API writes. |
| TXT data    | Accepted single-string ASCII content survives encoding and decoding. Unsupported encoding fails without a panic or API write.           |
| Addition    | Adding a second value keeps the first. Adding the same value again is idempotent.                                                       |
| Cleanup     | Removing one value keeps the other. Missing values are harmless. Full-set TXT removal is refused.                                       |
| Ordering    | Add and cleanup in one UPDATE keep the requested sequence.                                                                              |
| Pagination  | Matching records after page one are found. Removal does not skip records.                                                               |
| Concurrency | Different values survive overlapping operations. Duplicate additions do not cause a local race.                                         |
| Failure     | API errors, timeouts, and rate limits do not give incorrect success or disclose credentials.                                            |
| Protocol    | Signed UDP and TCP updates work. Responses have the expected ID, status, and verifiable TSIG.                                           |
| Regression  | Existing A and AAAA behavior and name restrictions stay covered.                                                                        |
| Integration | Actual proxy wire messages add and remove the exact value. Concurrent orders do not remove each other's records.                        |

The [CI workflow](.github/workflows/ci.yaml) runs formatting, Clippy, a locked
build, and container builds. It does not currently start `cargo test`. Add the
tests to CI.

Do the applicable Rust checks after implementation:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --locked
cargo test --workspace --locked
```

Keep the existing container build checks. Do not publish an image as part of
local validation. After satisfactory mock tests, a controlled staging trial must
check public TXT propagation, issuance, cleanup, and issuance retries. Use
[Let's Encrypt staging](https://letsencrypt.org/docs/staging-environment/)
before production issuance. Record the tested proxy and bridge revisions.
Identify source inspection and executed test results independently.

## 7. Suggested change sequence

The work can use these review units:

1. Refactor the Cloudflare transport and operation dispatch to support isolated
   tests without behavior changes.
2. Add opt-in TXT permissions, parsing, API operations, and tests.
3. Add concurrency controls, pagination, failure tests, and CI test execution.
4. Update the [README](README.md) and configuration examples with the supported
   subset and deployment limits.
5. Send upstream proxy changes independently, then do the integration trial.

Do not copy secrets into examples. Do not change license text as part of this
feature.
