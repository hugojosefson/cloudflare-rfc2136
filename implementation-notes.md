# ACME DNS-01 work record

## Git branch and commits

The fork is [hugojosefson/cloudflare-rfc2136](https://github.com/hugojosefson/cloudflare-rfc2136).
The remote `origin` remains `47star/cloudflare-rfc2136`.
The Git branch `feat/acme-dns01` tracks `hugojosefson/feat/acme-dns01`.
Planning documents have their own commits. Code commits do not include these documents.

## Decisions

These decisions apply:

- Start with the bridge and local mock tests.
- Keep `ENABLE_ACME_TXT` disabled by default.
- Accept one ASCII TXT string. Preserve case and whitespace.
- Reject full-set TXT removal. Cleanup must specify the value.
- Keep A and AAAA replacement behavior.
- Serialize operations for each zone, owner name, and type in this process.
- Use one writer for each zone. Configure one Kubernetes replica and the `Recreate` deployment strategy.
- Return API success without a public DNS propagation wait.
- Keep the PR draft until dev deployment and behavior checks succeed.

## Current state

The requirements document is committed and pushed. Source inspection found no test
deployment or domain. No live credentials were accessed.

The baseline has three tests with no failures.
Refactor commit `94fd93d` adds an injectable API endpoint and listener sockets.
Formatting, Clippy, locked build, and the three tests succeeded.
The TXT implementation has 28 tests with no failures.
Formatting, Clippy, and the locked build succeeded.
The AMD64 and ARM64 container builds succeeded without image publication.

Code commit `22c1133` contains the implementation, 28 tests, and CI test execution.
Documentation commit `ab8125e` describes operations, credentials, proxy limits, and deployment.
YAML parsing succeeded for the changed CI and Kubernetes files.
The Kubernetes example has one replica, `Recreate`, and TXT disabled by default.

Docker is available. `kubectl` and `bd`
are unavailable. This document records follow-up work because `bd` is unavailable.

## Next steps

The remaining work sequence is:

1. Make a draft PR with test results and deployment limits.
2. Correct the proxy code in a different PR.
3. Select the dev target and test domain.
4. Deploy the PR image to dev and record behavior checks.
5. Do the staging trial with the corrected proxy.
6. Keep the PR draft until the dev checks succeed.

## External work

The current [proxy updater](https://github.com/acme-proxy/acme-proxy/blob/main/src/signer/relay/dns01.rs)
uses `delete_rrset`, a ten-second timeout, and no response TSIG verification.
Its UDP socket does not check the sender address.
The [certificate flow](https://github.com/acme-proxy/acme-proxy/blob/main/src/signer/relay/flow.rs)
starts validation immediately after the update.
These findings are from source inspection on 2026-09-16. No proxy integration test
ran. Proxy changes belong in a different PR.

A staging trial needs a public domain controlled by the operator, runtime
Cloudflare credentials, a TSIG key, and a deployment target. We did not identify the target or domain. The trial must check public DNS, certificate issuance, cleanup,
concurrent orders, and retries. Record bridge and proxy revisions.

## API decisions

The [Cloudflare API contract](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/)
specifies quoted TXT strings. Encode one string with RFC 1035 escapes. Accept
quoted or plain single-string responses. Preserve unrelated multi-string values.
Do not send `proxied` for TXT. Keep A and AAAA serialization unchanged.

With ACME enabled, accept `DEFAULT_TTL=1` or 60 through 86400 seconds.
This range works without an Enterprise account. Preserve previous TTL validation
when ACME is disabled.

Each cloned client shares locks. One client has one fixed Cloudflare zone.
The lock key contains the normalized owner and type. Remove lock entries when no task uses them.
Collect all pages before removal. Refuse invalid pagination metadata.

API errors contain operation names, HTTP status, and numeric error codes only.
Remote response text and headers must not go into logs.

## Test evidence

The 28 local tests cover these cases:

- Disabled TXT permissions and invalid zones, suffixes, names, classes, TTLs, and data cause no API requests.
- Invalid TSIG and truncated packets cause no API requests.
- Additions keep other values. Duplicate additions do not make more records.
- Cleanup removes only matching values. Retries preserve other values after a failure.
- All pages are read before removal. Missing or inconsistent pagination causes an error.
- Concurrent client clones share locks across DNS name case and trailing dots.
- Different owners and types have different locks. Cancelled lock waits release their references.
- ASCII bytes, case, whitespace, quotes, and escapes survive round trips.
- API errors and timeouts return signed `SERVFAIL` without credential text.
- UDP and TCP share one client. Response verification succeeds with all three TSIG algorithms.
- A and AAAA parsing, owner restrictions, and replacement serialization have regression tests.
- Hickory builders encode accepted value cleanup and refused full-set cleanup.

These are mock and protocol tests. They do not use the proxy application,
Cloudflare, or a certificate authority.

The local validation commands all succeeded:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --locked
cargo test --workspace --locked
docker buildx build --builder arm64builder --platform linux/amd64,linux/arm64 --output type=oci,dest=/tmp/agents/cloudflare-rfc2136/acme-dns01.oci.tar --metadata-file /tmp/agents/cloudflare-rfc2136/build-metadata.json .
```

The local OCI image index digest is
`sha256:36940556ee119ef628cb95cb42329a6099d93f24104fe78025a1297a7b5d71d4`.
This image was not deployed to dev.
