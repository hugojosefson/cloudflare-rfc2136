# ACME DNS-01 work record

## Branch and commits

The fork is [hugojosefson/cloudflare-rfc2136](https://github.com/hugojosefson/cloudflare-rfc2136).
The remote `origin` remains `47star/cloudflare-rfc2136`.
The branch `feat/acme-dns01` tracks `hugojosefson/feat/acme-dns01`.
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

The Rust baseline test is in progress. Docker is available. `kubectl` and `bd`
are unavailable. This document records follow-up work because `bd` is unavailable.

## Next steps

The work sequence is:

1. Refactor transport construction and change dispatch for mock tests.
2. Add TXT permissions, decoding, addition, cleanup, pagination, and synchronization.
3. Add failure, concurrency, protocol, and regression tests. Add tests to CI.
4. Update permanent documentation and configuration examples.
5. Execute Rust checks and container builds. Commit and push each checkpoint.
6. Make a draft PR with test results and deployment limits.

## External work

The current [proxy updater](https://github.com/acme-proxy/acme-proxy/blob/main/src/signer/relay/dns01.rs)
uses `delete_rrset`, a ten-second timeout, and no response TSIG verification.
Its UDP socket does not check the sender address.
The [certificate flow](https://github.com/acme-proxy/acme-proxy/blob/main/src/signer/relay/flow.rs)
starts validation immediately after the update.
These findings are from source inspection on 2026-09-16. No proxy integration test
ran. Proxy changes belong in a different PR.

A staging trial needs a public domain controlled by the operator, runtime
Cloudflare credentials, a TSIG key, and a deployment target. The target and domain remain unidentified. The trial must check public DNS, certificate issuance, cleanup,
concurrent orders, and retries. Record bridge and proxy revisions.
