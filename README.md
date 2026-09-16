# Cloudflare DDNS RFC2136 Bridge

This Rust service accepts authenticated RFC2136 updates and sends permitted DNS changes to the Cloudflare API.
It accepts A and AAAA records by default. `ENABLE_ACME_TXT=true` also permits ACME TXT operations.

Architecture:

```text
DHCP server or RFC2136 DDNS client
  -> RFC2136 Dynamic DNS Update
  -> Rust service
  -> Cloudflare DNS API
```

The service has no domain, zone, suffix, credential, or Cloudflare setting compiled into the binary. Runtime configuration comes only from environment variables.

## Supported DNS behavior

These rules apply:

- UDP and TCP DNS listeners.
- RFC2136 UPDATE messages only.
- TSIG authentication is required.
- TSIG failures return REFUSED.
- Only the configured DNS zone is accepted.
- Only records below `ALLOWED_RECORD_SUFFIX` are accepted.
- The bridge rejects zone apex records, wildcard names, and names outside the zone.
- A and AAAA records cannot have an underscore at the start of the first label.
- TXT operations are disabled by default. The ACME policy below controls TXT permissions.
- The bridge rejects all other record types.
- RFC2136 prerequisite sections are refused because the bridge is stateless.

## Environment variables

| Name | Required | Example | Notes |
| --- | --- | --- | --- |
| `LISTEN_UDP` | yes | `0.0.0.0:53` | UDP listener address. |
| `LISTEN_TCP` | yes | `0.0.0.0:53` | TCP listener address. |
| `DNS_ZONE` | yes | `example.internal.` | Accepted zone, fully qualified. |
| `ALLOWED_RECORD_SUFFIX` | yes | `example.internal.` | Accepted owner-name suffix. |
| `CLOUDFLARE_ZONE_ID` | yes | `replace-me` | Cloudflare zone id. |
| `CLOUDFLARE_API_TOKEN` | yes | `replace-me` | Cloudflare API token. Never logged. |
| `DEFAULT_TTL` | yes | `300` | Cloudflare TTL. With ACME enabled: `1` for automatic TTL, or 60 through 86400 seconds. |
| `ENABLE_ACME_TXT` | no | `false` | ACME TXT operations are available only with `true`. |
| `TSIG_KEY_NAME` | yes | `ddns-key.` | TSIG key name. |
| `TSIG_SECRET` | yes | `base64-encoded-secret` | Base64 TSIG shared secret. Never logged. |
| `TSIG_ALGORITHM` | yes | `hmac-sha256` | `hmac-sha256`, `hmac-sha384`, or `hmac-sha512`. |
| `LOG_LEVEL` | yes | `info` | Any valid `tracing_subscriber` env-filter value. |

## ACME DNS-01

With `ENABLE_ACME_TXT=true`, the bridge accepts TXT updates at `_acme-challenge` names.
The first label must equal `_acme-challenge`. DNS name comparisons ignore case.
The owner must be inside `DNS_ZONE` and `ALLOWED_RECORD_SUFFIX` at DNS label boundaries.
For example, `_acme-challenge.host.example.com.` is allowed for `example.com.`.

Other labels cannot start with underscores. Names cannot contain `*`.
A wildcard certificate uses `_acme-challenge.example.com.`, without a wildcard in the record name.

The bridge accepts these TXT operations:

| Class | TTL in UPDATE | Data | Result |
| --- | --- | --- | --- |
| `IN` | 0 through 2147483647 | One ASCII TXT string | Add the value. Keep other values. |
| `NONE` | 0 | One ASCII TXT string | Remove only the specified value. |
| `ANY` | Any | Any | Refuse full-set removal. |

One TXT string can contain a maximum of 255 bytes. The bridge preserves case and whitespace.
The bridge rejects multiple strings and non-ASCII data before API requests.
It also rejects name-wide removal, prerequisites, invalid classes, and invalid TTLs.
The bridge checks the full UPDATE before it changes records.

An addition retry does not duplicate a value that exists. A cleanup retry succeeds when the value is missing.
TXT operations follow the order in the UPDATE. A and AAAA keep their previous replacement behavior.

Cloudflare receives a quoted TXT string with RFC 1035 escapes.
The bridge compares single-string API values after decoding. This comparison also accepts plain values without quotes.
It preserves unsupported multi-string API values.
See the [Cloudflare TXT contract](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/).

The bridge uses `DEFAULT_TTL` for additions. It does not copy the UPDATE TTL.
An existing TXT value keeps its TTL. With ACME enabled, `DEFAULT_TTL` accepts the range that works without an Enterprise account.

## Deployment limits

Use one bridge process as the writer for each Cloudflare zone.
Locks prevent concurrent changes to one record set in one process.
They cannot prevent changes from other processes or external DNS writers.
The Kubernetes example uses one replica and `Recreate` to prevent overlap during deployment.
Service stops while the new process starts.

`NOERROR` means that the required API calls succeeded.
It does not mean that public DNS contains the value.
The issuer must wait for public TXT propagation before certificate validation.
The bridge is a constrained UPDATE adapter. It is not a public authoritative DNS server.

Cloudflare calls do not make a multi-operation UPDATE atomic.
If a subsequent operation fails, earlier changes can stay. The bridge returns `SERVFAIL`.
You can retry TXT additions and value-specific removals after a failure.
API refusal, timeout, invalid responses, and rate limits also return `SERVFAIL`.

Each API request has a fifteen-second timeout. One UPDATE can use multiple API requests and wait for a lock.
The issuer timeout must cover that work. The current proxy timeout is ten seconds and needs correction.

## Proxy integration

The reviewed `acme-proxy/acme-proxy` updater uses `delete_rrset` for cleanup.
The bridge refuses that request because it contains no value to remove.
The proxy must use `delete_by_rdata` with the challenge TXT value.
Public DNS polling, response TSIG verification, UDP peer checks, and timeout changes belong in the proxy.
See the [proxy updater](https://github.com/acme-proxy/acme-proxy/blob/f005ffa4a32b1868976d9c48b504f7b00e8786ec/src/signer/relay/dns01.rs).

Local tests use a mock Cloudflare API, dummy credentials, and signed UDP and TCP messages.
Hickory message-builder tests check value-specific cleanup in DNS packets.
These tests do not prove compatibility with a deployed proxy or public DNS.
A [Let's Encrypt staging trial](https://letsencrypt.org/docs/staging-environment/) must check issuance, propagation, cleanup, and retries before production use.

## Runtime credentials

Supply `CLOUDFLARE_API_TOKEN` and `TSIG_SECRET` through runtime environment variables from your secret-management system.
The TSIG secret must use standard Base64. Configure the same key name, algorithm, and secret in the issuer.
Do not put credentials in command arguments or environment files on disk.
The service does not use external commands for TSIG verification.

## Cloudflare API token

Create a Cloudflare API token scoped to the target zone with:

- Zone: DNS: Edit

Use the resulting token as `CLOUDFLARE_API_TOKEN`, and set `CLOUDFLARE_ZONE_ID` to the target Cloudflare zone id.

## Docker

Build:

```sh
docker build -t cloudflare-ddns-rfc2136:local .
```

Run on port 5353:

```sh
docker run --rm \
  -p 5353:5353/udp \
  -p 5353:5353/tcp \
  -e LISTEN_UDP=0.0.0.0:5353 \
  -e LISTEN_TCP=0.0.0.0:5353 \
  -e DNS_ZONE=example.internal. \
  -e ALLOWED_RECORD_SUFFIX=example.internal. \
  -e CLOUDFLARE_ZONE_ID=replace-me \
  -e CLOUDFLARE_API_TOKEN \
  -e DEFAULT_TTL=300 \
  -e ENABLE_ACME_TXT=false \
  -e TSIG_KEY_NAME=ddns-key. \
  -e TSIG_SECRET \
  -e TSIG_ALGORITHM=hmac-sha256 \
  -e LOG_LEVEL=info \
  cloudflare-ddns-rfc2136:local
```

For container port 53 with a non-root runtime user, grant `NET_BIND_SERVICE` or use Kubernetes security context as shown in `k8s/deployment.yaml`.

## Kubernetes

Supply credentials through your deployment secret-management system. The repository Secret is an example.
Apply the configuration after you supply runtime credentials:

```sh
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

The service manifest exposes both UDP and TCP port 53.

## VyOS DHCP DDNS Example

VyOS 1.5 DHCP server supports RFC2136 DDNS with TSIG. The example below sends forward-domain changes to this bridge. Replace `192.0.2.53` with the service address that routes to the Kubernetes Service or Docker host.

```text
set service dhcp-server dynamic-dns-update
set service dhcp-server dynamic-dns-update send-updates enable
set service dhcp-server dynamic-dns-update conflict-resolution disable
set service dhcp-server dynamic-dns-update tsig-key ddns-key. algorithm hmac-sha256
set service dhcp-server dynamic-dns-update tsig-key ddns-key. secret base64-encoded-secret
set service dhcp-server dynamic-dns-update forward-domain example.internal. key-name ddns-key.
set service dhcp-server dynamic-dns-update forward-domain example.internal. dns-server 1 address 192.0.2.53
set service dhcp-server dynamic-dns-update forward-domain example.internal. dns-server 1 port 53
set service dhcp-server shared-network-name LAN dynamic-dns-update qualifying-suffix example.internal.
```

DDNS accepts A and AAAA forward records. ACME TXT operations use the opt-in policy above.
The bridge rejects reverse domains and PTR records.
