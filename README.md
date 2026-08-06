# temporal-codec

Platform **Codec Server** for Temporal Cloud UI/CLI **decode**, designed to
ADR 0008 in `bitovi-platform-services`:

`docs/architecture/adr/0008-temporal-cloud-codec-server.md`

This service is a **shared band-30 platform app** (not per-team). Workers encrypt via
**temporal-proxy** + `awskms://`; the UI calls this HTTP codec for on-demand decrypt.

| Legacy `codec-server` (static AES) | This repo |
| --- | --- |
| Static key AES, not proxy-compatible | temporal-proxy **envelope** + KMS URIs |
| Not safe for multi-tenant Cloud UI | Namespace-bound JWT authz (v1) |

Pin for wire-compat: **`github.com/temporalio/temporal-proxy v0.4.0`** (`pkg/crypto`).
Payload metadata matches `internal/proxy/encryption.go` (`binary/encrypted`,
`encryption-key-id`, `encryption-dek`).

**Implementation location:** lab/MVP lives under `pocs/temporal-codec` until
promoted to `bitovi/temporal-codec` (GitHub + ECR).

## HTTP surface (product)

Temporal Cloud UI only needs **decode**. Encode is not required on this server.

| Route | Auth | Role |
| --- | --- | --- |
| `POST /decode` | JWT + namespace authz | Primary UI path (only production codec route) |
| `GET /health` | none | k8s liveness/readiness |
| `POST /encode` | off by default | Local/debug only when `ENABLE_ENCODE=true` |

`crypto`/adapter `Encode` remains available to tests (codec-internal round-trip
and payload wiring); production listen path is **decode-only**.

Body shape: Temporal `converter.NewPayloadCodecHTTPHandler` JSON `{"payloads":[...]}`.

## Authn / Authz (v1)

1. **Never trust `X-Namespace` alone.** It is client-supplied.
2. Expect `Authorization: Bearer <Temporal Cloud access token>` when Cloud
   Namespace has `passAccessToken: true`.
3. Validate JWT against JWKS (`TEMPORAL_CLOUD_JWKS_URL`, default
   `https://login.tmprl.cloud/.well-known/jwks.json`).
4. Audience default: `https://saas-api.tmprl.cloud` (Temporal docs).
5. **Namespace-bound authz:** token must list the requested namespace under
   claim `permissions` (override with `TEMPORAL_NAMESPACE_PERMISSION_CLAIM`)
   or provisional claim keys documented in code. Denied → **403**, no KMS unwrap.
6. CORS allows `https://cloud.temporal.io` for browser preflight only — **not** authz.

### Claims check (how it works + TODO)

| Step | Behavior |
| --- | --- |
| Signature / exp / aud | `jwks` + `jwt.MapClaims` via MicahParks keyfunc |
| Principal | `sub` (required); optional `email` |
| Namespaces | string list from permission claim(s) |
| Match | Exact or short-name vs Cloud form `name.accountId` |

**TODO (production claim verification):** Confirm against a live Temporal Cloud
`passAccessToken` JWT which claim(s) enumerate Namespace membership/roles. Until
that is verified with a real token, production deploy must not rely solely on a
guessed claim name; interfaces are in place so a verified provider can replace
`ClaimAuthorizer` / claim extractors without changing HTTP. Unit tests cover
deny-wrong-namespace and allow-authorized-namespace with a mocked JWKS.

## Encryption (wire-compat)

- Imports `github.com/temporalio/temporal-proxy/pkg/crypto` (Vault + KEK + gocloud).
- Payload adapter mirrors temporal-proxy encrypt/decrypt visitors (not SDK static AES).
- **Per Temporal Cloud namespace CMK** (platform):
  `awskms://alias/platform-managed/<short>-codec` (TCN Composition).
- `ENCRYPTION_URI_TEMPLATE` — production fleet default:
  `awskms://alias/platform-managed/%s-codec` (sprintf of Cloud short name after JWT authz).
- `ENCRYPTION_URI_OVERRIDES` — optional `ns=uri,ns2=uri2` map (tests / break-glass).
- `ENCRYPTION_URI` — single-key fallback for local/`testing://` only.
- **Decode is namespace-bound:** after JWT authz for the requested Namespace,
  only that namespace's key may unwrap. Foreign `encryption-key-id` values are
  rejected (never open arbitrary wire KEKs under fleet-reader IRSA).
- X-Namespace alone never authorizes (middleware); key selection also uses only
  the JWT-bound namespace string.

### Wire-compat tests

CI proves **proxy-encrypt → codec-decrypt** without calling codec `Encode`:

```bash
go test ./internal/codec/ -run ProxyEncrypt_CodecDecode_wireCompat -count=1
```

`TestProxyEncrypt_CodecDecode_wireCompat` seals via `pkg/crypto` with the same
metadata keys as temporal-proxy `encryptPayloads`, then decodes with
`codec.Manager` (Cloud UI path). Uses `testing://` for determinism.

Optional KMS acceptance (ADR gate 1):

```bash
WIRECOMPAT_AWSKMS_URI='awskms://alias/platform-managed/<ns>-codec' \
  go test ./internal/codec/ -run awskmsOptional -count=1
```

### IRSA expectations (cluster)

| Who | Scope |
| --- | --- |
| temporal-codec SA | `kms:Decrypt` (unwrap) on keys tagged `Purpose=temporal-codec` (fleet reader) |
| Workers / temporal-proxy | Encrypt+Decrypt scoped to `TemporalNamespace=<name>` |

No long-lived CMK material in env secrets; default AWS credential chain / IRSA.

## Token sink

Never log: `Authorization`, raw JWTs, request/response payload bodies, DEKs.

Structured access logs: status, duration, namespace, principal `sub` only.

## Multi-replica

Stateless process. Ready means process up + codec manager + JWKS client
initialized (when auth enabled). Readiness does **not** require every Namespace
CMK to exist.

## Local run

Requires Go **1.26.4+** (pulled via `GOTOOLCHAIN=auto` if needed).

```bash
cp .env.example .env
# AUTH_DISABLED=true and ENCRYPTION_URI=testing://... for local

export $(grep -v '^#' .env | xargs)
go run ./cmd/server
# GET http://localhost:8080/health
# POST /decode only (no /encode unless ENABLE_ENCODE=true)
```

Docker:

```bash
docker build -t temporal-codec:dev .
docker run --rm -p 8080:8080 \
  -e ENCRYPTION_URI='testing://KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=' \
  -e AUTH_DISABLED=true \
  temporal-codec:dev
```

## Tests

```bash
export GOTOOLCHAIN=auto   # if local go < 1.26.4
go test ./...
go build -o /tmp/temporal-codec ./cmd/server
```

## Env reference

| Variable | Default | Notes |
| --- | --- | --- |
| `PORT` | `8080` | Listen |
| `LOG_LEVEL` | `info` | debug/info/warn/error |
| `ENCRYPTION_URI` | required | `awskms://` or `testing://` |
| `ENCRYPTION_URI_OVERRIDES` | empty | `ns=uri,...` |
| `TEMPORAL_CLOUD_JWKS_URL` | Cloud JWKS | Public HTTPS |
| `TEMPORAL_CLOUD_JWT_AUDIENCE` | saas-api audience | |
| `TEMPORAL_CLOUD_JWT_ISSUER` | empty | Optional issuer pin |
| `TEMPORAL_NAMESPACE_PERMISSION_CLAIM` | `permissions` | Claim for ns list |
| `CORS_ALLOWED_ORIGINS` | `https://cloud.temporal.io` | CSV |
| `AUTH_DISABLED` | `false` | Local only |
| `ENABLE_ENCODE` | `false` | Expose `POST /encode` (debug only) |

## Acceptance gates (from ADR 0008)

Use this as the checklist when promoting beyond MVP:

1. **Wire-compat** — Decode a real temporal-proxy `awskms://` payload against KMS
   with this binary (`WIRECOMPAT_AWSKMS_URI` test; not only `testing://` unit tests).
2. **Namespace authz** — Valid JWT for ns A + `X-Namespace` for ns B → 403, no KMS.
   Authorized principal → decode succeeds.
3. **Fail-closed encrypt** — Worker/proxy path (not this service): broken CMK must not
   write cleartext to Cloud history.

## Platform (bitovi-platform-services)

When wired:

1. `gitops/apps/temporal-codec.yaml` — Argo wave **30**, multi-source interface pointing
   at `https://github.com/bitovi/temporal-codec` (after promote from `pocs/`).
2. Capability **`temporal-codec-reader`** — fleet Decrypt IRSA on `Purpose=temporal-codec`.
3. TCN Composition registers `codecServer.endpoint=https://temporal-codec.bitovi-tools.com`
   + `passAccessToken: true` (when `spec.codec.enabled`, default true).

## Layout

```
cmd/server/main.go
internal/config/
internal/auth/      # JWKS, claims authz, middleware
internal/codec/     # temporal-proxy pkg/crypto + payload wire adapter
internal/httpapi/   # routes (decode-only), CORS, token-safe logs
deploy/values.yaml  # platform interface sketch
Dockerfile
```
