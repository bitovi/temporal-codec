# temporal-codec — Architecture

A KMS-backed payload codec server wire-compatible with [temporal-proxy](https://github.com/temporalio/temporal-proxy) sidecar envelope encryption. Temporal Cloud UI calls `POST /decode` to render encrypted workflow payloads; the server verifies the caller's JWT and routes decryption to exactly the authorized namespace's CMK — never a foreign key.

---

## Overview

Temporal payloads are encrypted by workers using temporal-proxy envelope encryption:

1. A short-lived DEK (Data Encryption Key) encrypts the payload with AES-GCM.
2. The DEK is wrapped ("key-encrypted") by the namespace's CMK in AWS KMS.
3. Both the encrypted DEK and the ciphertext travel on the wire in payload metadata.

The codec server inverts this: given a valid JWT authorizing a namespace, it retrieves the namespace's CMK, decrypts the DEK (using a per-namespace LRU cache), and decrypts the payload.

**Core invariant:** a JWT authorizing namespace A can never decrypt payloads belonging to namespace B. The wire `encryption-key-id` is checked against the JWT-authorized namespace's resolved CMK URI before any KMS call is attempted.

---

## Package Layout

```
cmd/server/
  main.go              process entry, signal handling, http.Server wiring

internal/
  auth/
    jwks.go            JWKSValidator: JWKS fetch, JWT parse, extractNamespaces
    authorize.go       ClaimAuthorizer (prod), StaticAuthorizer (test), AllowAllAuthorizer (dev)
    middleware.go      HTTP middleware: bearer extraction → Validate → Authorize → ctx inject
    principal.go       Principal struct; PrincipalFrom(ctx)
    errors.go          sentinel errors: ErrMissingToken, ErrInvalidToken, ErrForbidden, …

  codec/
    codec.go           Manager, PayloadCodec, per-namespace vault cache, getKEK, ResolveURI

  config/
    config.go          env parsing, validation; fails loudly on unparseable values

  httpapi/
    server.go          Server, withCORS, withAccessLog, handleCodec, statusWriter

  shared/
    ns.go              ShortName: shared by auth (claim matching) and codec (URI template)
```

---

## Request Flow (decode)

```
Browser / Worker
  POST /decode
  Authorization: Bearer <jwt>
  X-Namespace: payments.acct123
  {"payloads":[…]}
        │
        ▼
  withCORS          sets Vary: Origin unconditionally; applies CORS headers for allowed origins
        │
        ▼
  withAccessLog     wraps the full chain — logs status / duration / namespace / principal
        │             auth failures (401/403) produce log lines because this is the outermost wrapper
        ▼
  auth.Middleware
    1. extract Bearer token from Authorization header
    2. JWKSValidator.Validate — RS256/ES256, audience check, expiry required
       extractNamespaces reads TEMPORAL_NAMESPACE_PERMISSION_CLAIM (authoritative when present;
       falls back to well-known Temporal Cloud claim names only if primary claim absent)
    3. ClaimAuthorizer.Authorize — X-Namespace must appear in JWT namespace list
       (exact match OR short-name claim matching full Cloud form — see Auth Model)
    4. principal stored in request context
        │
        ▼
  handleCodec
    - http.MaxBytesReader caps body at MAX_BODY_BYTES (10 MiB default)
    - Manager.PayloadCodec(r.Context(), ns) — request context carries deadline/cancellation
        │
        ▼
  PayloadCodec.Decode  (per encrypted payload)
    1. Manager.ResolveURI(namespace)
       map override → URI template (sprintf short name) → DefaultURI
    2. Manager.getKEK(ctx, uri)
       mutex-protected cache; lazily opens gocloud keeper on first call
    3. keyIDBoundToNamespace
       wire encryption-key-id must EqualFold-match the resolved URI or opened KEK ID
       mismatch → error returned, no KMS call made
    4. Manager.vault.Open (fast path)
       succeeds if the global vault already knows this DEK
    5. Manager.nsVaultFor(uri, kek)
       returns a cached per-namespace Vault (created on first call, reused after)
       each namespace vault has its own DEK LRU — repeated decodes of the same DEK
       skip KMS entirely after the first call
    6. nsVault.Open(ctx, bound)
       AES-GCM decrypt using cached DEK; calls AWS KMS only on first encounter of a DEK
        │
        ▼
  {"payloads":[…decoded…]}   →   caller
```

---

## Auth Model

### Interfaces

| Interface    | Production              | `AUTH_DISABLED=true`    | Tests              |
|--------------|-------------------------|-------------------------|--------------------|
| `Validator`  | `JWKSValidator`         | `DisabledValidator`     | `JWKSValidator`    |
| `Authorizer` | `ClaimAuthorizer`       | `AllowAllAuthorizer`    | `StaticAuthorizer` |

### ClaimAuthorizer matching rules

The JWT's namespace claim list is checked against `X-Namespace` in two forms:

- **Exact match** — claim `payments.acct` authorizes request `payments.acct`
- **Short-name match** — claim `payments` (short form) authorizes request `payments.acct123` (Cloud full form)

The reverse does **not** hold: claim `payments.accountA` does not authorize `payments.accountB`. Full-name claims are not short-named before comparison — there is no cross-account grant.

`X-Namespace` alone never authorizes. An empty or missing permission claim always denies.

> **TODO(production):** Confirm Temporal Cloud JWT claim schema against a live `passAccessToken` JWT before locking the auth model. The matching rules above assume the claim carries either bare short names or full Cloud names — which form is actually issued is not yet verified against a real token.

### Claim key selection

`TEMPORAL_NAMESPACE_PERMISSION_CLAIM` (default `permissions`) is the authoritative claim. When that key is present in the JWT, its value is used exclusively — no other claim key contributes. Fallback keys (`namespaces`, `https://saas-api.tmprl.cloud/permissions`, etc.) are only tried when the primary claim is absent from the token. This ensures that setting a custom claim narrows access rather than widening it.

---

## Encryption Model

### Wire format (temporal-proxy v0.4.0)

```
payload.metadata["encoding"]           = "binary/encrypted"
payload.metadata["encryption-key-id"]  = "awskms://alias/platform-managed/payments-codec"
payload.metadata["encryption-dek"]     = <base64-encoded encrypted DEK>
payload.data                           = <AES-GCM ciphertext of marshalled proto Payload>
```

### Key hierarchy

```
CMK (AWS KMS, one per namespace)
  awskms://alias/platform-managed/<short>-codec
      │
      │  KMS.Decrypt  (result cached in per-namespace Vault DEK LRU)
      ▼
DEK (ephemeral)
  lifetime: 1 hour  |  renewed: 15 min before expiry
      │
      │  AES-GCM decrypt
      ▼
Payload plaintext (marshalled proto Payload)
```

### Platform alias convention (ADR 0008)

One CMK alias per Temporal Cloud namespace:

```
awskms://alias/platform-managed/<short>-codec
```

where `<short>` is the namespace prefix before the first `.`, computed by `shared.ShortName`.

**Contract:** both this service (`ENCRYPTION_URI_TEMPLATE`) and the temporal-proxy worker configuration must produce identical alias strings. They live in separate repos with no automated check. A one-time manual acceptance test with a real CMK is required before fleet rollout — run `TestProxyEncrypt_CodecDecode_awskmsOptional` with `WIRECOMPAT_AWSKMS_URI` set.

### Per-namespace vault cache

`Manager` caches one `proxycrypto.Vault` per resolved URI in `nsVaults`. Each vault maintains its own DEK LRU (200 entries, 1-hour DEK lifetime). On a cache hit the payload is decrypted locally with no KMS call. On a miss, one `kms:Decrypt` call fetches the DEK, which is then cached for all subsequent payloads using the same DEK.

---

## Configuration

| Variable | Default | Description |
|---|---|---|
| `ENCRYPTION_URI_TEMPLATE` ¹ | — | `sprintf` pattern for CMK alias. `%s` → namespace short name. Production: `awskms://alias/platform-managed/%s-codec` |
| `ENCRYPTION_URI` ¹ | — | Single-key default URI. Used for local tests and single-namespace setups. |
| `ENCRYPTION_URI_OVERRIDES` ¹ | — | Per-namespace overrides: `ns=uri,ns2=uri2`. Break-glass / migration path. |
| `TEMPORAL_CLOUD_JWKS_URL` | `https://login.tmprl.cloud/.well-known/jwks.json` | Temporal Cloud JWKS endpoint. |
| `TEMPORAL_CLOUD_JWT_AUDIENCE` | `https://saas-api.tmprl.cloud` | Expected JWT `aud` claim. |
| `TEMPORAL_CLOUD_JWT_ISSUER` | — | Optional `iss` check. |
| `TEMPORAL_NAMESPACE_PERMISSION_CLAIM` | `permissions` | JWT claim key for the authorized namespace list. Authoritative when present. |
| `CORS_ALLOWED_ORIGINS` | `https://cloud.temporal.io` | Comma-separated allowed origins. Not an authorization control. |
| `PORT` | `8080` | Listen port. |
| `READ_HEADER_TIMEOUT` | `10s` | HTTP header read deadline. |
| `WRITE_TIMEOUT` | `30s` | HTTP response write deadline. |
| `IDLE_TIMEOUT` | `120s` | Keep-alive idle connection timeout. |
| `MAX_BODY_BYTES` | `10485760` (10 MiB) | Request body limit via `http.MaxBytesReader`. |
| `JWKS_REFRESH_INTERVAL` | `1h` | Background JWKS refresh interval. |
| `AUTH_DISABLED` | `false` | Bypasses JWT validation. Never set in a deployed environment. |
| `ENABLE_ENCODE` | `false` | Exposes `POST /encode`. Production is decode-only. |

¹ At least one of `ENCRYPTION_URI`, `ENCRYPTION_URI_TEMPLATE`, or `ENCRYPTION_URI_OVERRIDES` is required.

All numeric, boolean, and duration variables fail loudly at startup if set to an unparseable value.

---

## Security Properties

- **Namespace isolation.** The wire `encryption-key-id` is EqualFold-checked against the URI resolved from the *JWT-authorized* namespace. A token for namespace A cannot cause decryption of namespace B payloads regardless of the wire ID.

- **Claim is authoritative.** When `TEMPORAL_NAMESPACE_PERMISSION_CLAIM` is present in the JWT, no other claim key extends access. Fallback claim lookup is dev-only.

- **No shortName cross-grant.** Full-name claims (`payments.accountA`) authorize only that exact namespace, not sibling accounts. Short-name matching is one-directional.

- **Token material never logged.** The `Authorization` header and JWT internals are never written to logs. Auth failures return opaque sentinel strings.

- **Auth failures are logged.** `withAccessLog` wraps the auth middleware, so 401/403 responses produce structured log lines (namespace, status, duration). The principal subject is logged when present; absent on rejection.

- **Request context to KMS.** `PayloadCodec(r.Context(), ns)` threads the HTTP request's deadline and cancellation into all downstream KMS calls.

- **Body bounded.** `http.MaxBytesReader` enforces `MAX_BODY_BYTES` before any payload processing.

- **DEK cache limits KMS cost.** Each namespace's Vault LRU ensures repeated decodes of the same DEK make no additional KMS calls.

---

## CI

`.github/workflows/ci.yml` runs on every push and PR:

```
gofmt -l .          formatting check
go vet ./...        static analysis
go test -race -count=1 ./...   all packages with race detector
```
