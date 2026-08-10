# Namespace ACL Configuration

## Overview

Codec-server validates user JWT emails against a namespace ACL to grant decode access independent of Temporal Cloud's own RBAC.

## Configuration

### File (production)

Mount ConfigMap `codec-acls` and set:

```bash
NAMESPACE_ACL_FILE=/etc/codec/namespace_acl
```

The file contents use the same format as the env var. codec-server **reloads on every authorize**, so ConfigMap updates apply without a restart.

### Env (local / override)

```bash
NAMESPACE_ACL="email1@example.com=namespace1,namespace2;email2@example.com=namespace3"
```

**Format:** `EMAIL=NS1,NS2;EMAIL2=NS3`
- Semicolon (`;`) separates email→namespace pairs
- Equals (`=`) separates email from its namespaces
- Comma (`,`) separates multiple namespaces per email
- Email lookup is case-insensitive

`NAMESPACE_ACL_FILE` takes precedence over `NAMESPACE_ACL` when both are set.

## In the Platform

Configure in your temporal worker's `deploy/values.yaml`:

```yaml
dependencies:
  temporal:
    type: temporal
    namespace: payments
    codecACL:
      - mchaffe@bitovi.com
      - alice@bitovi.com
```

The platform copies `codecACL` onto `TemporalCloudNamespace.spec.codec.namespaceACL`. A Crossplane `CodecACLAggregator` ExtraResources-selects all such namespaces and writes ConfigMap `codec-acls` for this service.

## Authorization Flow

1. User JWT validated against Temporal Cloud JWKS
2. Email extracted from JWT (`https://saas-api.tmprl.cloud/user/email`)
3. **EmailAuthorizer** checks if email is in any namespace's ACL
   - If found and namespace matches → Allow decode (200)
   - If found but namespace doesn't match → Deny (403)
   - If not found → fallback to JWT `namespaces` claim (if present)
4. If JWT has no claims and email not in ACL → Deny (403)

## Example

**Two workers declaring codec access:**

```yaml
# deploy/values.yaml for payments-worker
dependencies:
  temporal:
    type: temporal
    namespace: payments
    codecACL:
      - mchaffe@bitovi.com
      - alice@bitovi.com

---

# deploy/values.yaml for inventory-worker
dependencies:
  temporal:
    type: temporal
    namespace: inventory
    codecACL:
      - bob@bitovi.com
      - alice@bitovi.com
```

**Resulting ConfigMap `codec-acls` data.namespace_acl:**
```
alice@bitovi.com=inventory,payments;bob@bitovi.com=inventory;mchaffe@bitovi.com=payments
```

**Access:**
- mchaffe: can decode payments
- alice: can decode payments and inventory
- bob: can decode inventory
- charlie: denied for all namespaces (unless JWT namespace claims allow)
