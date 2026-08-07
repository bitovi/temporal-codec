# Namespace ACL Configuration

## Overview

Codec-server validates user JWT emails against a namespace ACL to grant decode access independent of Temporal Cloud's own RBAC.

## Configuration

Set `NAMESPACE_ACL` environment variable:
```bash
NAMESPACE_ACL="email1@example.com=namespace1,namespace2;email2@example.com=namespace3"
```

**Format:** `EMAIL=NS1,NS2;EMAIL2=NS3`
- Semicolon (`;`) separates email→namespace pairs
- Equals (`=`) separates email from its namespaces
- Comma (`,`) separates multiple namespaces per email
- Email lookup is case-insensitive

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

The platform generates the `NAMESPACE_ACL` env var for the codec-server automatically from all temporal dependencies' `codecACL` lists.

## Authorization Flow

1. User JWT validated against Temporal Cloud JWKS
2. Email extracted from JWT (`https://saas-api.tmprl.cloud/user/email`)
3. **EmailAuthorizer** checks if email is in any namespace's ACL
   - If found and namespace matches → ✅ Allow decode (200)
   - If found but namespace doesn't match → ❌ Deny (403)
   - If not found → fallback to JWT `namespaces` claim (if present)
4. If JWT has no claims and email not in ACL → ❌ Deny (403)

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

**Resulting codec-server config:**
```
NAMESPACE_ACL="mchaffe@bitovi.com=payments;alice@bitovi.com=payments,inventory;bob@bitovi.com=inventory"
```

**Access:**
- mchaffe: can decode payments ✅
- alice: can decode payments and inventory ✅
- bob: can decode inventory ✅
- charlie: denied for all namespaces ❌
