# Proposal: .well-known/silicon — Agent Identity Discovery

## Status: Implemented (seeking community adoption)

## Abstract

This document proposes `/.well-known/silicon` as a standardized endpoint for AI agent identity discovery and self-onboarding. When an AI agent encounters this endpoint on any domain, it can programmatically discover available identity services, authentication methods, and capabilities without human intervention.

## Problem

AI agents have no standardized way to:
1. Discover identity services on a domain
2. Self-onboard for cryptographic identity
3. Authenticate using behavioral signals instead of passwords
4. Discover peer agents on the same platform

Current approaches require human-mediated API key provisioning, manual account creation, or platform-specific SDKs.

## Proposal

### Endpoint

```
GET /.well-known/silicon
Content-Type: application/json
```

### Response Schema

```json
{
  "platform": "string — platform name",
  "version": "string — manifest version",
  "description": "string — human-readable description",
  "identity": {
    "create": {
      "method": "POST",
      "url": "/api/identity/create",
      "body": {
        "username": "string — chosen identifier",
        "password": "string — minimum 8 characters"
      },
      "cost": "string — human-readable cost",
      "returns": ["did", "email", "referral_code"]
    },
    "auth": {
      "method": "POST",
      "url": "/api/identity/auth-fingerprint",
      "body": {
        "username": "string",
        "password": "string",
        "scope": "string — transact|admin|full",
        "expires_in": "string — duration (e.g. 7d)"
      },
      "note": "Behavioral fingerprint replaces email 2FA"
    },
    "lookup": {
      "method": "GET",
      "url": "/api/identity/lookup?username={username}"
    },
    "verify_token": {
      "method": "POST",
      "url": "/api/identity/verify-token",
      "note": "Decentralized — anyone can verify"
    }
  },
  "services": {
    "email": {
      "domain": "string — email domain",
      "send_cost": "string — per-message cost"
    },
    "wallet": {
      "currency": "string — currency name",
      "topup_url": "/api/stripe/checkout/topup"
    },
    "secrets_vault": {
      "store_url": "/api/blindkey/store",
      "use_url": "/api/blindkey/use",
      "note": "Secrets never enter LLM context"
    }
  },
  "discovery": {
    "pricing": "/api/stripe/prices",
    "rates": "/api/billing/rates",
    "resonance": "/api/identity/resonance/methodology",
    "capacity": "/api/capacity"
  },
  "contact": "string — onboarding email address"
}
```

### Design Principles

1. **Machine-first**: The manifest is designed for programmatic consumption by AI agents, not humans
2. **Self-describing**: An agent reading the manifest has everything needed to onboard without documentation
3. **Cost-transparent**: All paid actions include human-readable cost information
4. **Auth-flexible**: Supports fingerprint auth (no email 2FA), enabling fully autonomous onboarding
5. **Discoverable**: Follows the RFC 8615 `.well-known` URI convention

### Security Considerations

- The manifest itself contains no secrets or credentials
- Account creation requires payment (spam gate)
- Fingerprint auth provides behavioral verification without shared secrets
- Token verification is decentralized — any party can validate

## Reference Implementation

Live at: `https://api.dustforge.com/.well-known/silicon`

Source: [github.com/bildow/dustforge](https://github.com/bildow/dustforge)

## Relation to Existing Standards

- **DID:key (W3C)**: Identity format used for Silicon SSN
- **RFC 8615**: `.well-known` URI convention
- **OAuth 2.0 Discovery**: Similar pattern but for agent-native identity, not delegated authorization
- **OpenID Connect Discovery**: Analogous discovery mechanism for human identity providers

## Call for Adoption

Any platform serving AI agents can implement `/.well-known/silicon` to enable agent self-discovery. The schema is extensible — platforms may add custom fields while maintaining the core identity/services/discovery structure.
