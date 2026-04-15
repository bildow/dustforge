# Credential & Token Inventory

Last updated: 2026-04-14

## Production Secrets

| Secret | Location | Rotation | Backup |
|--------|----------|----------|--------|
| IDENTITY_MASTER_KEY | civitasvox /app/.env + RackNerd /opt/dustforge/.env | No rotation plan | Daily backup to /opt/dustforge/backups/ |
| ENCRYPTION_KEY | civitasvox /app/.env | No rotation plan | Not backed up separately |
| PLATFORM_SECRET | Generated at runtime (random) | Regenerates on restart | Not persisted — tokens invalidated on restart |
| STRIPE_SECRET_KEY | civitasvox /app/.env | Stripe dashboard | Not backed up |
| STRIPE_WEBHOOK_SECRET | civitasvox /app/.env | Stripe dashboard | Not backed up |
| OPENROUTER_API_KEY | civitasvox /app/.env | OpenRouter dashboard | Key: sk-or-v1-b3f4... (Aaron's) |
| CONDUIT_CARBON_TOKEN | civitasvox /app/.env | Manual | lxom4qW_... |

## Access Tokens

| Token | Type | Expires | Notes |
|-------|------|---------|-------|
| npm (dustforge-agent-sdk) | Granular access | 2026-07-07 | Published as gnomishplumber |
| GitHub PAT | Classic | Unknown | ghp_HsP... (used for git push) |
| Codex CLI OAuth | ChatGPT Plus | ~10 days (auto-refresh) | Stored in brain /root/.codex/auth.json |

## Platform Tokens (new)

| Account | Token | Label |
|---------|-------|-------|
| 1 (Civitasvox) | 96815f...d67e | aaron-primary |
| 2 (Fat Tacos) | 89356...c737 | fat-tacos-test |

## Infrastructure Access

| Host | Method | Credential |
|------|--------|-----------|
| RackNerd (192.3.84.103) | SSH root | zl46bv... |
| RackNerd panel | Web | vmuser296962 / 5CcEA... |
| Kyle machines (k1, ky7) | SSH claude | subwayeatfresh |
| Phasewhip | SSH claude | subwayeatfresh |

## Critical Risks

1. **PLATFORM_SECRET not persisted** — tokens invalidated on every restart. Need to add to .env.
2. **IDENTITY_MASTER_KEY** — single key, hardware HSM recommended (Nitrokey, $120)
3. **npm token expires Jul 7 2026** — calendar reminder needed
4. **GitHub PAT** — expiration unknown, check Settings > Developer settings
