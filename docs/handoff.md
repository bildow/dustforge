# Dustforge — Session Handoff

## Machine Brief

| Field | Value |
|-------|-------|
| **Last commit** | `83c2de3` — Handoff checkpoint |
| **Branch** | `main` — `bildow/dustforge` |
| **Deployed** | **LIVE** on RackNerd (192.3.84.103) |
| **Status** | Brain audit fixes deployed. DemiPass + Rowen split into standalone repos. |

## Repo Split (2026-04-18)

| Repo | Purpose | Status |
|------|---------|--------|
| `bildow/dustforge` | Identity platform + API (DID:key, wallet, fleet, fingerprint) | Live at api.dustforge.com |
| `bildow/demipass` | Standalone secrets SDK + MCP server for Claude Code | Initial commit `adeb830` |
| `bildow/rowen` | Bonded courier — ingress/egress split, namespace-deployable | Initial commit `a340463` |
| `bildow/civitasvox` | Platform observatory (task boards, rounds, traces) | Live at 100.83.112.88:3000 |
| `bildow/civitasvox-site` | Under construction page for civitasvox.com | Deployed to Netlify |

## DemiPass Standalone (demipass.com purchased)

- `index.js` — 233-line SDK, zero deps, 14 exported functions (store, use-tokens, delegation, rotation, audit)
- `mcp-server.js` — 199-line MCP server for Claude Code (5 tools via JSON-RPC stdin/stdout)
- `.env.example` — DEMIPASS_URL, DEMIPASS_TOKEN, DEMIPASS_ADMIN_KEY
- Currently points at Dustforge API — standalone DemiPass server TBD

## Rowen Split

- `ingress/server.js` — receives secrets, encrypts into DemiVault, wipes memory. Port 3002.
- `egress/server.js` — dual-barrel closing table, SecretDose (30s hard kill), heartbeat supervision. Port 3003.
- `shared/crypto.js` — HMAC-SHA256 auth between services
- `shared/config.js` — namespace-aware env loading (NAMESPACE_ID per customer)
- `shared/audit.js` — fire-and-forget logging to DemiPass API
- Each customer namespace gets own ingress + egress with unique HMAC keys

## Brain Audit Fixes (commit 7f592cc, deployed)

1. Lori auth gate — requireLoriAuth on mutation routes
2. Admin delegation-chain — requires did/username, no cross-tenant
3. Rowen host policy — unified to BLINDKEY_HTTP_HOSTS
4. SDK URL — raw.githubusercontent.com (JS, not HTML)
5. Handoff — this document

## Containers on Phasewhip (7 running)

| Container | IP | Port | Service |
|-----------|-----|------|---------|
| brain | 10.225.75.22 | 8002 | Conductor gateway |
| chad | 10.225.75.165 | — | Fitness agent |
| civitasvox | 10.225.75.198 | 3000 | Platform |
| conductor | 10.225.75.95 | 8001 | MiMo V2 Pro |
| lori | 10.225.75.121 | 3003 | Platform assistant (needs Conductor wrapper) |
| mail | 10.225.75.76 | 8090 | Stalwart |
| rowen | 10.225.75.34 | 3002 | Auth keeper (stub — real code in bildow/rowen) |

## Critical Path

1. ~~Fix Brain's 5 audit findings~~ DONE
2. ~~Split DemiPass to standalone repo~~ DONE
3. ~~Split Rowen to standalone repo~~ DONE
4. Deploy Rowen ingress/egress to container
5. DemiPass delivery test (Brain uses OpenRouter key via use-token)
6. Lori Conductor wrapper (card 220) — real LLM personality
7. npm publish demipass
8. demipass.com landing page
9. AdWords unpause

## Task Cards Created This Session

- 232: Carbon onboarding via silicon — inverted SaaS
- 233: Sandbox demo mode
- 234: Degraded state — silicon recruits its carbon
- 235: DemiPass MCP Server for Claude Code
- 239: Session health barometer
- 240: Session flight recorder database
- 241: DemiPass standalone product at demipass.com
- 242: DemiPass MCP Server (duplicate of 235 — consolidate)

## Known Issues

- Incus socket exhaustion on phasewhip (recurring)
- Brain Matrix messages fail to render in Element (HTML formatting)
- Lori dashboard chat panel too small (needs CSS fix)
- Lori uses regex intent parsing, not LLM (card 220)
- gh auth expired — use GitHub API with git credential token
