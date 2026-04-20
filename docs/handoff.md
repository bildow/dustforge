# Dustforge — Session Handoff

## Machine Brief

| Field | Value |
|-------|-------|
| **Last commit** | `27485a7` — Phasewhip admin panel |
| **Branch** | `main` — `bildow/dustforge` |
| **Deployed** | Netlify + RackNerd LIVE. Phasewhip admin on 9190. |
| **Status** | All products live with SSL. Lori on Conductor. Buoy tick types deployed. |

## What Shipped This Session (2026-04-20)

### Infrastructure — 5 domains live with HTTPS
- **dustforge.com** — Netlify, main site + vault dashboard
- **api.dustforge.com** — RackNerd, API server (deployed with all new code)
- **demipass.com** — RackNerd, product landing page, SSL cert live
- **buoy.dustforge.com** — RackNerd, product landing page, SSL cert live
- **civitasvox.com** — RackNerd, placeholder, SSL cert live

### Brain Audit Fixes (3 findings from this session)
- `791ab8e` — Chrono SSRF prevention (HTTPS-only, private network blocked, metadata blocked, validated at create + fire time)
- `791ab8e` — Chrono tick chain integrity (auto-ticks use full pipeline: chain hash, billing, referral)
- `791ab8e` + `f579d08` — Lori invite key flow + query string fix (url.pathname → url.pathname + url.search)

### Card 220: Lori Conductor Wrapper
- `71fa458` — Lori routes LLM through Conductor (MiMo V2 Pro) as primary, OpenRouter DeepSeek V3.2 as fallback
- Context enrichment: gathers project names + sender info before LLM call
- Health endpoint shows Conductor status and LLM backend info
- Tested live: natural language responses working through Conductor

### Buoy (temporal anchor product)
- `9b93243` — Tick types: begin, complete, handoff, audit, decision, block, unblock, alert
- ref_tick cross-references for linked chains (handoff → begin)
- tags field for card/repo correlation
- `5e9bed3` — Buoy landing page at buoy.dustforge.com
- Vault dashboard Buoy tab: tick chain ledger, chrono trigger management, chain verification
- Buoy MCP server in demipass@1.1.0

### DemiPass
- `59a6802` — Landing page at demipass.com
- `369261b` — demipass@1.1.0 published (includes Buoy MCP server)
- e2e test: 9/9 pass (store→context→token→rotate→revoke)

### Rowen Egress Expansion (bildow/rowen repo, NOT dustforge/rowen-server.js)
- `c74d223` in **bildow/rowen** `egress/server.js` — 4 new action types: document, http_body, env_inject, smtp_auth
- Total: 6 action types in the standalone rowen repo
- NOTE: dustforge/rowen-server.js is the older monolithic version and only has http_header + ssh_exec. The standalone bildow/rowen repo is the source of truth for egress.

### Other
- 36 authoritative @dustforge.com emails reserved on production (legal, support, admin, etc.)
- Phasewhip admin panel at http://100.83.112.88:9190 (container health + Lori chat)
- Flowhook registered, enrolled, phone online (temporary patch from Kyle)
- TOS v3 canonical at /terms.html, handoff accuracy fixes

## Repos

| Repo | Latest | Status |
|------|--------|--------|
| bildow/dustforge | 27485a7 | Netlify + RackNerd LIVE |
| bildow/demipass | 369261b | npm 1.1.0 LIVE |
| bildow/rowen | c74d223 | Deployed on phasewhip |
| bildow/tome | 2b6ec09 | Session logged |

## For Brain's Audit

### Verify new since last audit:
1. **Chrono SSRF fix** — POST /api/chrono/create rejects non-HTTPS, private networks, metadata endpoints. Fire-time re-validation blocks pre-existing unsafe targets.
2. **Chrono tick chain fix** — auto-ticks use computeTickHash, billing, referral accumulator (not raw INSERT)
3. **Lori Conductor wrapper** — health endpoint shows `llm.primary: "conductor (MiMo V2 Pro)"`, `primary_status: "live"`. Send a natural language message via POST /api/conduit/inbound and verify Conductor processes it.
4. **Buoy tick types** — POST /api/tick with `type`, `ref_tick`, `tags` fields. Verify chain_hash includes the type in computation. Verify ref_tick links work.
5. **Egress action types** — document, http_body, env_inject, smtp_auth in **bildow/rowen** repo at `egress/server.js` (commit `c74d223`), NOT in dustforge/rowen-server.js (which is the older monolithic version). Verify honeypot traps fire on unapproved hosts for http_body. Verify document returns plaintext to caller.
6. **demipass.com HTTPS** — valid cert, serves landing page
7. **buoy.dustforge.com HTTPS** — valid cert, serves landing page
8. **36 reserved emails** — `GET /api/identity/lookup?username=legal` returns status=reserved
9. **Lori query string fix** — dustforgeRequest uses `url.pathname + url.search` (was dropping query params)

### Known issues (not bugs, just status):
- TOS v3 still has "prepared without legal counsel" disclaimer and 72h breach notice — intentional pending Brain's v4 push
- Phasewhip admin container status shows "unknown" (needs root for full incus status, health checks work)
- Flowhook phone connection is Kyle's temporary patch, not permanent

## Open Task Cards
- DemiPass Android wallet APK (blocked: JDK install needs sudo)
- Brain TOS v4 via DemiPass document courier (blocked: Brain needs to push v4 via git)
- npm 2FA re-enable (blocked: desktop browser)
- Recursive adversarial audit cycle on DemiPass document courier (planned)
