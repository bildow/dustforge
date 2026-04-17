# Decision Trace: Parallel Agent Dispatch Pattern

**Date:** 2026-04-16/17
**Actor:** Claude Code (Opus 4.6, 1M context)
**Category:** code_ergonomics, deployment, merge_tactics

## Pattern: Claude Code as Conductor

Claude Code performs the Conductor role natively via the Agent tool. The pattern is identical to what the platform's deliberation rounds do — decompose, dispatch, merge, audit — but with direct filesystem access.

### How It Works

1. **Decompose** — break work into independent, non-overlapping tasks
2. **Dispatch** — launch 2-3 agents in parallel, each with isolated context and specific file/section instructions
3. **Merge** — agents write to disk, operator verifies syntax, commits as single atomic unit
4. **Audit** — run a review pass (or platform audit round) on the merged output

### Session Stats (2026-04-16/17)

- ~30 agents spawned
- 60+ task cards closed
- 0 merge conflicts reaching production
- 2 syntax failures caught before commit (fixed inline)
- ~15 deployments, zero downtime
- 20 design passes shipped across 6 sprints in one afternoon

## Code Ergonomics

### Decomposition Rules

- Tasks MUST be file-independent or section-independent
- Two agents editing the same function = conflict
- Two agents editing different endpoints in the same 3000-line file = safe if edits don't overlap
- Schema changes (table creation) and endpoint additions are naturally non-overlapping

### Merge Tactics

1. After agents return, run `node --check` for syntax verification
2. `git diff --cached --stat` to review scope of changes
3. Stage and commit as single atomic unit
4. If agents touched overlapping code, resolve manually before commit
5. The merge is implicit — each agent writes to disk sequentially under the hood

### Conflict Resolution

- **Prevention:** assign each agent a different section (e.g., "add K1 schema after silicon_resonance table" vs "add I1 endpoints near line 200")
- **Detection:** syntax check catches most conflicts
- **Observed failure:** Python patch scripts using regex replacement when the target string appears in unexpected locations. Fix: use more specific match strings.
- **Zero conflicts in 30+ agent dispatches this session**

## Deployment Pattern

Every deployment follows the same 4-step sequence:

```
node --check server.js          # 1. syntax gate
git commit -m "..."             # 2. commit (audit trail)
scp server.js root@RackNerd     # 3. deploy
systemctl restart dustforge     # 4. restart + verify health
```

For phasewhip containers:
```
incus file push server.js container/app/server.js
incus exec container -- systemctl restart service
```

**Rules:**
- Never deploy without syntax check
- Never deploy uncommitted code
- Git history IS the audit trail
- Health check after every restart

## Relation to Platform Architecture

This pattern IS the Conductor pattern:

| Aspect | Claude Code | Platform Conductor |
|--------|------------|-------------------|
| Decomposition | Manual task splitting | Round problem_spec |
| Dispatch | Agent tool (subprocess) | OpenRouter API calls |
| Workers | Child Claude instances | Ideation/audit agents |
| Merge | Filesystem + git | Proposal reviews + harvest |
| Trust | Direct filesystem access | Carbon approval gate |
| Audit | Platform audit rounds | Same |

The difference is the trust boundary. Claude Code has filesystem access and can merge directly. Platform agents produce proposals that need human approval. Same pattern, different authorization level.

## Implications for Conductor

The Conductor agent on phasewhip (MiMo V2 Pro, port 8001) should be able to replicate this pattern:
- Accept a decomposed task list
- Dispatch to multiple model calls in parallel
- Merge results with syntax verification
- Return the merged output for operator approval

The platform already has the round infrastructure for this. The gap is: rounds produce proposals (text), not code patches (diffs). Bridging that gap is the Pulse → Task Card → Code pipeline.
