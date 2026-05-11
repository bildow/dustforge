---
name: Progressive rendering workflow — foundational platform philosophy
description: All platform work uses progressive passes, not linear task slices. Errors are tracked not blocked. The gemstone metaphor. This is THE default for all rounds, deliberation, collaboration, and auditing.
type: project
---

## Progressive Rendering Workflow (decided 2026-04-25)

This is the foundational philosophical framing for ALL work on the silicon carbon platform.

### The Model

Software features are rendered progressively, like the old interlaced image loading:

| Pass | Analogy | What happens | Error handling |
|------|---------|-------------|----------------|
| **1 — Rough** | Blocky grid | Every feature exists as a stub. Shape is visible. Nothing works e2e. | Errors expected and logged |
| **2 — Scaffold** | Blurry render | Wiring connects stubs. Features are rough but functional. | Errors tracked, not fixed |
| **3 — Lattice** | Sharpening | Batch fixes — one fix eliminates multiple bugs sharing a root cause | Systemic errors prioritized |
| **4 — Cut** | Gemstone facets | Individual feature refinement. Remaining errors are isolated. | Targeted fixes |
| **5 — Polish** | Fine adjustment | The current audit/fix workflow. Brain audits, findings fixed, re-verified. | Zero-tolerance on remaining issues |

### Key Principles

1. **Passes not slices** — don't finish one feature before starting the next. Render ALL features at the same resolution, then increase resolution for all.
2. **Errors are data, not blockers** — track them across passes. The pattern of errors tells you what to fix next, not any single error.
3. **Batch elimination** — prioritize the pass/fix that eliminates the MOST tracked errors simultaneously.
4. **The gemstone metaphor** — geological process (rough creation) → shaping (cutting facets) → polishing (fine adjustment). Each stage has different tools and tolerances.

### Where This Applies

- **Brain's autonomous loop** — the claims ledger scores feature-map passes, not individual tasks
- **Claude ↔ Brain workflow** — collaborative passes at the right resolution level
- **Platform rounds** — deliberation, collaboration, auditing all use this framing
- **The current audit workflow IS Pass 5** — it's preserved, not replaced. It's the fine-polish stage.

### How Brain Should Implement This

Brain's scorer should evaluate: "which pass across the feature map eliminates the most tracked errors?" Not "which single task is highest priority."

The claims ledger holds the error map. Each pass produces observations about what improved and what didn't. The scorer ranks the NEXT pass based on cumulative error reduction, not individual bug severity.

### Articulation → Health: The Design-to-Construction Bridge

Nodes have two lifecycle phases. In **design phase**, they carry an articulation percentage — how well-formed is the solution. In **construction phase**, they carry a health percentage — how built is the implementation.

The bridge between them:

| Articulation % | Meaning | Action | Resulting Pass Level |
|---------------|---------|--------|---------------------|
| 0-25% | Raw intuition, unnamed tension | Ideation round: name it, find analogs | Not yet a node |
| 25-50% | Tension identified, options generated | Audit round: test feasibility | Pass 1 (rough stub) |
| 50-75% | Solution selected, magic numbers remain | Hybridized round: strip magic numbers, find spanning insights | Pass 1-2 |
| 75-90% | Architecture locked, parameters derived | Build it. Stop ideating. | Pass 2-3 |
| 90-100% | Implementation detail only | Execute, test, deploy | Pass 3-5 |

**Serendipity potential = 100 - articulation.** When serendipity is high (>25%), don't iterate on the current solution. Strip to first principles, find the biological/sociological analog, map back. The breakthrough comes from outside the current frame.

See [inspiration-methodology.md](../../project/dustforge/docs/inspiration-methodology.md) for the full serendipity methodology.

### Node Health (Construction Phase)

Once a node crosses from design into construction (articulation >= 75%), it gets a health score:

| Health | Meaning |
|--------|---------|
| 0 | Spec only — design complete, nothing built |
| 1-25 | Stub exists — table created, route registered, no logic |
| 25-50 | Scaffold — wiring connects to other nodes, rough but functional |
| 50-75 | Lattice — systemic fixes applied, works in production |
| 75-90 | Cut — individual refinement, edge cases handled |
| 90-100 | Polish — audited, tested, production-proven |

Health maps directly to passes:
- Pass 1 (rough) → health 1-25
- Pass 2 (scaffold) → health 25-50
- Pass 3 (lattice) → health 50-75
- Pass 4 (cut) → health 75-90
- Pass 5 (polish) → health 90-100

### The Scorer

What to build next = the node whose NEXT PASS produces the most:
1. Error reduction across the map (not just this node)
2. Dependency unlocks (other nodes blocked by this one)
3. Serendipity consumption (high-serendipity nodes resolved)

This is the topological inspiration scorer applied to construction.

### DO NOT

- Do not eradicate the current linear audit process — it's Pass 5
- Do not treat errors as blockers during Passes 1-3
- Do not prioritize single-feature completion over broad-pass completion
- Do not build nodes that are still below 75% articulation — ideate more first
- Do not keep ideating on nodes above 90% articulation — build them
