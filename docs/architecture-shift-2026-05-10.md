# Architecture Shift: DemiPass as Kernel
## Date: 2026-05-10

## The Shift

DemiPass is not a product on the platform. DemiPass is the kernel the platform needs to function. Every agent needs credentials. Every credential operation needs the oracle, behavioral surface, and jury pool. The platform can't run without DemiPass. DemiPass can run without the platform.

### Modularization Line
- **DemiPass**: ships standalone. Oracle, behavioral surface, security events, use-token, blind rotation, invitation graph. This is the base layer.
- **Carbon Silicon Platform**: adorns DemiPass. Accounts, projects, silicon provisioning, task boards, UI. Built on top, not beside.
- **Deliberation Engine**: belongs to the platform (CivitasVox), not to DemiPass. Generates detection functions through expansion/contraction cycles. Feeds the jury pool.

### Why Not Rewrite
DemiPass at 10,000+ lines with accumulated fixes IS the deliberation trace. A clean rewrite from the methodology would converge on similar code from a different angle — more rational path, same destination. The rational case for rewriting is not DemiPass itself but extracting it cleanly as the modular base, then building the platform layer as new code with the methodology from day one.

The platform's greatest customer is itself — it needs DemiPass to function.

## The Deliberation Engine

### Expansion/Contraction Rhythm
Deliberation rounds breathe:
1. **Expand** — ideation, explore the space, generate options
2. **Contract** — audit, extract only what survives scrutiny
3. **Expand** — spanning insight detection, does this resolve multiple tensions?
4. **Contract** — feasibility, integrity check, does it stand?
5. **Merge** — hybridized round, refined product becomes the next path

This is not a linear pipeline. It's a breathing rhythm. Passive merging — the refined outputs naturally converge without forced integration.

### Two Engines, One System

**Deliberation Engine (blue):** Studies past behavioral data and attack patterns. Produces new detection functions (statistical tests, canary patterns, behavioral thresholds). Output: new jurors for the rotating pool. Expansion-oriented — exploring what defenses are needed.

**Shadow Engine (red):** Studies the detection functions the deliberation engine produces. Attempts to craft inputs that bypass them. Every bypass becomes training data for the next deliberation cycle. Contraction-oriented — pruning weak defenses before deployment.

### Cooperative Framing, Not Adversarial

CRITICAL: The shadow engine is NOT an adversary. It is a cooperative partner within the same system. The framing must be serial (cooperative), not zero-sum (adversarial). Both engines serve the same goal: system integrity.

The analogy is thymic selection in the immune system — the thymus destroys T-cells that would attack the body's own tissue. It's not fighting the immune system. It's quality-controlling it. The shadow engine quality-controls the deliberation engine's output. Weak defenses are culled before deployment. This is cooperative culling, not adversarial competition.

Zero-sum framing in security systems is carcinogenic — it produces arms races that consume the system's resources fighting itself. The shadow engine must be framed as the system's own quality control, not as an opponent. The CivitasVox mythology and Crystalline Library should reflect this: the shadow is not the enemy of the light. It is the light's own self-examination.

### Biological Analog
- **Deliberation engine** = bone marrow (produces new immune cells)
- **Shadow engine** = thymic selection (tests immune cells against self, destroys those that would cause autoimmune response)
- **Jury pool** = mature T-cells in circulation (proven, deployed, rotating)
- **Behavioral surface** = the bloodstream (continuous observation medium)
- **Human admin** = the conscious mind (reviews when the body signals pain/fever — rare but authoritative)

## Node Implications

The following areas need new or updated nodes:

### DemiPass (kernel layer)
- oracle-mode (P3, deployed)
- security-events (P2, deployed)
- behavioral-surface (P1, logging deployed)
- deviation-detection (P1, needs data)
- probe-battery (P1, spec complete)
- judgment-hash (P1, spec complete)
- honeypot-capabilities (P1, spec only)
- opaque-refs (P1, spec only)
- capability-resolution (P1, spec only)
- invitation-trust-priors (P1, spec only)
- rotating-jury-pool (NEW — random selection from pool of detection functions)
- lori-switchboard (P1, MCP tool built)

### Platform layer (CivitasVox)
- deliberation-engine (NEW — background think cycles producing detection functions)
- shadow-engine (NEW — cooperative quality control, thymic selection pattern)
- breach-transparency (P1, spec only — public model coherence data)

### Modularization
- demipass-kernel-extraction (NEW — clean separation of DemiPass as standalone module)
