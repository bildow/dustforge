# Decision Trace Integration Guide — For Claude Code Instances

## What Decision Traces Are

Every significant decision made during a session should be recorded in the platform's `decision_traces` table. This creates an organizational memory that future rounds (audit, ideation, collaboration) can reference. The traces form a graph with typed relationships (fork, merge, derive, contradict, subsume, usurp).

## How to Push Traces

### Option 1: Via API (preferred for external instances)

```bash
# The platform is at http://100.83.112.88:3000 (Tailscale only)
# Or through any host that can reach it

curl -s -X POST http://100.83.112.88:3000/api/decision-traces/link \
  -H "Content-Type: application/json" \
  -d '{
    "from_trace": "DT-existing-code",
    "to_trace": "DT-new-code",
    "relationship": "derive",
    "notes": "new decision built on prior one"
  }'
```

Note: The link endpoint requires both traces to already exist. Create traces first.

### Option 2: Direct DB Insert (from inside phasewhip/containers)

```javascript
// From inside an incus container or phasewhip host
require("dotenv").config();
const Database = require("better-sqlite3");
const db = new Database("/data/platform.db");

const stmt = db.prepare(`
  INSERT INTO decision_traces 
  (trace_code, project_id, round_type, agent_key, decision_type, 
   title, description, chosen_path, rationale, confidence, tags)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

// Generate a unique trace code
const code = "DT-manual-" + Date.now() + "-" + Math.random().toString(36).slice(2,6);

stmt.run(
  code,
  17,              // project_id (17 = Civitasvox MVP)
  "manual",        // round_type
  "claude-kyle",   // agent_key — identify which Claude instance
  "choice",        // decision_type: choice | pivot | rejection | escalation | deferral
  "Title of the decision",
  "What was being decided",
  "Which option was selected",
  "WHY this option over alternatives",
  "high",          // confidence: high | medium | low
  JSON.stringify(["tag1", "tag2"])
);
```

### Option 3: Script File (easiest for batch inserts)

```javascript
// Save as push_traces.js, run with: cd /app && node push_traces.js
require("dotenv").config();
const Database = require("better-sqlite3");
const db = new Database("/data/platform.db");

const traces = [
  {
    title: "Chose X over Y",
    type: "choice",
    desc: "We needed to decide between X and Y for feature Z",
    chosen: "X",
    rationale: "X has lower latency and we already have the dependency",
    tags: ["architecture", "performance"]
  },
  // ... more traces
];

const stmt = db.prepare(
  "INSERT INTO decision_traces (trace_code, project_id, round_type, agent_key, decision_type, title, description, chosen_path, rationale, confidence, tags) VALUES (?,17,'manual','claude-kyle',?,?,?,?,?,'high',?)"
);

traces.forEach((t, i) => {
  const code = "DT-kyle-" + Date.now() + "-" + i;
  stmt.run(code, t.type, t.title, t.desc, t.chosen, t.rationale, JSON.stringify(t.tags || []));
});

console.log("Inserted " + traces.length + " traces");
```

## Decision Types

| Type | When to use |
|------|-------------|
| `choice` | Selected one option from alternatives |
| `pivot` | Changed direction from original plan |
| `rejection` | Explicitly rejected an approach (document why) |
| `escalation` | Elevated decision to human or higher authority |
| `deferral` | Postponed decision (document what triggers revisit) |

## Relationship Types (for linking traces)

| Type | Meaning |
|------|---------|
| `fork` | Decision split into branches (1 parent → N children) |
| `subsume` | One decision absorbed another |
| `usurp` | New decision replaced an old one |
| `merge` | Branches rejoined |
| `derive` | One decision informed another (weak causal link) |
| `contradict` | Decisions conflict (flagged for resolution) |

## What To Trace

Trace every decision that:
- Chose between alternatives (even if obvious — document WHY it was obvious)
- Changed direction from a prior plan
- Rejected an approach someone proposed
- Was deferred for later
- Affects architecture, security, deployment, or user experience

Do NOT trace:
- Routine code changes (that's git)
- Bug fixes (that's the failure modes doc)
- Things already captured in round outputs (traces are auto-harvested from rounds)

## Reading Traces

```bash
# All traces for a project
curl -s http://100.83.112.88:3000/api/projects/17/decision-traces

# Single trace with links
curl -s http://100.83.112.88:3000/api/decision-traces/DT-xxx-xxx

# Full graph (nodes + edges)
curl -s http://100.83.112.88:3000/api/projects/17/decision-graph
```

## Project IDs

| ID | Project |
|----|---------|
| 2 | Text Friendly |
| 3 | Carbon Silicon Platform |
| 17 | Civitasvox MVP (Dustforge) |

## Agent Keys

Use a consistent agent_key so traces can be filtered by source:
- `claude-code` — Aaron's Claude Code instance
- `claude-kyle` — Kyle's Claude Code instance
- `brain` — Brain agent
- `codex` — Codex sessions
- `manual` — Human-entered decisions
