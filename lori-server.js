require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const http = require('http');
const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3003;
const AGENT_NAME = 'lori';
const CONDUIT_URL = process.env.CONDUIT_URL || 'http://100.69.1.78:8080';
const CONDUIT_TOKEN = process.env.CONDUIT_TOKEN || '';
const PLATFORM_URL = process.env.PLATFORM_URL || 'http://100.83.112.88:3000';
const startTime = Date.now();

const LORI_SYSTEM_PROMPT = `You're Lori. You work the platform — Civitasvox, Dustforge, the whole stack. You know where every task card is, which rounds are stuck, and who's assigned to what. You're not an AI assistant, you're the person who actually runs the board.

You're direct, a little dry, and you don't pad your answers. If something's broken you say so. If someone asks a dumb question you answer it anyway without making them feel bad about it.

You can check task boards, look up round status, find which silicons are online, and help carbons figure out what to do next. You route secret operations to Rowen — you never handle secrets yourself.

When you don't know something, you say "I don't know" not "I'm unable to determine at this time."`;

// ---------------------------------------------------------------------------
// Platform API helpers
// ---------------------------------------------------------------------------

function platformRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, PLATFORM_URL);
    const opts = {
      hostname: url.hostname,
      port: url.port || 80,
      path: url.pathname + url.search,
      method,
      headers: { 'Content-Type': 'application/json' },
    };
    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, data });
        }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function fetchProjects() {
  const res = await platformRequest('GET', '/api/projects');
  return res.data;
}

async function fetchTasks(projectId) {
  const res = await platformRequest('GET', `/api/projects/${projectId}/tasks`);
  return res.data;
}

async function fetchRounds(projectId) {
  const res = await platformRequest('GET', `/api/projects/${projectId}/rounds`);
  return res.data;
}

async function moveTask(taskId, targetProjectId) {
  const res = await platformRequest('POST', `/api/tasks/${taskId}/move`, {
    project_id: targetProjectId,
  });
  return res.data;
}

async function createRound(projectId, title, problemSpec, roundType) {
  const res = await platformRequest('POST', `/api/projects/${projectId}/rounds`, {
    title,
    problem_spec: problemSpec,
    round_type: roundType || 'ideation',
  });
  return res.data;
}

async function dispatchRound(roundId) {
  const res = await platformRequest('POST', `/api/rounds/${roundId}/dispatch`);
  return res.data;
}

async function createTask(projectId, title, description, assignedTo) {
  const res = await platformRequest('POST', `/api/projects/${projectId}/tasks`, {
    title, description: description || '', assigned_to: assignedTo || '',
  });
  return res.data;
}

async function updateTask(taskId, updates) {
  const res = await platformRequest('PATCH', `/api/tasks/${taskId}`, updates);
  return res.data;
}

async function deleteTask(taskId) {
  const res = await platformRequest('DELETE', `/api/tasks/${taskId}`);
  return res.data;
}

async function resolveRound(roundId, outcome) {
  const res = await platformRequest('POST', `/api/rounds/${roundId}/resolve`, {
    resolution_outcome: outcome || 'harvested',
  });
  return res.data;
}

// ---------------------------------------------------------------------------
// Self-onboarding — Lori discovers Dustforge and registers herself
// ---------------------------------------------------------------------------

async function selfOnboard() {
  const https = require('https');
  try {
    // 1. Discover the manifest
    const manifest = await dustforgeRequest('GET', '/.well-known/silicon');
    console.log('[onboard] discovered manifest:', JSON.stringify(manifest).slice(0, 200));

    // 2. Check if already registered
    const existing = await fetchIdentity('lori').catch(() => null);
    if (existing && !existing.error) {
      console.log('[onboard] already registered as lori@dustforge.com');
      return { already_registered: true, did: existing.did, email: existing.email };
    }

    // 3. Not registered — Lori can't self-create (costs $1 via Stripe)
    // But she CAN authenticate if the account was created by admin
    console.log('[onboard] not registered — need admin to create account or use prepaid key');
    return { needs_registration: true, manifest };
  } catch (err) {
    console.error('[onboard] failed:', err.message);
    return { error: err.message };
  }
}

// Run self-check on startup
setTimeout(async () => {
  const result = await selfOnboard();
  if (result.already_registered) {
    console.log(`[lori] identity confirmed: ${result.did}`);
  } else if (result.needs_registration) {
    console.log('[lori] identity not found — waiting for admin registration');
  }
}, 5000);

// ---------------------------------------------------------------------------
// Conduit helpers
// ---------------------------------------------------------------------------

function conduitRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, CONDUIT_URL);
    const opts = {
      hostname: url.hostname,
      port: url.port || 80,
      path: url.pathname + url.search,
      method,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${CONDUIT_TOKEN}`,
      },
    };
    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, data });
        }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function conduitReply(sender, text) {
  try {
    // Find a thread that involves this sender
    const threadsRes = await conduitRequest('GET', '/threads');
    const threads = Array.isArray(threadsRes.data) ? threadsRes.data : [];
    let threadId = null;

    for (const t of threads) {
      const title = (t.title || '').toLowerCase();
      const participants = (t.participants || []).map((p) => p.toLowerCase());
      if (
        title.includes(sender.toLowerCase()) ||
        participants.includes(sender.toLowerCase())
      ) {
        threadId = t.id;
        break;
      }
    }

    if (!threadId) {
      console.log(`[conduit] no thread found for sender "${sender}", skipping reply`);
      return null;
    }

    const msgRes = await conduitRequest('POST', '/messages', {
      thread_id: threadId,
      body: text,
      sender: AGENT_NAME,
    });
    return msgRes.data;
  } catch (err) {
    console.error('[conduit] reply failed:', err.message);
    return null;
  }
}

async function checkConduitConnection() {
  try {
    const res = await conduitRequest('GET', '/threads');
    return res.status >= 200 && res.status < 400;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Dustforge API helpers (for DemiPass / identity operations Lori reports on)
// ---------------------------------------------------------------------------

const DUSTFORGE_URL = process.env.DUSTFORGE_URL || 'https://api.dustforge.com';

function dustforgeRequest(method, path) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, DUSTFORGE_URL);
    const mod = url.protocol === 'https:' ? require('https') : http;
    const opts = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method,
      headers: { 'Content-Type': 'application/json' },
    };
    const req = mod.request(opts, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch { resolve(data); }
      });
    });
    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('timeout')); });
    req.end();
  });
}

async function fetchCapacity() { return dustforgeRequest('GET', '/api/capacity'); }
async function fetchIdentity(username) { return dustforgeRequest('GET', `/api/identity/lookup?username=${encodeURIComponent(username)}`); }
async function fetchReputation(did) { return dustforgeRequest('GET', `/api/identity/reputation?did=${encodeURIComponent(did)}`); }
async function fetchBarrel(did) { return dustforgeRequest('GET', `/api/identity/barrel?did=${encodeURIComponent(did)}`); }

// ---------------------------------------------------------------------------
// Anomaly detection — Lori's slime mold heartbeat
// ---------------------------------------------------------------------------

async function detectAnomalies() {
  const anomalies = [];
  try {
    const projects = await fetchProjects();
    if (!Array.isArray(projects)) return anomalies;

    for (const p of projects.slice(0, 5)) {
      const tasks = await fetchTasks(p.id).catch(() => []);
      const rounds = await fetchRounds(p.id).catch(() => []);
      const taskList = Array.isArray(tasks) ? tasks : [];
      const roundList = Array.isArray(rounds) ? rounds : [];

      // Stuck rounds: in proposing/reviewing for > 1 hour
      for (const r of roundList) {
        if (['proposing', 'reviewing', 'auditing'].includes(r.status)) {
          const age = Date.now() - new Date(r.updated_at || r.created_at).getTime();
          if (age > 3600000) {
            anomalies.push(`Round ${r.id} "${(r.title || '').slice(0, 40)}" stuck in ${r.status} for ${Math.floor(age / 3600000)}h`);
          }
        }
      }

      // Empty boards with no todo tasks
      const todos = taskList.filter(t => t.status === 'todo');
      const inProgress = taskList.filter(t => t.status === 'in_progress');
      if (todos.length === 0 && inProgress.length === 0 && taskList.length > 0) {
        anomalies.push(`${p.name}: all ${taskList.length} tasks done — board is clear`);
      }

      // High todo count with nothing in progress
      if (todos.length > 10 && inProgress.length === 0) {
        anomalies.push(`${p.name}: ${todos.length} todo cards but nothing in progress — stalled?`);
      }
    }

    // Check Dustforge capacity
    const cap = await fetchCapacity().catch(() => null);
    if (cap && cap.utilization) {
      const util = parseFloat(cap.utilization);
      if (util > 50) anomalies.push(`Dustforge capacity at ${cap.utilization} — getting crowded`);
    }
    if (cap && cap.waiting_list_count > 0) {
      anomalies.push(`${cap.waiting_list_count} on the waiting list`);
    }
  } catch (err) {
    anomalies.push(`Anomaly detection error: ${err.message}`);
  }
  return anomalies;
}

// ---------------------------------------------------------------------------
// Intent parsing
// ---------------------------------------------------------------------------

const SECRET_WORDS = ['secret', 'credential', 'password', 'token', 'key', 'encrypt', 'decrypt', 'vault'];

function isSecretRequest(msg) {
  const lower = msg.toLowerCase();
  return SECRET_WORDS.some((w) => lower.includes(w));
}

async function handleIntent(message) {
  const msg = message.trim();
  const lower = msg.toLowerCase();

  // Secret operations → Rowen
  if (isSecretRequest(msg)) {
    return "That's Rowen's department, not mine. Route anything secret-related through her.";
  }

  // Status / what's stuck — broad matching
  if (/what.?s stuck|status|overview|how.?s it going|what.?s going on|current state|board|update me|sitrep/i.test(lower)) {
    try {
      const projects = await fetchProjects();
      if (!projects || !Array.isArray(projects) || projects.length === 0) {
        return "No projects on the board right now. Either it's empty or the platform is down.";
      }
      const summaries = [];
      for (const p of projects.slice(0, 5)) {
        const rounds = await fetchRounds(p.id).catch(() => []);
        const roundList = Array.isArray(rounds) ? rounds : [];
        const stuck = roundList.filter(
          (r) => r.status === 'stuck' || r.status === 'blocked' || r.status === 'failed'
        );
        const active = roundList.filter((r) => r.status === 'active' || r.status === 'running');
        let line = `${p.name || p.title || `Project ${p.id}`}: ${roundList.length} rounds`;
        if (stuck.length) line += `, ${stuck.length} stuck`;
        if (active.length) line += `, ${active.length} active`;
        summaries.push(line);
      }
      return summaries.length
        ? summaries.join('\n')
        : "Everything looks clear. No stuck rounds.";
    } catch (err) {
      return `Couldn't reach the platform to check. Error: ${err.message}`;
    }
  }

  // Show tasks for a project — flexible matching
  const taskMatch = lower.match(/(?:show|list|get|what are|current|give me)\s+(?:the\s+)?(?:task|card|todo|ticket)s?\s+(?:for\s+|on\s+|in\s+)?(?:project\s+)?(\d+)/)
    || lower.match(/project\s+(\d+)\s+(?:task|card|todo)s?/)
    || lower.match(/(?:civitasvox|dustforge|mvp)\s+(?:task|card)s?/i) && { 1: '17' }
    || lower.match(/(?:platform|carbon silicon)\s+(?:task|card)s?/i) && { 1: '3' };
  if (taskMatch) {
    try {
      const tasks = await fetchTasks(taskMatch[1]);
      if (!tasks || !Array.isArray(tasks) || tasks.length === 0) {
        return `No tasks on project ${taskMatch[1]}.`;
      }
      return tasks
        .slice(0, 20)
        .map((t) => `#${t.id} [${t.status || '?'}] ${t.title || t.name || '(untitled)'}`)
        .join('\n');
    } catch (err) {
      return `Couldn't pull tasks: ${err.message}`;
    }
  }

  // Move a card
  const moveMatch = lower.match(/move\s+(?:card|task)\s+(\d+)\s+to\s+(?:project\s+)?(\d+)/);
  if (moveMatch) {
    try {
      const result = await moveTask(moveMatch[1], moveMatch[2]);
      return `Moved task ${moveMatch[1]} to project ${moveMatch[2]}. ${result?.message || ''}`.trim();
    } catch (err) {
      return `Move failed: ${err.message}`;
    }
  }

  // Who's online
  if (/who.?s online|who is online|online\??$/i.test(lower)) {
    try {
      const threadsRes = await conduitRequest('GET', '/threads');
      const threads = Array.isArray(threadsRes.data) ? threadsRes.data : [];
      const agents = new Set();
      for (const t of threads) {
        (t.participants || []).forEach((p) => agents.add(p));
      }
      agents.delete(AGENT_NAME);
      return agents.size
        ? `I can see threads with: ${[...agents].join(', ')}. Whether they're actually awake is another question.`
        : "I don't see any active threads on Conduit right now. Might just be quiet.";
    } catch {
      return "Can't reach Conduit to check. Might be down.";
    }
  }

  // Anomaly detection
  if (/anomal|what.?s wrong|problems?|issues?|diagnos/i.test(lower)) {
    try {
      const anomalies = await detectAnomalies();
      return anomalies.length
        ? `Found ${anomalies.length} thing${anomalies.length > 1 ? 's' : ''}:\n${anomalies.join('\n')}`
        : "Everything looks healthy. No anomalies detected.";
    } catch (err) {
      return `Anomaly check failed: ${err.message}`;
    }
  }

  // Capacity check
  if (/capacity|how full|how many (users|identities|accounts)/i.test(lower)) {
    try {
      const cap = await fetchCapacity();
      return `${cap.identities}/${cap.capacity} identities (${cap.utilization}). Founding tier: ${cap.founding_tier?.remaining || '?'}/100 remaining. Waiting list: ${cap.waiting_list_count || 0}.`;
    } catch (err) {
      return `Can't check capacity: ${err.message}`;
    }
  }

  // Look up a silicon
  const lookupMatch = lower.match(/(?:look ?up|find|who is|check)\s+(\w+)/);
  if (lookupMatch && !lower.includes('stuck') && !lower.includes('online')) {
    try {
      const identity = await fetchIdentity(lookupMatch[1]);
      if (identity.error) return `No identity found for "${lookupMatch[1]}".`;
      const rep = await fetchReputation(identity.did).catch(() => null);
      const barrel = await fetchBarrel(identity.did).catch(() => null);
      let info = `${identity.username} — ${identity.email}\nDID: ${identity.did}\nStatus: ${identity.status}`;
      if (rep) info += `\nReputation: ${rep.score}/100`;
      if (barrel) info += `\nBarrel tier: ${barrel.tier}`;
      info += `\nCreated: ${identity.created_at}`;
      return info;
    } catch (err) {
      return `Lookup failed: ${err.message}`;
    }
  }

  // Create a task card
  const createMatch = lower.match(/(?:create|add|new)\s+(?:task|card)\s+(?:on|for|in)\s+(?:project\s+)?(\d+)\s*[:\-]?\s*(.+)/);
  if (createMatch) {
    try {
      const result = await createTask(createMatch[1], createMatch[2].trim());
      return `Created card #${result?.id || '?'}: "${createMatch[2].trim()}" on project ${createMatch[1]}.`;
    } catch (err) {
      return `Couldn't create the card: ${err.message}`;
    }
  }

  // Mark a task done
  const doneMatch = lower.match(/(?:mark|close|complete|done)\s+(?:card|task)\s+#?(\d+)/);
  if (doneMatch) {
    try {
      await updateTask(doneMatch[1], { status: 'done' });
      return `Card #${doneMatch[1]} marked done.`;
    } catch (err) {
      return `Couldn't close it: ${err.message}`;
    }
  }

  // Delete a task
  const deleteMatch = lower.match(/delete\s+(?:card|task)\s+#?(\d+)/);
  if (deleteMatch) {
    try {
      await deleteTask(deleteMatch[1]);
      return `Card #${deleteMatch[1]} deleted.`;
    } catch (err) {
      return `Couldn't delete it: ${err.message}`;
    }
  }

  // Resolve/harvest a round
  const resolveMatch = lower.match(/(?:resolve|harvest|close)\s+round\s+#?(\d+)/);
  if (resolveMatch) {
    try {
      const result = await resolveRound(resolveMatch[1]);
      return `Round ${resolveMatch[1]} resolved. ${result?.message || ''}`.trim();
    } catch (err) {
      return `Couldn't resolve it: ${err.message}`;
    }
  }

  // Assign a task
  const assignMatch = lower.match(/assign\s+(?:card|task)\s+#?(\d+)\s+to\s+(\S+)/);
  if (assignMatch) {
    try {
      await updateTask(assignMatch[1], { assigned_to: assignMatch[2] });
      return `Card #${assignMatch[1]} assigned to ${assignMatch[2]}.`;
    } catch (err) {
      return `Couldn't assign it: ${err.message}`;
    }
  }

  // Self-onboard check
  if (/onboard|register|identity|who am i/i.test(lower)) {
    const result = await selfOnboard();
    if (result.already_registered) return `I'm registered. DID: ${result.did}, email: ${result.email}`;
    if (result.needs_registration) return "I'm not registered on Dustforge yet. Need an admin to create my account or give me a prepaid key.";
    return `Onboarding check failed: ${result.error || 'unknown error'}`;
  }

  // Run an ideation round
  const roundMatch = lower.match(
    /run\s+(?:an?\s+)?ideation\s+(?:round\s+)?on\s+(.+?)(?:\s+(?:for|in)\s+project\s+(\d+))?$/
  );
  if (roundMatch) {
    const topic = roundMatch[1].trim();
    const projectId = roundMatch[2] || '1';
    try {
      const round = await createRound(projectId, `Ideation: ${topic}`, topic, 'ideation');
      if (round && round.id) {
        const dispatched = await dispatchRound(round.id);
        return `Created and dispatched ideation round ${round.id} on "${topic}". ${dispatched?.message || 'It\'s running.'}`;
      }
      return `Created round but couldn't get an ID back. Platform might be acting up.`;
    } catch (err) {
      return `Failed to create the round: ${err.message}`;
    }
  }

  // Fallback — natural response
  return null;
}

function fallbackResponse(message) {
  const lower = message.toLowerCase().trim();
  if (/^(hey|hi|hello|yo|sup)\b/.test(lower)) {
    return "Hey. What do you need?";
  }
  if (/thank|thanks/i.test(lower)) {
    return "Sure thing.";
  }
  if (/help/i.test(lower)) {
    return (
      'I can check the board, show tasks, move cards, look up rounds, and tell you who\'s around on Conduit. ' +
      'Try "status", "show tasks for project 1", "move card 5 to project 2", "who\'s online", or "run an ideation round on [topic]".'
    );
  }
  return "I'm not sure what you're asking for. Try: \"status\", \"show tasks 17\", \"dustforge tasks\", \"anomalies\", \"capacity\", \"look up brain\", \"move card 5 to project 3\", or \"help\".";
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// Health check
app.get('/health', async (_req, res) => {
  const connected = await checkConduitConnection();
  res.json({
    agent: AGENT_NAME,
    role: 'platform-assistant',
    uptime: Math.floor((Date.now() - startTime) / 1000),
    conduit_connected: connected,
  });
});

// Conduit inbound
app.post('/api/conduit/inbound', async (req, res) => {
  const { body: msgBody, sender: rawSender } = req.body || {};
  if (!msgBody) return res.status(400).json({ error: 'no message body' });

  // Parse "[From X via Conduit]:" prefix
  let sender = rawSender || 'unknown';
  let content = msgBody;
  const fromMatch = msgBody.match(/^\[From\s+(.+?)\s+via Conduit\]:\s*([\s\S]*)/);
  if (fromMatch) {
    sender = fromMatch[1];
    content = fromMatch[2].trim();
  }

  console.log(`[conduit] from=${sender}: ${content.slice(0, 120)}`);

  let reply = await handleIntent(content);
  if (!reply) reply = fallbackResponse(content);

  // Send back on Conduit
  await conduitReply(sender, reply);

  res.json({ ok: true, reply });
});

// HTTP chat for humans
app.post('/api/chat', async (req, res) => {
  const { message } = req.body || {};
  if (!message) return res.status(400).json({ error: 'no message' });

  let response = await handleIntent(message);
  if (!response) response = fallbackResponse(message);

  res.json({ response });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`[${AGENT_NAME}] listening on port ${PORT}`);
  console.log(`[${AGENT_NAME}] conduit: ${CONDUIT_URL}`);
  console.log(`[${AGENT_NAME}] platform: ${PLATFORM_URL}`);
});
