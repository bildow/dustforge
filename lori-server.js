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

  // Status / what's stuck
  if (/what.?s stuck|status|overview/i.test(lower)) {
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

  // Show tasks for a project
  const taskMatch = lower.match(/(?:show|list|get)\s+tasks?\s+(?:for\s+)?(?:project\s+)?(\d+)/);
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
  return "I'm not sure what you're asking for. Try \"status\" or \"help\" if you're lost.";
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
