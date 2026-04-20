#!/usr/bin/env node
/**
 * Phasewhip Admin Panel — incus container health + Lori chat
 * Runs on phasewhip host, serves a dashboard for managing containers.
 * Port: 9090 (or ADMIN_PORT env)
 */

const http = require('http');
const { execSync } = require('child_process');
const PORT = process.env.ADMIN_PORT || 9090;
const LORI_URL = process.env.LORI_URL || 'http://10.225.75.121:3003';
const LORI_KEY = process.env.LORI_AUTH_KEY || '';

function getContainers() {
  try {
    const raw = execSync('incus list -c ns4tMSup --format json 2>/dev/null', { encoding: 'utf8', timeout: 5000 });
    const containers = JSON.parse(raw);
    return containers.map(c => ({
      name: c.name,
      status: c.status?.status || 'unknown',
      type: c.type || 'container',
      ip: Object.values(c.state?.network || {})
        .flatMap(n => (n.addresses || []).filter(a => a.family === 'inet' && a.scope === 'global'))
        .map(a => a.address)[0] || '',
      cpu: c.state?.cpu?.usage || 0,
      memory: c.state?.memory?.usage || 0,
      memory_peak: c.state?.memory?.usage_peak || 0,
      pid: c.state?.pid || 0,
      processes: c.state?.processes || 0,
      created: c.created_at || '',
    }));
  } catch (e) {
    return [{ name: 'error', status: e.message, type: 'error', ip: '' }];
  }
}

function getContainerHealth(name) {
  const healthPorts = {
    brain: 8002, lori: 3003, rowen: 3002, civitasvox: 3000,
    conductor: 8001, mail: 8090, chad: 3003,
  };
  const port = healthPorts[name];
  if (!port) return Promise.resolve({ status: 'no health endpoint' });

  const containers = getContainers();
  const c = containers.find(x => x.name === name);
  if (!c || !c.ip) return Promise.resolve({ status: 'no ip' });

  return new Promise(resolve => {
    const req = http.request({ hostname: c.ip, port, path: '/health', method: 'GET', timeout: 3000 }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve({ raw: d }); } });
    });
    req.on('error', () => resolve({ status: 'unreachable' }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 'timeout' }); });
    req.end();
  });
}

function loriChat(message) {
  return new Promise(resolve => {
    const body = JSON.stringify({ body: message, sender: 'admin' });
    const req = http.request({
      hostname: '10.225.75.121', port: 3003,
      path: '/api/conduit/inbound', method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        ...(LORI_KEY ? { 'x-lori-key': LORI_KEY } : {}),
      },
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve({ reply: d }); } });
    });
    req.on('error', e => resolve({ error: e.message }));
    req.setTimeout(30000, () => { req.destroy(); resolve({ error: 'timeout' }); });
    req.write(body);
    req.end();
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  // API: containers list
  if (url.pathname === '/api/containers') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(getContainers()));
    return;
  }

  // API: container health
  if (url.pathname.startsWith('/api/health/')) {
    const name = url.pathname.split('/')[3];
    const health = await getContainerHealth(name);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(health));
    return;
  }

  // API: chat with Lori
  if (url.pathname === '/api/lori' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      try {
        const { message } = JSON.parse(body);
        const reply = await loriChat(message);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(reply));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // API: container action (restart/stop/start)
  if (url.pathname === '/api/action' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const { container, action } = JSON.parse(body);
        if (!['restart', 'stop', 'start'].includes(action)) throw new Error('invalid action');
        if (!container.match(/^[a-z0-9-]+$/)) throw new Error('invalid container name');
        const cmd = action === 'restart' ? `incus restart ${container}` : `incus ${action} ${container}`;
        const output = execSync(cmd, { encoding: 'utf8', timeout: 15000 });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, output: output.trim() }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // Dashboard HTML
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(DASHBOARD_HTML);
});

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phasewhip — Admin</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  :root { --bg:#08111a; --surface:#0e1824; --card:#132131; --border:#27445f; --text:#e7f1fb; --text2:#9cb4c9; --text3:#6d8397; --accent:#5fb3ff; --green:#69c7b1; --red:#e06c75; --yellow:#c8a84b; }
  body { background:var(--bg); color:var(--text); font-family:'Inter',-apple-system,sans-serif; line-height:1.6; }
  .header { padding:1rem 2rem; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; }
  .logo { font-size:1.3rem; font-weight:800; } .logo span { color:var(--accent); }
  .grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(280px, 1fr)); gap:1rem; padding:1.5rem 2rem; }
  .container-card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:1.25rem; }
  .container-card h3 { font-size:1rem; margin-bottom:0.5rem; display:flex; align-items:center; gap:0.5rem; }
  .dot { width:10px; height:10px; border-radius:50%; display:inline-block; }
  .dot-green { background:var(--green); box-shadow:0 0 6px var(--green); }
  .dot-red { background:var(--red); box-shadow:0 0 6px var(--red); }
  .meta { font-size:0.8rem; color:var(--text3); }
  .meta span { color:var(--text2); }
  .actions { margin-top:0.75rem; display:flex; gap:0.5rem; }
  .btn { padding:0.3rem 0.6rem; border:1px solid var(--border); border-radius:4px; background:transparent; color:var(--text2); font-size:0.75rem; cursor:pointer; }
  .btn:hover { border-color:var(--accent); color:var(--accent); }
  .btn-red { color:var(--red); } .btn-red:hover { border-color:var(--red); }
  .health-badge { font-size:0.7rem; padding:0.15rem 0.5rem; border-radius:4px; background:rgba(105,199,177,0.15); color:var(--green); }

  .chat-section { padding:0 2rem 2rem; }
  .chat-title { font-size:1rem; font-weight:700; margin-bottom:0.75rem; padding-bottom:0.5rem; border-bottom:1px solid var(--border); }
  .chat-box { background:var(--card); border:1px solid var(--border); border-radius:10px; display:flex; flex-direction:column; height:400px; }
  .chat-messages { flex:1; overflow-y:auto; padding:1rem; font-size:0.85rem; }
  .msg { margin-bottom:0.75rem; }
  .msg-you { color:var(--text2); }
  .msg-you strong { color:var(--accent); }
  .msg-lori { color:var(--text); }
  .msg-lori strong { color:var(--green); }
  .msg-lori pre { background:var(--surface); padding:0.5rem; border-radius:4px; margin-top:0.25rem; font-size:0.8rem; white-space:pre-wrap; overflow-x:auto; }
  .chat-input { display:flex; border-top:1px solid var(--border); }
  .chat-input input { flex:1; background:transparent; border:none; padding:0.75rem 1rem; color:var(--text); font-size:0.9rem; outline:none; }
  .chat-input button { background:var(--accent); border:none; padding:0.75rem 1.5rem; color:var(--bg); font-weight:700; cursor:pointer; border-radius:0 0 10px 0; }
</style>
</head>
<body>
<div class="header">
  <div class="logo">Phase<span>whip</span> Admin</div>
  <div style="font-size:0.8rem;color:var(--text3)" id="refresh-time"></div>
</div>

<div class="grid" id="containers"></div>

<div class="chat-section">
  <div class="chat-title">Lori</div>
  <div class="chat-box">
    <div class="chat-messages" id="chat-messages">
      <div class="msg msg-lori"><strong>lori:</strong> Hey. What do you need?</div>
    </div>
    <div class="chat-input">
      <input type="text" id="chat-input" placeholder="Talk to Lori..." autofocus>
      <button onclick="sendChat()">Send</button>
    </div>
  </div>
</div>

<script>
async function loadContainers() {
  const res = await fetch('/api/containers');
  const containers = await res.json();
  const grid = document.getElementById('containers');
  grid.innerHTML = '';
  for (const c of containers) {
    const running = c.status === 'Running';
    const memMB = (c.memory / 1024 / 1024).toFixed(1);
    const card = document.createElement('div');
    card.className = 'container-card';
    card.innerHTML = \`
      <h3><span class="dot \${running ? 'dot-green' : 'dot-red'}"></span>\${c.name}</h3>
      <div class="meta">IP: <span>\${c.ip || '—'}</span></div>
      <div class="meta">Status: <span>\${c.status}</span> · PID: <span>\${c.pid}</span> · Procs: <span>\${c.processes}</span></div>
      <div class="meta">Memory: <span>\${memMB} MB</span></div>
      <div class="meta" id="health-\${c.name}"><span class="health-badge">checking...</span></div>
      <div class="actions">
        <button class="btn" onclick="containerAction('\${c.name}','restart')">restart</button>
        <button class="btn btn-red" onclick="containerAction('\${c.name}','stop')">stop</button>
        <button class="btn" onclick="checkHealth('\${c.name}')">health</button>
      </div>
    \`;
    grid.appendChild(card);
    checkHealth(c.name);
  }
  document.getElementById('refresh-time').textContent = 'Updated: ' + new Date().toLocaleTimeString();
}

async function checkHealth(name) {
  const el = document.getElementById('health-' + name);
  if (!el) return;
  try {
    const res = await fetch('/api/health/' + name);
    const data = await res.json();
    const status = data.status || data.agent || 'ok';
    const extra = data.uptime ? ' · up ' + Math.floor(data.uptime) + 's' : '';
    const llm = data.llm ? ' · LLM: ' + data.llm.primary_status : '';
    el.innerHTML = '<span class="health-badge">' + status + extra + llm + '</span>';
  } catch {
    el.innerHTML = '<span class="health-badge" style="color:var(--red);background:rgba(224,108,117,0.15)">unreachable</span>';
  }
}

async function containerAction(name, action) {
  if (!confirm(action + ' ' + name + '?')) return;
  const res = await fetch('/api/action', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({container:name, action}) });
  const data = await res.json();
  if (data.ok) { setTimeout(loadContainers, 2000); }
  else { alert(data.error); }
}

async function sendChat() {
  const input = document.getElementById('chat-input');
  const msg = input.value.trim();
  if (!msg) return;
  input.value = '';
  const messages = document.getElementById('chat-messages');
  messages.innerHTML += '<div class="msg msg-you"><strong>you:</strong> ' + esc(msg) + '</div>';
  messages.scrollTop = messages.scrollHeight;

  try {
    const res = await fetch('/api/lori', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({message: msg}) });
    const data = await res.json();
    const reply = data.reply || data.error || 'no response';
    messages.innerHTML += '<div class="msg msg-lori"><strong>lori:</strong> ' + formatReply(reply) + '</div>';
  } catch (e) {
    messages.innerHTML += '<div class="msg msg-lori"><strong>lori:</strong> <span style="color:var(--red)">connection error: ' + esc(e.message) + '</span></div>';
  }
  messages.scrollTop = messages.scrollHeight;
}

function formatReply(text) {
  // Convert markdown-ish formatting
  return esc(text).replace(/\\n/g, '<br>').replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

document.getElementById('chat-input').addEventListener('keydown', e => { if (e.key === 'Enter') sendChat(); });

loadContainers();
setInterval(loadContainers, 30000);
</script>
</body>
</html>`;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[phasewhip-admin] listening on 0.0.0.0:${PORT}`);
  console.log(`[phasewhip-admin] lori: ${LORI_URL}`);
});
