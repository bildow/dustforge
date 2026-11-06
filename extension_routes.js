'use strict';
// ── Browser extension install page support (public/extension.html at demipass.com/extension).
// Registered from server.js: require('./extension_routes')({ app, db }).
//
// POST /api/extension/waitlist {email, browser}: while the Chrome Web Store listing is pending review, people on
// Chrome, Brave, Edge or Chromium leave an email to hear once when it is listed. The answer never says whether the address was
// already on the list. Kept apart from the capacity waiting_list (different purpose, different promise).
// Reading the list is an operator act on the DB:
//   SELECT email, browser, created_at FROM extension_waitlist WHERE notified_at IS NULL;

const rateLimit = require('express-rate-limit');

const BROWSERS = new Set(['chrome', 'brave', 'edge', 'chromium']);
const MAX_ROWS = 50000;       // a full list refuses new rows instead of growing without bound
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

module.exports = function registerExtensionRoutes({ app, db }) {
  db.exec(`CREATE TABLE IF NOT EXISTS extension_waitlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    browser TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    notified_at TEXT,
    UNIQUE (email, browser)
  )`);

  const limit = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
    message: { error: 'Too many requests. Try again in a few minutes.' } });

  app.post('/api/extension/waitlist', limit, (req, res) => {
    const body = req.body || {};
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const browser = typeof body.browser === 'string' ? body.browser.trim().toLowerCase() : '';
    if (email.length > 254 || !EMAIL_RE.test(email)) return res.status(400).json({ error: 'a valid email is required' });
    if (!BROWSERS.has(browser)) return res.status(400).json({ error: 'browser must be one of chrome, brave, edge, chromium' });
    const n = db.prepare('SELECT COUNT(*) AS n FROM extension_waitlist').get().n;
    if (n >= MAX_ROWS) return res.status(503).json({ error: 'the waitlist is full' });
    db.prepare('INSERT OR IGNORE INTO extension_waitlist (email, browser) VALUES (?, ?)').run(email, browser);
    return res.json({ ok: true });
  });
};
