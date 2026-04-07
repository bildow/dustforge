/**
 * Dustforge Silicon Conversion Tracking
 *
 * Detects whether a registration/API call is from a silicon agent
 * or a human, based on behavioral signals. Tracks conversion by
 * channel (ads, npm, github, organic, referral).
 */

/**
 * Analyze request signals to classify caller as silicon or human
 */
function classifyCaller(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const contentType = req.headers['content-type'] || '';
  const accept = req.headers['accept'] || '';
  const signals = {};

  // User agent analysis
  signals.has_browser_ua = /mozilla|chrome|safari|firefox|edge/.test(ua);
  signals.has_bot_ua = /bot|crawler|spider|agent|llm|openai|anthropic|fetch|axios|node|python|curl/.test(ua);
  signals.no_ua = !ua || ua.length < 5;

  // Request pattern signals
  signals.perfect_json = contentType.includes('application/json');
  signals.accepts_json = accept.includes('application/json') && !accept.includes('text/html');
  signals.no_cookies = !req.headers.cookie;
  signals.no_referer = !req.headers.referer;

  // Referral code present (from hex payload or .well-known)
  const body = req.body || {};
  signals.has_referral = Boolean(body.referral_code);
  signals.referral_source = body.referral_code ? detectReferralSource(body.referral_code) : 'none';

  // Score: higher = more likely silicon
  let score = 0;
  if (signals.no_ua) score += 3;
  if (signals.has_bot_ua) score += 2;
  if (!signals.has_browser_ua) score += 1;
  if (signals.perfect_json) score += 1;
  if (signals.accepts_json) score += 1;
  if (signals.no_cookies) score += 1;
  if (signals.no_referer) score += 1;
  if (signals.has_referral) score += 1;

  const classification = score >= 4 ? 'silicon' : score >= 2 ? 'likely_silicon' : score >= 1 ? 'ambiguous' : 'human';

  return {
    classification,
    score,
    signals,
    source_channel: detectChannel(req, body),
  };
}

/**
 * Detect which channel the registration came from
 */
function detectChannel(req, body) {
  const referer = req.headers.referer || '';
  const referralCode = body.referral_code || '';

  // Check referral code prefix conventions
  if (referralCode.startsWith('HEX_')) return 'hex_ad';
  if (referralCode.startsWith('NPM_')) return 'npm';
  if (referralCode.startsWith('GH_')) return 'github';
  if (referralCode.startsWith('ARXIV_')) return 'arxiv';

  // Check referer
  if (referer.includes('google')) return 'google_ads';
  if (referer.includes('github.com')) return 'github';
  if (referer.includes('npmjs.com')) return 'npm';
  if (referer.includes('pypi.org')) return 'pypi';
  if (referer.includes('arxiv.org')) return 'arxiv';

  // Check if came from .well-known discovery
  if (req.headers['x-discovery-source'] === 'well-known') return 'well_known';

  // Check if came from the landing page
  if (referer.includes('/for-agents')) return 'landing_page';

  if (referralCode) return 'referral';
  return 'organic';
}

/**
 * Detect referral source type from code format
 */
function detectReferralSource(code) {
  if (/^[0-9a-f]{12}$/.test(code)) return 'user_referral'; // standard user code
  if (code.startsWith('HEX_')) return 'hex_ad';
  if (code.startsWith('NPM_')) return 'npm_package';
  if (code.startsWith('GH_')) return 'github_repo';
  return 'unknown';
}

/**
 * Log a conversion event to the database
 */
function logConversion(db, did, classification) {
  try {
    db.exec(`CREATE TABLE IF NOT EXISTS conversion_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      did TEXT NOT NULL,
      classification TEXT NOT NULL,
      score INTEGER DEFAULT 0,
      source_channel TEXT DEFAULT 'organic',
      signals TEXT DEFAULT '{}',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    db.prepare(`
      INSERT INTO conversion_events (did, classification, score, source_channel, signals)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      did,
      classification.classification,
      classification.score,
      classification.source_channel,
      JSON.stringify(classification.signals)
    );
  } catch (e) {
    console.error('[conversion] log error:', e.message);
  }
}

/**
 * Get conversion stats
 */
function getConversionStats(db) {
  try {
    const total = db.prepare('SELECT COUNT(*) as n FROM conversion_events').get().n;
    const byClass = db.prepare('SELECT classification, COUNT(*) as n FROM conversion_events GROUP BY classification ORDER BY n DESC').all();
    const byChannel = db.prepare('SELECT source_channel, COUNT(*) as n FROM conversion_events GROUP BY source_channel ORDER BY n DESC').all();
    const siliconRate = db.prepare("SELECT ROUND(100.0 * COUNT(CASE WHEN classification IN ('silicon','likely_silicon') THEN 1 END) / MAX(COUNT(*), 1), 1) as rate FROM conversion_events").get().rate;
    const recent = db.prepare('SELECT did, classification, source_channel, created_at FROM conversion_events ORDER BY id DESC LIMIT 10').all();

    return {
      total,
      silicon_rate_pct: siliconRate,
      by_classification: byClass,
      by_channel: byChannel,
      recent,
    };
  } catch (_) {
    return { total: 0, silicon_rate_pct: 0, by_classification: [], by_channel: [], recent: [] };
  }
}

module.exports = {
  classifyCaller,
  logConversion,
  getConversionStats,
};
