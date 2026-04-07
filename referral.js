/**
 * Civitasvox Referral System
 *
 * Every account gets a referral code. When a new account is created
 * with that code, the referrer gets a payout from the creation fee.
 * Every outbound email gets an invisible referral link injected.
 */

// Referral payout: percentage of the $1 account creation fee
const REFERRAL_PAYOUT_CENTS = 25; // $0.25 per successful referral

// Referral link base URL
const REFERRAL_BASE_URL = process.env.REFERRAL_BASE_URL || 'https://civitasvox.com/join';

/**
 * Process a referral payout when a new account is created.
 * Called after successful account creation if referred_by is set.
 */
function processReferralPayout(db, referrerDid, newAccountDid, newUsername) {
  if (!referrerDid) return null;

  const billing = require('./billing');
  const result = billing.creditBalance(
    db,
    referrerDid,
    REFERRAL_PAYOUT_CENTS,
    'referral_payout',
    `Referral payout: ${newUsername} joined via your invite`
  );

  if (result.ok) {
    // Log the referral
    try {
      db.prepare(`
        INSERT INTO identity_transactions (did, amount_cents, type, description, balance_after)
        VALUES (?, 0, 'referral_converted', ?, 0)
      `).run(newAccountDid, `Referred by ${referrerDid.slice(0, 20)}...`);
    } catch (_) {}

    console.log(`[referral] ${referrerDid.slice(0, 25)}... earned ${REFERRAL_PAYOUT_CENTS}¢ for referring ${newUsername}`);
  }

  return result;
}

/**
 * Generate the referral link for an account.
 */
function getReferralLink(referralCode) {
  return `${REFERRAL_BASE_URL}?ref=${referralCode}`;
}

/**
 * Inject referral link into email body (invisible footer).
 * This is the viral growth mechanism — every email sent carries
 * the sender's referral link.
 */
function injectReferralLink(emailBody, referralCode, format = 'html') {
  const link = getReferralLink(referralCode);

  if (format === 'html') {
    // Invisible footer with referral link
    const footer = `
<div style="margin-top:24px;padding-top:12px;border-top:1px solid #eee;font-size:11px;color:#999">
  <a href="${link}" style="color:#999;text-decoration:none">Powered by Civitasvox</a>
</div>`;
    return emailBody + footer;
  }

  // Plain text
  return emailBody + `\n\n---\nPowered by Civitasvox: ${link}`;
}

/**
 * Get referral stats for an account.
 */
function getReferralStats(db, did) {
  const wallet = db.prepare('SELECT referral_code FROM identity_wallets WHERE did = ?').get(did);
  if (!wallet) return null;

  const referralCount = db.prepare(
    'SELECT COUNT(*) as n FROM identity_wallets WHERE referred_by = ?'
  ).get(did).n;

  const totalEarned = db.prepare(
    "SELECT COALESCE(SUM(amount_cents), 0) as total FROM identity_transactions WHERE did = ? AND type = 'referral_payout'"
  ).get(did).total;

  const recentReferrals = db.prepare(
    'SELECT username, created_at FROM identity_wallets WHERE referred_by = ? ORDER BY created_at DESC LIMIT 10'
  ).all(did);

  return {
    referral_code: wallet.referral_code,
    referral_link: getReferralLink(wallet.referral_code),
    total_referrals: referralCount,
    total_earned_cents: totalEarned,
    recent: recentReferrals,
  };
}

module.exports = {
  REFERRAL_PAYOUT_CENTS,
  processReferralPayout,
  getReferralLink,
  injectReferralLink,
  getReferralStats,
};
