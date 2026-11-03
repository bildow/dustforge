/**
 * Diamond Dust units — the one place dollars turn into DD.
 *
 * Since the 2026-11 redenomination 1 DD = $0.001 (it was $0.01). Every price,
 * balance and stored DD amount was multiplied by 10 then (bin/redenominate-dd.js),
 * so a balance buys exactly what it bought before. The columns keep their old
 * `*_cents` names; they hold DD, not cents.
 *
 * A deposit buys 950 DD per dollar; the other 5% is the platform's.
 */
const DD_PER_USD = 1000;          // list value: what $1 of prices is worth in DD
const DEPOSIT_DD_PER_USD = 950;   // what $1 paid in buys
const REDENOMINATION_FACTOR = 10; // old DD → new DD

// DD credited for a payment of `usdCents` US cents.
function ddForUsdCents(usdCents) {
  return Math.floor(Number(usdCents) * DEPOSIT_DD_PER_USD / 100);
}

// "$0.010" style dollar value of an amount of DD, for display.
function usdLabel(dd) {
  const usd = Number(dd) / DD_PER_USD;
  return '$' + (usd < 1 ? usd.toFixed(3) : usd.toFixed(2));
}

module.exports = { DD_PER_USD, DEPOSIT_DD_PER_USD, REDENOMINATION_FACTOR, ddForUsdCents, usdLabel };
