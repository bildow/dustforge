# AKStrapped LLC — Legal & Compliance Checklist

Last updated: 2026-04-08

## Status Key
- [x] Done
- [ ] Not done
- [~] Partial / needs review

---

## 1. Privacy Policy & Terms of Service

| Item | Status | Location |
|------|--------|----------|
| Privacy Policy | [x] | `http://100.83.112.88:3000/privacy` (platform) |
| Terms of Service | [x] | `http://100.83.112.88:3000/terms` (platform) |
| Dustforge privacy (standalone) | [x] | `dustforge.com/privacy` / `privacy.html` in repo |
| Dustforge terms (standalone) | [x] | `dustforge.com/terms` / `terms.html` in repo |
| akstrapped.com legal pages | [ ] | Bluehost — currently empty default pages |

**Action needed:** Keep Dustforge legal pages updated alongside product changes and Stripe/legal dashboard settings.

---

## 2. Stripe Compliance

| Item | Status | Notes |
|------|--------|-------|
| Stripe account active | [x] | Processing payments |
| Webhook endpoint configured | [~] | Needs public HTTPS URL (blocked by SSL cert) |
| Privacy policy linked in Stripe dashboard | [ ] | Add `https://dustforge.com/privacy` in Stripe settings |
| Terms linked in Stripe checkout | [ ] | Add `terms_of_service` consent in Stripe Checkout Session |
| Refund policy documented | [x] | In Terms §4 — non-refundable except where required by law |
| PCI compliance | [x] | Stripe handles all card data — we never touch it |

**Action needed:**
1. Get SSL cert on dustforge.com (needs RackNerd SSH)
2. Add privacy/terms URLs to Stripe Dashboard → Settings → Branding → Legal
3. Add `consent_collection: { terms_of_service: 'required' }` to Checkout sessions

---

## 3. SMS / A2P 10DLC Compliance (Text Friendly / Chad)

| Item | Status | Notes |
|------|--------|-------|
| A2P 10DLC brand registration | [ ] | Register "AKStrapped LLC" as brand with SignalWire/TCR |
| A2P campaign registration | [ ] | Register "Text Friendly" / "Chad" campaign |
| EIN on file | [x] | AKStrapped LLC EIN registered |
| Opt-in mechanism | [x] | Web opt-in overlay with checkbox in Chad |
| Opt-in record keeping | [~] | IP + timestamp logged, needs formal consent log |
| STOP keyword handling | [x] | Chad processes STOP → sends opt-out confirmation |
| HELP keyword handling | [x] | Chad processes HELP → sends info message |
| START keyword handling | [x] | Chad processes START → re-subscribes |
| Message frequency disclosure | [x] | "Msg frequency varies" in welcome + help messages |
| Data rates disclosure | [x] | "Msg&Data rates may apply" in welcome + help messages |
| Business contact in HELP | [x] | mayer.kyle@gmail.com in HELP response |
| Privacy policy accessible | [~] | Platform has it, needs link in Chad HELP message |
| Content type declaration | [ ] | For A2P registration — "AI fitness coaching" |

**Action needed:**
1. Register A2P 10DLC brand with SignalWire/The Campaign Registry (TCR)
   - Company name: AKStrapped LLC
   - EIN: (on file)
   - Website: https://akstrapped.com
   - Vertical: Health & Fitness
2. Register campaign:
   - Campaign name: Text Friendly — Chad
   - Use case: AI fitness coaching & nutrition
   - Sample messages required (5)
   - Opt-in flow description
   - Privacy policy URL
3. Update Chad HELP message to include privacy policy URL
4. Add formal consent log table to Chad's database

---

## 4. TCPA Compliance (SMS)

| Item | Status | Notes |
|------|--------|-------|
| Prior express written consent | [x] | Web opt-in checkbox before first message |
| Clear disclosure of AI-generated content | [x] | Disclosure in opt-in overlay |
| Opt-out honored within 24h | [x] | Immediate — STOP processed in real-time |
| No messages to non-opted-in numbers | [x] | Chad only responds to inbound messages |
| Time-of-day restrictions | [ ] | Not implemented — should suppress 9PM-8AM local |
| Consent revocation records | [~] | STOP logged, needs formal audit trail |

**Action needed:**
1. Add quiet hours logic to Chad (no messages 9PM-8AM recipient local time)
2. Formalize consent log with timestamps, IP, method, and revocation

---

## 5. Data Protection (CCPA / General)

| Item | Status | Notes |
|------|--------|-------|
| Right to know | [x] | Documented in privacy policy |
| Right to delete | [x] | Documented in privacy policy |
| Right to opt-out of sale | [x] | We don't sell data — stated in policy |
| Data inventory | [ ] | Need formal inventory of all PII stored |
| Data retention schedule | [x] | In privacy policy §5 |
| Data breach notification plan | [ ] | Need incident response procedure |
| Sub-processor list | [~] | Stripe, SignalWire, OpenRouter listed in privacy policy |

**Action needed:**
1. Create data inventory document (what PII, where stored, who has access)
2. Write incident response / data breach notification procedure
3. Consider adding "Do Not Sell My Info" page for CCPA compliance

---

## 6. Dustforge-Specific Compliance

| Item | Status | Notes |
|------|--------|-------|
| DID:key generation security | [x] | Ed25519 + AES-256-GCM encryption |
| IDENTITY_MASTER_KEY persisted | [x] | In .env on RackNerd |
| Key backup procedure | [~] | .env backed up daily to /opt/dustforge/backups/ — needs envelope encryption + cold storage |
| Rate limiting | [x] | Three-tier express-rate-limit (strict/standard/relaxed) — shipped 2026-04-12 |
| Wallet double-entry validation | [x] | Double-entry bookkeeping, balance=SUM(transactions), idempotency keys — shipped 2026-04-12 |
| Database backups | [x] | Daily at 2 AM on RackNerd, 14-day retention — shipped 2026-04-08 |
| Token/credential rotation plan | [ ] | npm token expires Jul 7 2026 — task #87 |
| Silicon conversion tracking disclosure | [ ] | Not disclosed in privacy policy |

**Action needed:**
1. CRITICAL: Set up automated daily database backups on RackNerd
2. Back up IDENTITY_MASTER_KEY to secure location
3. Add rate limiting (express-rate-limit) to all endpoints
4. Add silicon conversion tracking disclosure to privacy policy
5. Audit wallet billing for double-debit vulnerabilities

---

## 7. Google Ads Compliance

| Item | Status | Notes |
|------|--------|-------|
| Landing page has privacy link | [x] | Footer added to /for-agents — shipped 2026-04-08 |
| Landing page has terms link | [x] | Footer added to /for-agents — shipped 2026-04-08 |
| Ad copy complies with policy | [x] | Variant C — plaintext, no misleading claims |
| Conversion tracking disclosed | [ ] | gtag.js on /for-agents — needs cookie consent? |

**Action needed:**
1. Add privacy/terms footer links to /for-agents landing page
2. Consider cookie consent banner for Google Ads tracking pixel

---

## 8. Infrastructure Security

| Item | Status | Notes |
|------|--------|-------|
| SSL/TLS on dustforge.com | [x] | certbot + auto-renew, expires 2026-07-07 — shipped 2026-04-08 |
| SSL/TLS on platform | [~] | Internal Tailscale only — no public HTTPS |
| Firewall on RackNerd | [ ] | Needs audit |
| SSH key-only auth | [ ] | Currently password auth on RackNerd |
| Secrets in env vars (not code) | [x] | .env files used |
| No secrets in git | [~] | Need to audit git history |

---

## Priority Actions (ordered, updated 2026-04-12)

1. ~~**SSL cert on dustforge.com**~~ — DONE 2026-04-08
2. ~~**Database backups on RackNerd**~~ — DONE 2026-04-08
3. ~~**Rate limiting on all APIs**~~ — DONE 2026-04-12
4. ~~**Wallet double-entry bookkeeping**~~ — DONE 2026-04-12
5. ~~**Legal links on /for-agents**~~ — DONE 2026-04-08
3. **A2P 10DLC registration** — required for continued SMS delivery
4. **Rate limiting on all APIs** — abuse prevention
5. **IDENTITY_MASTER_KEY backup** — losing this = all Dustforge identities unrecoverable
6. **Add legal links to /for-agents page** — Google Ads compliance
7. **Stripe dashboard legal links** — Stripe compliance
8. **Data inventory document** — foundation for CCPA compliance
