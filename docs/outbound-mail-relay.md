# Outbound mail relay and gradual ramp

The default outbound path is local Postfix. Microsoft rejected the RackNerd IP
`192.3.84.103` with `550 5.7.1 S3140`, so direct sending to Hotmail cannot be
treated as delivered merely because `/api/email/send` returns `ok: true`.
As of September 30, the existing Resend account reports `dustforge.com` as
`failed` (DKIM `resend._domainkey` and both `send` SPF records), while
`azurecarbon.com` is verified. Do not configure that account as the Dustforge
relay until the domain records pass verification.

DemiPass lists an Atlas Cloudflare API token and a Resend API key. This branch
adds `api.cloudflare.com` and `api.resend.com` to the DemiPass HTTP host
allowlist so those credentials can be checked through vault mediated requests
after deployment. The Cloudflare token belongs to Aaron's Atlas account; its
access to the `dustforge.com` zone has not been verified. The keys remain in
DemiPass and are not copied into this repository.

Set `SMTP_RELAY_HOST`, `SMTP_RELAY_PORT`, `SMTP_RELAY_USER`, and
`SMTP_RELAY_PASSWORD` to use an authenticated SMTP provider. The connection
requires TLS and verifies the provider certificate. The provider must verify
`dustforge.com` and its SPF/DKIM records before this is enabled; the app sends
from `@dustforge.com` addresses. A provider error fails the API request instead
of falling back to the blocked IP. Incoming Stalwart mail is unaffected.

`MAIL_WARMUP_START_UTC` enables a conservative cap on routine
`POST /api/email/send` traffic. The initial daily limit defaults to 10 messages,
doubles every seven days, and stops at 100 per day by default. Set
`MAIL_WARMUP_INITIAL_DAILY_LIMIT` and `MAIL_WARMUP_MAX_DAILY_LIMIT` to change
those bounds. Counters persist in the application database across restarts;
failed API responses release their reservation. Authentication messages,
forwarded inbound mail, and internal alerts still use the relay but do not
consume this routine mail cap. This ramp sends no synthetic messages.

Operational check after deployment:

1. Confirm the provider verifies `dustforge.com`, including DKIM and SPF.
2. Set the four relay variables and three warmup variables in the live service
   environment, then restart only the Dustforge application.
3. Send one consenting test message to a Microsoft mailbox through
   `/api/email/send`; check the provider's final delivery event and bounce feed.
4. Check the `email_warmup_daily` table for the UTC day and observe 429 after
   the configured cap. Monitor bounces and complaints before increasing volume.

The September 30 DemiPass invitation to Kyle was sent separately through an
existing verified `azurecarbon.com` Resend route; this code is not live until
the PR is merged and the relay credentials are configured on RackNerd.
