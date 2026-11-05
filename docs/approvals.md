# Security depth: per-use approval

Code: `use_approvals.js` (gate + routes), hooks in `server.js` (`/use` token and direct mode, reveal). Test:
`test/approvals_smoke.sh`.

## Levels (owner sets `security_depth` with `POST /api/demipass/gate-policy`)
| depth | `/use` | reveal |
|---|---|---|
| standard | a delegation is enough, as before | PIN |
| elevated | **every use needs the owner's approval of that exact call** | PIN + email code (unchanged) |
| critical | the same, and the owner's **PIN opens the request screen** | PIN + email code + **an approved request** |

Depth belongs to the secret: every delegation and share inherits it, and only the owner can change it (a recipient
gets 404 from gate-policy). Critical no longer asks for SMS (unprovable on most accounts, which made it unsettable).

## The request
A `/use` on an elevated/critical secret without an approval creates a request and answers **202**:
```json
{ "status": "approval_pending", "approval_id": 41, "expires_at": "…", "owner": "aaron", "depth": "elevated",
  "next": "Park this task. … make the same call once more with approval_id 41 …" }
```
- It binds the exact call: secret, action, target host/URL, and the parameters (command, body, sudo, stdin) —
  everything except `use_token`, `ref`, `name`, `owner_did`, `approval_id`, `approval_code`, `purpose`, `params`.
  The same call with another command or URL → 409.
- TTL 5 minutes (pending), and 5 minutes from approval to use. One use per approval.
- The same caller asking for the same call again gets the same request back (no pile-up); the parked call is refunded
  and its use-token retired.
- `purpose` (≤200 chars, from the caller) and a server-built `summary` (`ssh root@host: <command>`) are shown to the owner.
- The owner is notified by mail: *"DemiPass: an approval is pending"* and nothing else (it may show on a locked phone).

## Approving
- `POST /api/demipass/approvals/:id/open` (owner, own session; **critical: PIN**, intent `approval-open:<id>`) starts
  the code and returns the current one with `code_valid_until`. The app re-opens every few seconds to show the next.
- **Approve** — `POST /approvals/:id/approve {code}`: the app sends the code on the screen; nobody types it. A critical
  request is approved only from the session that opened it with the PIN. The agent's next `/use` with `approval_id`
  acts once.
- **Code in another channel** — the owner reads the 6 digits to the agent; its `/use` carries `approval_id` +
  `approval_code` and acts once. Three wrong codes cancel the request (critical security event).
- `POST /approvals/:id/deny`. `GET /approvals` → `{incoming, outgoing, recent}` (the audit on both accounts);
  `GET /approvals/:id` → status for owner or requester (never a code).

## The code (channel-independent)
`code = HMAC-SHA256(code_key of the request, "dp-approval:<id>:<floor(t/30)>")` → 6 digits; the current and the
previous 30-s step are accepted. It exists only after the request is opened. A channel only *delivers* it: the app
screen today, SMS via Riley later — adding a channel changes nothing about what a code proves (this request, this
minute). A code seen in a transcript opens no other request and is dead within a minute.

## Agents (SDK / MCP)
`use()` / `ssh()` return the 202 body as data. Park the task — no retry loop — and when it resumes make the same
call once with `approval_id` (and `approval_code` if the owner read one out). `purpose` tells the owner why.
