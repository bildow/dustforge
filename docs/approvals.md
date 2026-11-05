# Security depth: per-use approval

Code: `use_approvals.js` (gate + routes), hooks in `server.js` (`/use` token and direct mode, reveal). Test:
`test/approvals_smoke.sh`.

## Levels (owner sets `security_depth` with `POST /api/demipass/gate-policy`)
| depth | `/use` | reveal |
|---|---|---|
| standard | a delegation is enough, as before | PIN |
| elevated | **every use needs the owner's approval of that exact call** | PIN + email code (unchanged) |
| critical | the same (the PIN opens every request screen) | PIN + email code + **an approved request** (share reveals too) |

Depth belongs to the secret: every delegation and share inherits it, and only the owner can change it (a recipient
gets 404 from gate-policy). Critical no longer asks for SMS (unprovable on most accounts, which made it unsettable).

## The request
A `/use` on an elevated/critical secret without an approval creates a request and answers **202**:
```json
{ "status": "approval_pending", "approval_id": 41, "expires_at": "…", "owner": "aaron", "depth": "elevated",
  "next": "Park this task. … make the same call once more with approval_id 41 …" }
```
- It binds the exact call: secret, action, target host/URL, and the whole request body as sent — everything except
  `use_token`, `approval_id`, `approval_code`, `purpose`. The same call with another command, URL, method or any
  extra field → 409. Make the resumed call with the same shape as the first (the SDK does).
- TTL 5 minutes (pending), and 5 minutes from approval to use. One use per approval.
- The same caller asking for the same call again gets the same request back (no pile-up); its use-token is retired.
  A parked call is charged like any /use (no refund: the DD provenance ledger stays whole). At most 5 requests per
  requester and 30 per owner wait at once; a call whose bound JSON is over 4 KB is refused (the owner must be able to
  read all of it).
- The binding is the raw request body as sent (top level and `params` both), so no path can act on a field the owner
  did not see. A `key_name` secret above standard is refused (it would ride on the primary's approval). Rowen/
  conductor deliveries refuse elevated/critical secrets.
- `purpose` (≤200 chars, from the caller) and a server-built `summary` (`ssh root@host: <command>`) are shown to the owner.
- The owner is notified by mail: *"DemiPass: an approval is pending"* and nothing else (it may show on a locked phone).

## Approving
- `POST /api/demipass/approvals/:id/open` (owner, own session; **the PIN, at every depth**, intent
  `approval-open:<id>` — the one factor an agent signed in as the owner never holds) starts the code and returns it
  with `code_valid_until` and the full bound `call`. The app re-opens every few seconds to show the next code.
  When the app's dormancy lock lands, its unlock can stand in for the PIN on elevated; critical keeps asking.
- **Approve** — `POST /approvals/:id/approve {code}`: the app sends the code on the screen; nobody types it. A request is
  approved only from the session that opened it with the PIN. The agent's next `/use` with `approval_id`
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

## Queued (behind the dormancy lock)
- **Device-bound approvals.** "Approved only from the session that opened it" is session-bound. The stronger form
  binds the open/approve to a device key enrolled in the phone's secure enclave; it lands with the dormancy lock.
- **A mechanically derived one-line summary** above the JSON on the request screen — host, action, command — built
  from the bound body only (never from the agent's text), with the full JSON one tap away. Without it people approve
  JSON they did not read, which is approval fatigue by another route.
