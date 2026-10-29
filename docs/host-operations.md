# DemiPass host operations

Status: v1 spec, 2026-10-23. Owner: Aaron (decision 2026-10-23: "spec and build it"; the phasewhip SSD migration finishes through it).

## Why

`ssh_exec` hands an agent a raw shell line that runs with a stored credential. The line passes only a list of
banned words, a character list, and a 30 s timeout. In practice that fails every real admin task:

- **False positives with no way out.** `incus storage create … source=/srv/…` is refused because it contains
  the word `source`. The agent gets "command contains disallowed pattern"; the only remedies are a code change
  or going around DemiPass.
- **No long work.** Container moves, backups and package installs die at 30 s, half done.
- **No owner intent.** It is all or nothing per secret and host: the owner cannot say "may create pools, may
  not delete them", or "for the next two days".
- **A denylist is not a boundary.** It blocks words, not effects.
- **Hosts are hard-coded** (`BLINDKEY_SSH_HOSTS`, the operator's own machines); a customer cannot add one.
  Host keys are not checked (`StrictHostKeyChecking=no`).

What actually happened on 2026-10-22: the agent migrating containers was blocked by the word filter, and the
pool creation and container moves were then run over a raw SSH key outside DemiPass, with no receipt. Host
operations makes the DemiPass path the easy path.

## Model

An operation is an **argv** (a list of words) run on a **host** with a stored **credential**. It runs only if
it fits a **shape** inside an open **window** (or a one-time approval), and every run leaves a **receipt**.

| Thing | What it is |
|---|---|
| Host | An owner-registered SSH target: address, port, login user, **pinned host key**. Registered on the owner's approval (PIN); the key is scanned when the request is made and pinned when the owner approves. |
| Shape | A command template: literal words and typed slots, `sudo` yes/no, `mode` run or job, `max_seconds`. Never a shell line. |
| Request | An agent asks: run this exact argv once, or open a window with these shapes for N hours, with a reason. Pending until the owner decides; expires after 24 h. |
| Window | The owner's approval: grantee, host, credential, shapes, opens/closes, optional run cap. The owner can close it any time. A one-time approval is a window of one literal shape, one run, one hour. |
| Run | One execution and its receipt: who, what argv, under which window, status, exit code, timings, stdout/stderr tails (credential redacted). |

Every operation runs under a window. That includes the owner's own agents: they ask, and the owner approves
on the phone. Approving (and so registering a host) needs a fresh vault PIN typed for that request (PIN intent
`hostop:<request id>`, the same gate as reveal and browser fill). Closing a window or denying a request needs no PIN, because
both only remove authority.

## Shapes

```json
{
  "name": "flight",
  "mode": "job",
  "sudo": true,
  "max_seconds": 10800,
  "argv": [
    "/usr/local/sbin/agent-ssd-flight.sh",
    { "slot": "container", "enum": ["brain2", "soul2", "triadic2"] },
    { "slot": "stamp", "match": "^[0-9]{8}T[0-9]{4}Z$" },
    { "literal": "precopy", "optional": true }
  ]
}
```

- A plain string is a literal word. `argv[0]` must be a literal: a command name or an absolute path.
- **Slots.** Every slot value is checked against a safe charset (`A-Z a-z 0-9 . _ : @ = + , / -`, with no
  spaces, quotes or shell characters) and must not start with `-`, so no slot can smuggle in a flag. Slot types:
  - `{"slot", "type": "word"}`: 1–128 safe characters.
  - `{"slot", "type": "int"}`: digits.
  - `{"slot", "enum": [...]}`: one of the listed values.
  - `{"slot", "match": "^…$"}`: an anchored regex chosen by the owner.
  - `{"slot", "type": "path", "under": ["/srv/agent-ssd/"]}`: absolute and normalised (no `..`, `//` or
    `/./`), inside one of the listed prefixes.
- Any slot may carry a literal `"prefix"` (for example `"source="`). The argument is then prefix plus value,
  which is how `source=/srv/agent-ssd/incus` is expressed.
- `"optional": true` lets a literal or a slot be left out.
- **Limits.** At most 32 elements and 4 KB rendered. `mode: "job"` requires `sudo: true`. `max_seconds` is at
  most 60 for `run` and at most 86 400 for `job`.
- **Matching.** An argv is matched in order against the window's shapes; the first match wins, and optional
  elements may be skipped.

## Execution

- DemiPass starts `sshpass -e ssh` with `execFile`, so no local shell is involved. The SSH options are pinned:
  `-o StrictHostKeyChecking=yes -o UserKnownHostsFile=<per-host file> -o BatchMode=no -o ConnectTimeout=10`.
  The password goes in the `SSHPASS` environment variable, never in argv.
- The remote command is the argv with every element single-quoted (POSIX quoting), prefixed with
  `sudo -n --` when the shape says sudo. The remote shell therefore sees only literal words. The type checks
  are the policy; the quoting is the floor underneath them.
- **run:** synchronous, killed at the shape's `max_seconds` (60 s at most). Returns exit code, stdout and stderr.
- **job:** started as
  `sudo -n systemd-run --unit=dp-hostop-<run id> --remain-after-exit --property=RuntimeMaxSec=<max> -- <argv>`.
  The run id comes back at once. `GET` on the run refreshes it from `systemctl show` plus the last journal lines
  (cached 5 s). A finished unit is read once more and then stopped, which removes it. Cancel uses
  `systemctl stop`. The job's own exit code becomes the run's.
- **Redaction.** The credential (and the key secret, if one is used) is replaced with `[REDACTED]` in every
  output that is stored or returned.
- **Limits.** 4 running jobs per host. Billing: one compute call (1 DD) per run started, charged through the
  normal attributed billing; requests, polls and denials are free.

## API

All routes live under `/api/demipass/hostops/` (`/api/blindkey/hostops/` is the same) and need a Bearer token.

**Agent side** (the credential's owner or a holder of an active delegation for it):

| Route | Body / result |
|---|---|
| `POST run` | `{ref, host, argv[], mode?, reason?}`. Returns **200** `{run}` when covered, or **202** `{status:'needs_approval', request_id, explain}` after filing a run request. A covered job returns 200 with `status:'running'`. |
| `GET runs/:id` | The run, refreshed for a running job. Visible to its caller and to the owner. |
| `POST runs/:id/cancel` | Stop a running job. |
| `GET runs?limit=` | Recent runs: the caller's own, or all of the owner's. |
| `POST requests` | `{kind:'window', ref, host, label, reason, duration_hours, shapes[]}`. Returns **202** `{request_id}`. Shapes are validated here; an invalid shape is 400 with the reason. |
| `GET requests/:id` | The request's status and, once approved, its `window_id`. |
| `GET windows` | Windows where the caller is grantee or owner. |

**Owner side** (a human token; silicon tokens may never approve; never from the session that asked):

| Route | Notes |
|---|---|
| `GET pending` | The wallet's list: requests waiting for this owner (with `intent` and `own_session`), open windows, recent runs. |
| `POST requests/:id/approve` | `{duration_hours?}`. Needs a fresh PIN for `hostop:<id>`: without one, 403 `missing:['pin']` with the intent, and the vault walks it. Registers the host with the key scanned at request time, then opens the window (or the one-time grant). |
| `POST requests/:id/deny` | No PIN. |
| `POST windows/:id/close` | No PIN; takes effect at once. |

A host is named by address (`100.83.112.88`) or `host:<id>`. The login user comes from the request's `user`
(validated), then from the host's registered user. With neither, the request is refused.

**Explaining a refusal.** A run that is not covered reports why: whether the host is registered, which of the
caller's windows are open and their shapes, and the nearest shape with its first mismatch (for example
`argument 2 "brain3" is not one of brain2|soul2|triadic2`). Nothing is opaque.

## Vault

The phone vault gets a **Host operations** page, opened from a banner on the vault home ("N requests waiting")
and from Settings:

- **Waiting for you:** each request shows who, which host (with its key fingerprint on first use), the exact
  argv or every shape rendered readably, the reason and the duration. The buttons are **Approve** (PIN) and
  **Deny**.
- **Open windows:** grantee, host, shapes, closes-at, runs used, and **Close**.
- **Recent runs:** the receipts, with status, exit code, duration and the output tail.

## Security notes

- An agent can never author its own authority. It proposes; the owner approves with the PIN, and approval is
  bound to that request (intent).
- Windows are time-boxed (30 days at most) and can be closed at any moment. One-time grants last one run or
  one hour.
- There is no local shell, the remote words are quoted, slots are typed and never start with a dash, and the
  host key is pinned.
- Every run is billed and receipted, and denials are logged as security events.
- `ssh_exec` keeps working unchanged for existing callers. It will be deprecated once agents have moved over.

## The migration window (first use)

Brain requests one window on phasewhip (`100.83.112.88`, user `apple`, credential `DP-PWD-phasewhi-c4b276f9`),
grantee Brain, about 72 h. Aaron approves it with his PIN. Shapes:

1. `flight`: job, sudo, the template above (brain2, soul2, triadic2), 3 h.
2. `delete-failed-copy`: run, sudo: `incus delete {container ∈ triad-agentssd-failed-20261023T0101Z | brain-agentssd-failed-20261023T0105Z}`.
3. `delete-hitachi-rollback`: run, sudo: `incus delete {container ~ ^(brain2|soul2|triadic2|brain|soul|triad)-hitachi-[0-9]{8}T[0-9]{4}Z$}`.
4. Read-only: `incus list --format csv`, `incus storage list --format csv`, `incus info {container}`, and
   `cat {path under /var/backups/agent-ssd-flight/}`.

No shape carries `--force`. Incus refuses to delete a running instance, so removals happen only when Brain is
satisfied, and only while the window is open.

## Acceptance (abridged)

- **Brain's 14-row filter matrix**, recast. The three benign rows (P1–P3) are shapes that run. The eleven
  dangerous rows (N1–N11) cannot even be expressed as an argv that fits a shape. Even fed in as literal words,
  they reach the host as inert strings.
- **Quoting** survives quotes, `;`, `$()`, backticks, newlines and leading dashes in slot values; those values
  are refused before anything runs.
- **Authorization.** No window means a 202 and a pending request, with no execution and no charge. A closed or
  expired window means the same. A shape mismatch reports the first mismatching argument.
- **Approval** without a PIN is a 403 with `missing:['pin']` and intent `hostop:<id>`; a PIN for another
  intent does not open it. A silicon token cannot approve.
- **Jobs:** start, poll, finish (exit code), cancel, and timeout (`RuntimeMaxSec`), all against a fake host.
- **Host key pinning:** a changed host key is refused.
