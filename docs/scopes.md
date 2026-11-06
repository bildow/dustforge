# Scopes: where a secret may go

A secret is usable only through a scope (a `blindkey_contexts` row) that its owner set. Red team items 2, 3, 11, 12 and 13
(tome `decisions/2026-11-05-THREAT-MODEL-demipass-red-team-v0.1.md`) and the #43 review are the reasons for each rule.

## Who sets a scope

Only the secret's owner, as a person in their own session, with the PIN (intent `scope:<secret id>`; `scope:0` for the
scope of a new deposit into a fleet agent). Agents (silicon, worker, `fleet_owner_mint` tokens) and delegates never can.
Narrowing (revoking, a lower use cap, fewer commands) needs no PIN.

## What a scope checks on every use

| Action | Target checked | Pattern | Also |
|---|---|---|---|
| `http_header`, `http_body` | the URL | `target_url_pattern` | global HTTP host list |
| `database_connect` | the URL | `target_url_pattern` | global DB host list |
| `git_clone` | the repo URL (`params.repo_url` when asking; the token's URL is the one cloned) | `target_url_pattern` | global git host list |
| `ssh_exec` | the host | `target_host_pattern` | SSH host list; the command list below |
| `smtp_auth` | `params.smtp_host` | `target_host_pattern` | global SMTP list always; STARTTLS required off port 465 |

URLs are matched as they will be requested: parsed first (so `../`, `%2e%2e` and `\` segments are resolved), https
only, no `user:password@` part; the parsed URL is what is fetched and logged. A pattern's host is matched whole.

A call that names no target is refused, not waved through. A frozen secret is used by nothing; unfreezing takes the
owner's PIN. `rotate-blind` sends the current password only to a host the secret's own ssh_exec scope covers. A secret with no active scope is refused. A use token is
for the one target it was issued for.

## SSH command lists (forced commands)

- `null`: any command. Only contexts made before 2026-11-05; the app shows them with a *restrict* link.
- `[]`: nothing runs. Every new ssh_exec scope starts here, including one PATCHed into ssh_exec from another action.
- Entries: an exact command, or `prefix *`. The words a `*` matches are plain (no shell syntax), and none may start
  with `-` or contain `..`. That is all a `*` holds back: absolute paths, `key=value` operands (`dd if=… of=…`) and
  remote targets (`scp file user@host:`) still match. So a `*` belongs only after a command whose every plain argument
  is safe — list `systemctl status *`, never `dd *`, `scp *`, `tar *` or an interpreter; prefer exact entries.
- What is matched is what runs: with `sudo: true` the call is `sudo <command>`, so a root command needs its own
  `sudo …` entry.
- `stdin` (text the command reads) is code to an interpreter, so it is allowed only on an entry ending ` <stdin`, e.g.
  `tee -a /srv/app.log <stdin`.
- `key_name` (a second secret used as the login) needs its own ssh_exec scope on that host with the same command on its
  own list, and standard depth; it gets its own egress row.
- A refused command is refused before an approval is asked for and before the scope's use count moves.

## Egress log

Every connection `/use` (and a Rowen/conductor delivery) makes writes an `egress` row in `blindkey_events` right before
it: the action and the target, never a value. A refused use has no row.

## Browser fill origins

Origins given when storing a login apply at once (the caller supplied that value). Origins added later through
`POST /api/blindkey/origins` are pending: a person's session may ask to fill there, and the owner approving that fill in
the wallet (PIN, origin on the card) confirms the origin. Agents fill confirmed origins only.

## Approved calls (item 14)

An elevated or critical call runs from the call the owner approved, as stored: an HTTP body reaches the upstream in the
key order shown on the approval card, whatever order the agent sent.
