# Leak scanner wiring (red team item 5)

The scanner (`bin/leak-scan.js`, zero dependencies) asks the server whether any of the owner's vault values appear in
some files. **The scanner is told one bit per request: leak or clean.** Which secret and where (refs, names, file:lines)
go only to the owner, by mail and in the app (Settings → Leak scanner).

Limits:
- Only scan tokens can scan; a session token is refused.
- The first hit revokes the token that found it, mails the owner and is a critical event.
- A token gets at most 150 scans and 64 MB a day, and values shorter than 8 characters are never matched.

Panes run as the same user as their token files (and have sudo), so a pane *can* read a pane token. These limits are
what bound it: one bit per request, guesses tested slowly, and a single positive answer that ends the token and alerts
the owner. Revoking a token takes the PIN.

## Getting tokens (no PIN typed anywhere but the app)

    node bin/leak-scan.js --request ~/.config/demipass-scan pane-start pane-daily ci-dustforge ci-demipass ci-demipass-android ci-civitasvox

This asks with the owner's DemiPass session (SDK credentials). The owner approves once in the app (Settings card,
PIN plus the linked phone). Each token is written to `~/.config/demipass-scan/<label>.token` (0600) and never printed.
After a hit, fix the leak and request a new token for that label.

## Where it runs

| Where | What it scans | Token | Install |
|---|---|---|---|
| Pane start (Claude Code SessionStart hook) | `~/.claude/CLAUDE.md`, every `~/.claude/projects/*/memory`, `./CLAUDE.md` | `pane-start` | copy `bin/leak-scan.js` and `ops/leak-scan/*.sh` to `~/.local/lib/demipass/`; hook command `~/.local/lib/demipass/pane-start.sh` |
| Daily (systemd user timer, 04:20) | bytes appended to transcripts and tome files since the last run (`--incremental`; resumes after a budget stop; any failure is shown at the next pane start) | `pane-daily` | `ops/leak-scan/demipass-leak-scan-daily.{service,timer}` → `~/.config/systemd/user/`, `systemctl --user enable --now demipass-leak-scan-daily.timer` |
| CI (GitHub Actions, push to main) | the whole repository, `--strict` | `ci-<repo>`, an **environment** secret of `leak-scan`, whose branch policy is main only, so a pushed branch never gets it | `.github/workflows/leak-scan.yml`; create the environment with a main-only branch policy; `gh secret set DEMIPASS_SCAN_TOKEN --env leak-scan --repo bildow/<repo> < ~/.config/demipass-scan/ci-<repo>.token` |
| Deploy gate (racknerd `dustforge-deploy`) | every path a deploy adds or changes, any type (NUL-safe), `--strict` | `deploy-gate` in `/etc/dustforge-deploy/scan.token` (root 0600) | `ops/deploy-identity/setup.sh` installs the root-owned scanner copy. The operator's root call claims an approved `deploy-gate` request with its claim secret. Fails closed. |

The budget is 64 MB a day per token, and values shorter than 8 characters are not matched.
