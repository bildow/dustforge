# Leak scanner wiring (red team item 5)

The scanner (`bin/leak-scan.js`, zero dependencies) asks the server whether any of the owner's vault values appear in
some files. The server answers with refs, names and file:lines, never a value. Only scan tokens can scan; a session
token is refused, so an agent holding the owner's session gets no oracle. The first hit revokes the token that found
it (stop the line), mails the owner and is a critical event.

## Getting tokens (no PIN typed anywhere but the app)

    node bin/leak-scan.js --request ~/.config/demipass-scan pane-start pane-daily ci-dustforge ci-demipass ci-demipass-android ci-civitasvox

This asks with the owner's DemiPass session (SDK credentials). The owner approves once in the app (Settings card,
PIN plus the linked phone). Each token is written to `~/.config/demipass-scan/<label>.token` (0600) and never printed.
After a hit, fix the leak and request a new token for that label.

## Where it runs

| Where | What it scans | Token | Install |
|---|---|---|---|
| Pane start (Claude Code SessionStart hook) | `~/.claude/CLAUDE.md`, every `~/.claude/projects/*/memory`, `./CLAUDE.md` | `pane-start` | copy `bin/leak-scan.js` and `ops/leak-scan/*.sh` to `~/.local/lib/demipass/`; hook command `~/.local/lib/demipass/pane-start.sh` |
| Daily (systemd user timer, 04:20) | transcripts and tome files changed in the last 26 h | `pane-daily` | `ops/leak-scan/demipass-leak-scan-daily.{service,timer}` → `~/.config/systemd/user/`, `systemctl --user enable --now demipass-leak-scan-daily.timer` |
| CI (GitHub Actions, every push and PR) | the whole repository | `ci-<repo>`, as the `DEMIPASS_SCAN_TOKEN` repo secret | `.github/workflows/leak-scan.yml`; `gh secret set DEMIPASS_SCAN_TOKEN --repo bildow/<repo> < ~/.config/demipass-scan/ci-<repo>.token` |
| Deploy gate (racknerd `dustforge-deploy`) | the files a deploy changes | `deploy-gate` in `/etc/dustforge-deploy/scan.token` (root 0600) | `ops/deploy-identity/setup.sh` installs the root-owned scanner copy. The operator's root call claims an approved `deploy-gate` request with its claim secret. Fails closed. |

The budget is 64 MB a day per token, and values shorter than 8 characters are not matched.
