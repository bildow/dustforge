# dustforge deploy identity (racknerd)

Aaron, 2026-11-05: *"Mint a standard-depth deploy identity for the dustforge server scoped to the deploy path and
service restart, delegate it to yourself, and use it for every deploy; my RackNerd root stays elevated and is never the
deploy credential again."*

| Piece | What it allows |
|---|---|
| unix user `dustforge-deploy` | password login only, held in DemiPass (standard depth); never typed or shown anywhere |
| login shell + sshd `ForceCommand` `/usr/local/libexec/dustforge-deploy-shell` | only `sudo /usr/local/sbin/dustforge-deploy <sha>`, `… status`, `… rollback <sha>`; no shell, tty, forwarding or sftp |
| `/etc/sudoers.d/dustforge-deploy` | that one script as root, nothing else |
| `/usr/local/sbin/dustforge-deploy` | `<sha>`: commit must be on origin/main and a fast-forward of the live commit, tracked files unchanged, no dependency change; backs up `data/dustforge.db` (`sqlite3 .backup`, last 10 in `/opt/backups/dustforge-deploy`), merges, restarts dustforge in 3 s. `rollback <sha>`: an ancestor of the live commit, code only (restoring the DB stays an operator act). `status`: live commit, service state, last backups. |

Refused on purpose, operator (root) acts: dependency installs (`npm ci` runs package scripts as root), DB restores,
anything off origin/main.

DemiPass scope of the secret: `ssh_exec` on `192.3.84.103`, user `dustforge-deploy`, command list
`["sudo /usr/local/sbin/dustforge-deploy *"]` (once forced commands are live, #43), delegated use-only to Claude's
wallet. Each deploy is one `/use`: the egress log records who deployed what, when.

## Setup (once, as root)

`setup.sh` is idempotent. It takes the password as a SHA-512 crypt hash only (`chpasswd -e`):

    DEPLOY_HASH='$6$…' bash setup.sh <dir holding dustforge-deploy and dustforge-deploy-shell>

It refuses to keep the sshd drop-in if `sshd -t` fails or root's effective sshd settings would change; the login shell
alone still forces the command then. Tested in a disposable Ubuntu 22.04 container: setup twice, a bad hash refused,
status and a deploy run, `id`/`sudo -l`/`sudo /bin/bash`/interactive/sftp/port forwarding refused, root unchanged.

## Deploy

    POST /api/demipass/use {"ref":"<deploy ref>","action":"ssh_exec","target_host":"192.3.84.103",
                            "target_user":"dustforge-deploy","command":"sudo /usr/local/sbin/dustforge-deploy <40-hex sha>"}
