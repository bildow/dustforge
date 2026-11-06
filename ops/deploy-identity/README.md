# dustforge deploy identity (racknerd)

Aaron, 2026-11-05: *"Mint a standard-depth deploy identity for the dustforge server scoped to the deploy path and
service restart, delegate it to yourself, and use it for every deploy; my RackNerd root stays elevated and is never the
deploy credential again."*

| Piece | What it allows |
|---|---|
| unix user `dustforge-deploy` | password login only, held in DemiPass (standard depth); never typed or shown anywhere; home root-owned and empty |
| login shell + sshd `ForceCommand` `/usr/local/libexec/dustforge-deploy-shell` | only `sudo /usr/local/sbin/dustforge-deploy <sha>`, `… status`, `… rollback` (one line, three words); no shell, tty, forwarding or sftp |
| `/etc/sudoers.d/dustforge-deploy` | that one script as root, nothing else |
| `/usr/local/sbin/dustforge-deploy` | `<sha>`: commit must be on origin/main and a fast-forward of the live commit, tracked files unchanged, no dependency change; backs up `data/dustforge.db` (`sqlite3 .backup`, last 10 in `/opt/backups/dustforge-deploy`), merges, restarts dustforge in 3 s. `rollback`: back to the commit this script deployed before the live one, from its root-only history (`/var/lib/dustforge-deploy/history`) — never an arbitrary ancestor, which could bring back a fixed root RCE; code only (restoring the DB stays an operator act). `status`: live commit, service state, last backups. |

Refused on purpose, operator (root) acts: dependency installs (`npm ci` runs package scripts as root), DB restores,
anything off origin/main.

DemiPass scope of the secret: `ssh_exec` on `192.3.84.103`, user `dustforge-deploy`, command list
`["sudo /usr/local/sbin/dustforge-deploy *"]` (once forced commands are live, #43), delegated use-only to Claude's
wallet. Each deploy is one `/use`: the egress log records who deployed what, when.

## Setup (once, as root)

`setup.sh` is idempotent. It takes the password as a SHA-512 crypt hash only (`chpasswd -e`):

    DEPLOY_HASH='$6$…' bash setup.sh <dir holding dustforge-deploy and dustforge-deploy-shell>

The account stays locked until the sudoers rule and the sshd drop-in are installed and verified (`sshd -t`, root's full
`sshd -T` unchanged, the deploy user's ForceCommand/DisableForwarding/PermitTTY in effect); only then is the password set.
Any failure leaves it locked and exits non-zero. `/opt/backups` is left as it is (its mode is printed).
Tested in disposable Ubuntu 22.04 containers: setup twice, a bad hash refused, status/deploy/rollback chain, rollback with
no recorded deploy refused, `id`/`sudo -l`/`sudo /bin/bash`/interactive/sftp/port forwarding/newline-smuggling refused,
no-Include fallback leaves the account locked, root unchanged.

## Deploy

    POST /api/demipass/use {"ref":"<deploy ref>","action":"ssh_exec","target_host":"192.3.84.103",
                            "target_user":"dustforge-deploy","command":"sudo /usr/local/sbin/dustforge-deploy <40-hex sha>"}
