#!/bin/bash
# One-time setup of the dustforge deploy identity on racknerd (2026-11-05, Aaron's order: root is never the deploy
# credential again). Run once as root; idempotent:
#   DEPLOY_HASH='<sha512-crypt>' bash setup.sh <dir holding dustforge-deploy and dustforge-deploy-shell>
# Creates user dustforge-deploy whose login shell and sshd ForceCommand allow only
# "sudo /usr/local/sbin/dustforge-deploy <sha>|status|rollback", and whose only sudo right is that script.
# The password arrives as a SHA-512 crypt hash only (chpasswd -e) and is set LAST, once the sshd restrictions are in
# place and verified; if they cannot be, the account stays locked and this exits non-zero (#46 review M1).
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
U=dustforge-deploy
HOMEDIR=/var/lib/dustforge-deploy-home
SRC=${1:?usage: DEPLOY_HASH=... bash setup.sh <dir>}
[[ "${DEPLOY_HASH:-}" =~ ^\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$ ]] || { echo "ABORT: DEPLOY_HASH must be a SHA-512 crypt hash"; exit 1; }
step() { echo "== $*"; }
lock_and_fail() { usermod -L "$U" 2>/dev/null || true; echo "ABORT: $* — $U is LOCKED (no password login)"; exit 1; }
sshd_t() { sshd -T -C "user=$1,host=preflight,addr=127.0.0.1" 2>/dev/null | sort; }

step preflight
command -v sqlite3 >/dev/null || { echo "ABORT: sqlite3 missing"; exit 1; }
git -c safe.directory=/opt/dustforge -C /opt/dustforge rev-parse --abbrev-ref HEAD
git -c safe.directory=/opt/dustforge -C /opt/dustforge log --oneline -1
echo "/opt/backups: $(stat -c '%a %U:%G' /opt/backups 2>/dev/null || echo absent) (left as it is)"
ROOT_BEFORE=$(sshd_t root)
[ -n "$ROOT_BEFORE" ] || { echo "ABORT: sshd -T gave nothing for root"; exit 1; }

step files
install -d -m 0755 /usr/local/libexec
install -o root -g root -m 0755 -T "$SRC/dustforge-deploy" /usr/local/sbin/dustforge-deploy
install -o root -g root -m 0755 -T "$SRC/dustforge-deploy-shell" /usr/local/libexec/dustforge-deploy-shell
bash -n /usr/local/sbin/dustforge-deploy && bash -n /usr/local/libexec/dustforge-deploy-shell
[ -d /opt/backups ] || install -d -m 0700 /opt/backups
install -d -m 0700 -o root -g root /opt/backups/dustforge-deploy /var/lib/dustforge-deploy

step user
install -d -m 0555 -o root -g root "$HOMEDIR"   # root-owned and empty: nothing for the user to plant (#46 L5)
id "$U" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir "$HOMEDIR" --shell /usr/local/libexec/dustforge-deploy-shell "$U"
usermod --home "$HOMEDIR" --shell /usr/local/libexec/dustforge-deploy-shell "$U" 2>/dev/null || true
usermod -L "$U"                                  # locked until every restriction below is verified

step sudoers
printf '%s\n' "# dustforge-deploy: this script and nothing else (2026-11-05)" \
  "Defaults:$U !requiretty, env_reset" \
  "$U ALL=(root) NOPASSWD: /usr/local/sbin/dustforge-deploy" > /etc/sudoers.d/dustforge-deploy.new
chmod 0440 /etc/sudoers.d/dustforge-deploy.new
visudo -cf /etc/sudoers.d/dustforge-deploy.new >/dev/null || lock_and_fail "sudoers rule invalid"
mv -f /etc/sudoers.d/dustforge-deploy.new /etc/sudoers.d/dustforge-deploy
visudo -c >/dev/null || lock_and_fail "sudoers as a whole invalid"

step sshd
DROP=/etc/ssh/sshd_config.d/dustforge-deploy.conf
grep -qiE '^\s*Include\s+/etc/ssh/sshd_config.d/\*\.conf' /etc/ssh/sshd_config || lock_and_fail "sshd_config has no Include of sshd_config.d"
printf '%s\n' "# dustforge-deploy: forced command, no forwarding, no tty, no sftp (2026-11-05)" "Match User $U" \
  "    PasswordAuthentication yes" "    ForceCommand /usr/local/libexec/dustforge-deploy-shell" \
  "    DisableForwarding yes" "    PermitTTY no" "    PermitTunnel no" "    X11Forwarding no" "    PermitUserRC no" > "$DROP"
chmod 0644 "$DROP"
if ! sshd -t; then rm -f "$DROP"; lock_and_fail "sshd -t failed with the drop-in (removed)"; fi
ROOT_AFTER=$(sshd_t root)
if [ "$ROOT_BEFORE" != "$ROOT_AFTER" ]; then rm -f "$DROP"; lock_and_fail "root's effective sshd settings would change (drop-in removed)"; fi
DEP=$(sshd_t "$U")
for want in "forcecommand /usr/local/libexec/dustforge-deploy-shell" "disableforwarding yes" "permittty no" "passwordauthentication yes"; do
  echo "$DEP" | grep -qix "$want" || { rm -f "$DROP"; lock_and_fail "the deploy user's sshd settings lack: $want"; }
done
systemctl reload ssh 2>/dev/null || systemctl reload sshd || lock_and_fail "sshd reload failed"
echo "sshd: forced command, no forwarding/tty/tunnel; root's sshd settings unchanged (full sshd -T compared)"

step password
printf '%s:%s\n' "$U" "$DEPLOY_HASH" | chpasswd -e
usermod -U "$U"
passwd -S "$U" | awk '{print $1, $2}'
echo SETUP-DONE
