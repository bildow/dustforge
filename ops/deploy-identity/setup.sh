#!/bin/bash
# One-time setup of the dustforge deploy identity on racknerd (2026-11-05, Aaron's order: root is never the deploy
# credential again). Run once as root; idempotent:
#   DEPLOY_HASH='<sha512-crypt>' bash setup.sh <dir holding dustforge-deploy and dustforge-deploy-shell>
# Creates user dustforge-deploy whose login shell and sshd ForceCommand allow only "sudo /usr/local/sbin/dustforge-deploy <sha>|status|rollback <sha>", and whose
# only sudo right is that script. The password arrives here as a SHA-512 crypt hash only (chpasswd -e); the password
# itself is only in DemiPass.
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
U=dustforge-deploy
SRC=${1:?usage: DEPLOY_HASH=... bash setup.sh <dir>}
[[ "${DEPLOY_HASH:-}" =~ ^\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$ ]] || { echo "ABORT: DEPLOY_HASH must be a SHA-512 crypt hash"; exit 1; }
step() { echo "== $*"; }

step preflight
command -v sqlite3 >/dev/null || { echo "ABORT: sqlite3 missing"; exit 1; }
git -c safe.directory=/opt/dustforge -C /opt/dustforge rev-parse --abbrev-ref HEAD
git -c safe.directory=/opt/dustforge -C /opt/dustforge log --oneline -1
git -c safe.directory=/opt/dustforge -C /opt/dustforge remote get-url origin | sed -E 's#//[^@/]*@#//#'
ROOT_BEFORE=$(sshd -T -C user=root,host=preflight,addr=127.0.0.1 2>/dev/null | { grep -iE '^(forcecommand|passwordauthentication|permitrootlogin|allowtcpforwarding) ' | sort || true; })

step files
install -d -m 0755 /usr/local/libexec /opt/backups
install -d -m 0700 /opt/backups/dustforge-deploy
install -o root -g root -m 0755 -T "$SRC/dustforge-deploy" /usr/local/sbin/dustforge-deploy
install -o root -g root -m 0755 -T "$SRC/dustforge-deploy-shell" /usr/local/libexec/dustforge-deploy-shell
bash -n /usr/local/sbin/dustforge-deploy && bash -n /usr/local/libexec/dustforge-deploy-shell

step user
id "$U" >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/$U --shell /usr/local/libexec/dustforge-deploy-shell "$U"
usermod --shell /usr/local/libexec/dustforge-deploy-shell "$U"
printf '%s:%s\n' "$U" "$DEPLOY_HASH" | chpasswd -e
passwd -S "$U" | awk '{print $1, $2}'

step sudoers
printf '%s\n' "# dustforge-deploy: this script and nothing else (2026-11-05)" \
  "Defaults:$U !requiretty, env_reset" \
  "$U ALL=(root) NOPASSWD: /usr/local/sbin/dustforge-deploy" > /etc/sudoers.d/dustforge-deploy.new
chmod 0440 /etc/sudoers.d/dustforge-deploy.new
visudo -cf /etc/sudoers.d/dustforge-deploy.new >/dev/null
mv -f /etc/sudoers.d/dustforge-deploy.new /etc/sudoers.d/dustforge-deploy
visudo -c >/dev/null && echo "sudoers ok"

step sshd
DROP=/etc/ssh/sshd_config.d/dustforge-deploy.conf
if grep -qiE '^\s*Include\s+/etc/ssh/sshd_config.d/\*\.conf' /etc/ssh/sshd_config; then
  printf '%s\n' "# dustforge-deploy: forced command, no forwarding, no tty (2026-11-05)" "Match User $U" \
    "    PasswordAuthentication yes" "    ForceCommand /usr/local/libexec/dustforge-deploy-shell" \
    "    DisableForwarding yes" "    PermitTTY no" "    PermitTunnel no" "    X11Forwarding no" > "$DROP"
  chmod 0644 "$DROP"
  ROOT_AFTER=$(sshd -T -C user=root,host=preflight,addr=127.0.0.1 2>/dev/null | { grep -iE '^(forcecommand|passwordauthentication|permitrootlogin|allowtcpforwarding) ' | sort || true; })
  DEP=$(sshd -T -C user=$U,host=preflight,addr=127.0.0.1 2>/dev/null | { grep -iE '^(forcecommand|passwordauthentication|disableforwarding|allowtcpforwarding|permittty) ' | sort || true; })
  if sshd -t && [ "$ROOT_BEFORE" = "$ROOT_AFTER" ] && echo "$DEP" | grep -qi '^forcecommand /usr/local/libexec/dustforge-deploy-shell'; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd
    echo "sshd drop-in active:"; echo "$DEP"
  else
    rm -f "$DROP"; sshd -t && echo "sshd drop-in NOT applied (check failed); root's sshd settings untouched — the login shell still forces the command"
    echo "root before: $ROOT_BEFORE"; echo "root after: $ROOT_AFTER"; echo "deploy: $DEP"
  fi
else
  echo "sshd_config has no Include of sshd_config.d: drop-in skipped; the login shell still forces the command"
fi
echo "root sshd settings: $ROOT_BEFORE" | tr '\n' ' '; echo
echo SETUP-DONE
