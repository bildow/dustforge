#!/bin/bash
# Read-only. Who can write the dustanvil web root, and what Brain's deploy lane (brain-deploy) can reach (EVAL review
# 2026-11-16: a study subject must not be able to alter the public record of its own studies); plus the facts the
# hardened deploy-site.sh relies on. Changes nothing; prints no key material and no authorized_keys option values.
set -u
export LC_ALL=C
D=/var/www/dustanvil
echo "== web root ownership"
stat -c '%U:%G %a %n' "$D" "$D/registry" "$D/evals" "$D/evals/MCI-1" "$D/ledger" 2>&1
echo "== owners of files under the web root (count by owner, lane excluded)"
find "$D" -path "$D/evals/MCI-1" -prune -o -printf '%u\n' 2>/dev/null | sort | uniq -c
echo "== symlinks in the web root: $(find "$D" -type l 2>/dev/null | wc -l)"
echo "== brain-deploy: account and groups"
getent passwd brain-deploy | cut -d: -f1,6,7
id brain-deploy 2>&1
for f in /home/brain-deploy/.ssh/authorized_keys /etc/ssh/authorized_keys/brain-deploy; do
  [ -e "$f" ] || continue
  echo "-- $f $(stat -c '%U:%G %a' "$f"): option NAMES and command= only (values of other options withheld)"
  while IFS= read -r l; do
    [ -n "$l" ] || continue; case "$l" in \#*) continue;; esac
    opts=${l%% ssh-*}; opts=${opts%% ecdsa-*}; opts=${opts%% sk-*}
    cmd=$(printf '%s' "$opts" | grep -o -E 'command="[^"]*"' | head -1)
    names=$(printf '%s' "$opts" | sed -E 's/"[^"]*"//g' | tr ',' '\n' | sed -E 's/=.*//' | tr '\n' ',' | sed 's/,$//')
    echo "   options: $names ${cmd:+| $cmd}"
  done < "$f"
done
echo "== forced commands and rrsync flags"
for c in /usr/local/libexec/dustanvil-deploy-sync /usr/bin/rrsync; do [ -e "$c" ] && echo "-- $c $(stat -c '%U:%G %a' "$c") sha256:$(sha256sum < "$c" | cut -c1-16)"; done
grep -n -E 'rrsync|rsync|munge|/var/www' /usr/local/libexec/dustanvil-deploy-sync 2>/dev/null | head -20
for u in git-bundles; do f=/home/$u/.ssh/authorized_keys; [ -e "$f" ] && echo "-- $u: $(grep -o -E 'command="[^"]*"' "$f" | head -2 | tr '\n' ' ')"; done
echo "== can brain-deploy write these? (test -w as that user)"
for p in "$D" "$D/registry" "$D/registry/index.html" "$D/evals" "$D/evals/MCI-1" "$D/index.html"; do
  [ -e "$p" ] || continue
  if runuser -u brain-deploy -- test -w "$p" 2>/dev/null; then echo "WRITABLE     $p"; else echo "not writable $p"; fi
done
echo "== facts deploy-site.sh relies on"
echo "/rsyncd-munged exists: $([ -e /rsyncd-munged ] && echo YES || echo no)"
echo "fs.protected_hardlinks=$(sysctl -n fs.protected_hardlinks 2>/dev/null) fs.protected_symlinks=$(sysctl -n fs.protected_symlinks 2>/dev/null)"
findmnt -n -o TARGET,OPTIONS --target /var/www 2>/dev/null
tar --version | head -1; command -v setpriv >/dev/null && echo "setpriv: $(setpriv --version 2>&1 | head -1)"
echo "-- deploy-script path ownership (every component must be root-owned, not group/other-writable)"
p=/opt/dustforge/ops/dustanvil/deploy-site.sh
while [ "$p" != "/" ]; do stat -c '%U:%G %a %n' "$p" 2>&1; p=$(dirname "$p"); done
stat -c '%U:%G %a %n' /opt/backups/git-bundles /opt/backups/git-bundles/site-deploy 2>&1
echo "== mci-publish"
getent passwd mci-publish | cut -d: -f1,6,7
echo "== done"
