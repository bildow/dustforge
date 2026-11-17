#!/bin/bash
# Read-only. Who can write the dustanvil web root, and what Brain's deploy lane (brain-deploy) can reach (EVAL review
# 2026-11-16: a study subject must not be able to alter the public record of its own studies). Changes nothing.
set -u
export LC_ALL=C
D=/var/www/dustanvil
echo "== web root ownership"
stat -c '%U:%G %a %n' "$D" "$D/registry" "$D/evals" "$D/evals/MCI-1" "$D/ledger" 2>&1
echo "== owners of files under the web root (count by owner)"
find "$D" -path "$D/evals/MCI-1" -prune -o -printf '%u\n' 2>/dev/null | sort | uniq -c
echo "== brain-deploy: account, groups, authorized_keys (options only, no key material)"
getent passwd brain-deploy | cut -d: -f1,6,7
id brain-deploy 2>&1
for f in /home/brain-deploy/.ssh/authorized_keys /etc/ssh/authorized_keys/brain-deploy; do
  [ -e "$f" ] || continue
  echo "-- $f $(stat -c '%U:%G %a' "$f")"
  sed -E 's/ (ssh-[a-z0-9-]+|ecdsa-[a-z0-9-]+) [A-Za-z0-9+\/=]+/ \1 <key>/' "$f"
done
echo "== the forced command(s) brain-deploy runs"
for c in /usr/local/libexec/dustanvil-deploy-sync /usr/bin/rrsync; do [ -e "$c" ] && echo "-- $c $(stat -c '%U:%G %a' "$c") sha256:$(sha256sum < "$c" | cut -c1-16)"; done
grep -n -v -E '^\s*(#|$)' /usr/local/libexec/dustanvil-deploy-sync 2>/dev/null | head -40
echo "== can brain-deploy write the registry? (test -w as that user)"
for p in "$D" "$D/registry" "$D/evals" "$D/index.html" "$D/registry/index.html"; do
  [ -e "$p" ] || continue
  if runuser -u brain-deploy -- test -w "$p" 2>/dev/null; then echo "WRITABLE $p"; else echo "not writable $p"; fi
done
echo "== mci-publish"
getent passwd mci-publish | cut -d: -f1,6,7
echo "== done"
