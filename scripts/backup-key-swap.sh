#!/bin/bash
# backup-key-swap.sh — ONE-TIME, run once by root on racknerd behind Aaron's phone approval (2026-11-14).
# Retires the unrestricted racknerd-backup key (apple@phasewhip + NOPASSWD sudo = root on phasewhip) for the backup job:
#   1. pre-launch checks: the backup script, DB and env exist; the old key is found by its fingerprint;
#      phasewhip already has the receiver (/usr/local/sbin/dustforge-backup-receive, installed beforehand);
#   2. a NEW ed25519 key for the backup job alone: /root/.ssh/dustforge-backup-push (kept if it already exists);
#   3. its public half goes into apple@phasewhip's authorized_keys as
#        restrict,from="100.73.251.12",command="/usr/local/sbin/dustforge-backup-receive" <key> dustforge-backup-push
#      installed over the OLD key — its last unrestricted use (idempotent: not added twice);
#   4. one real run of /opt/dustforge/scripts/backup-all.sh, which now pushes with the new key (it does when the key
#      exists), and its result.
# The old key's authorized_keys line on phasewhip is removed afterwards from phasewhip itself, once this run and a
# scheduled run have landed. Prints fingerprints and paths only; no private key is ever printed.
set -euo pipefail
umask 077
PW=100.83.112.88
OLD_FP=SHA256:zo8YDMKKiaVuHaoFlBC8VeCnBl2tGxoJqf6zaoZfQFA
NEW=/root/.ssh/dustforge-backup-push
SSHO="-o BatchMode=yes -o ConnectTimeout=20 -o StrictHostKeyChecking=no -o IdentitiesOnly=yes"

echo "== 1. pre-launch checks"
for f in /opt/dustforge/scripts/backup-all.sh /opt/dustforge/data/dustforge.db /opt/dustforge/.env; do
  [ -e "$f" ] && echo "ok   $f" || { echo "MISSING $f — stop"; exit 1; }
done
grep -q 'PUSH_KEY=/root/.ssh/dustforge-backup-push' /opt/dustforge/scripts/backup-all.sh \
  && echo "ok   the deployed backup-all.sh knows the push key" || { echo "the deployed backup-all.sh predates the push key — deploy it first; stop"; exit 1; }
OLD=""
for k in /root/.ssh/*; do
  case "$k" in *.pub|*known_hosts*|*authorized_keys*|*config) continue;; esac
  [ -f "$k" ] || continue
  fp=$(ssh-keygen -lf "$k" 2>/dev/null | awk '{print $2}') || true
  [ "$fp" = "$OLD_FP" ] && OLD="$k"
done
[ -n "$OLD" ] && echo "ok   old racknerd-backup key: $OLD ($OLD_FP)" || { echo "old key not found in /root/.ssh — stop"; ls -la /root/.ssh; exit 1; }
ssh $SSHO -i "$OLD" apple@$PW test -x /usr/local/sbin/dustforge-backup-receive \
  && echo "ok   phasewhip has the receiver" || { echo "phasewhip has no receiver — stop"; exit 1; }

echo "== 2. new key (generated under a temporary name; it takes its real name only once phasewhip accepts it, so a"
echo "      half-finished swap never leaves backup-all.sh pointing at a key phasewhip does not know — review M2)"
if [ -e "$NEW" ]; then echo "kept existing $NEW"; KEYF="$NEW"
else
  rm -f "$NEW.tmp" "$NEW.tmp.pub"
  ssh-keygen -q -t ed25519 -N '' -C dustforge-backup-push -f "$NEW.tmp"; echo "generated $NEW.tmp"; KEYF="$NEW.tmp"
fi
ssh-keygen -lf "$KEYF.pub"
KEYTEXT=$(awk '{print $1" "$2" dustforge-backup-push"}' "$KEYF.pub")
LINE="restrict,from=\"100.73.251.12\",command=\"/usr/local/sbin/dustforge-backup-receive\" $KEYTEXT"

echo "== 3. authorize it on phasewhip (restricted), over the old key"
# Whole-line match (review M3); a newline first if the file does not end with one, so the line is never glued on.
ssh $SSHO -i "$OLD" apple@$PW "f=~/.ssh/authorized_keys; if grep -qxF '$LINE' \$f; then echo 'already present'; else [ -z \"\$(tail -c1 \$f)\" ] || echo >> \$f; printf '%s\n' '$LINE' >> \$f && echo added; fi"
# The restricted key must now work on its own and reach only the receiver: an empty input is refused by it with exit
# 2 (or 6 if a scheduled push landed in the last 10 minutes). Anything else (255 = not accepted) stops the swap.
rc=0; ssh $SSHO -F /dev/null -i "$KEYF" apple@$PW < /dev/null >/dev/null 2>&1 || rc=$?
if [ "$rc" = 2 ] || [ "$rc" = 6 ]; then echo "ok   phasewhip accepts the new key and runs the receiver (exit $rc)"
else echo "the new key does not reach the receiver (exit $rc) — stop; backup-all.sh still uses the old path"; exit 1; fi
if [ "$KEYF" = "$NEW.tmp" ]; then mv "$NEW.tmp.pub" "$NEW.pub"; mv "$NEW.tmp" "$NEW"; echo "installed $NEW"; fi

echo "== 4. one real backup run through the new key"
rc=0; /opt/dustforge/scripts/backup-all.sh || rc=$?
echo "backup-all.sh exit $rc"
exit $rc
