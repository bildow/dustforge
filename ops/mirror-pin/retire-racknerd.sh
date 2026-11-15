#!/bin/bash
# I2 phase B, root on racknerd (through the root lane): remove phasewhip root's old UNRESTRICTED key from root's
# authorized_keys, but only once the new restricted mirror key is present and has logged in since phase A.
# Otherwise it changes nothing. Prints fingerprints only.
set -euo pipefail
umask 077
OLDFP=${MIRROR_PIN_OLDFP:-SHA256:RHV3C6w9XsqjIQ1LsPzHJh2cad6EDDy8ZUpOBW5W2E0}
NEWKEY=${MIRROR_PIN_NEWKEY:-'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINNjghjs4+P5TciChPqbgO3Di64XX976VWSN8ZbfZm43 phasewhip-mirror-racknerd'}
FROM=${MIRROR_PIN_FROM:-100.83.112.88}
AK=/root/.ssh/authorized_keys
DST=/usr/local/sbin/dustforge-mirror-send
TS=$(date -u +%Y%m%dT%H%M%SZ)
NEWFP=$(printf '%s\n' "$NEWKEY" | ssh-keygen -lf - | awk '{print $2}')
LINE="restrict,from=\"$FROM\",command=\"$DST\" $NEWKEY"
grep -qxF "$LINE" "$AK" || { echo "the restricted line is not there (run install-racknerd.sh): nothing changed"; exit 3; }
BAK=$(ls -1t "$AK".bak-mirrorpin-* 2>/dev/null | tail -1)
[ -n "$BAK" ] || { echo "no phase-A backup found: nothing changed"; exit 3; }
SINCE=$(stat -c %Y "$BAK")
if ! journalctl -u ssh.service -u sshd.service --since "@$SINCE" --no-pager -o cat 2>/dev/null \
     | grep -qE "Accepted publickey for root from $FROM port [0-9]+ ssh2: ED25519 $NEWFP"; then
  echo "the new key ($NEWFP) has not logged in from $FROM since phase A: the old key stays; nothing changed"; exit 4
fi
echo "ok   the new key has logged in from $FROM since phase A"
cp -a "$AK" "$AK.bak-mirrorretire-$TS"; echo "ok   backup $AK.bak-mirrorretire-$TS"
TMP=$(mktemp "$AK.XXXXXX"); removed=0
while IFS= read -r l || [ -n "$l" ]; do
  fp=$(printf '%s\n' "$l" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}' || true)
  if [ "$fp" = "$OLDFP" ]; then removed=$((removed+1)); continue; fi
  printf '%s\n' "$l" >> "$TMP"
done < "$AK"
chmod 600 "$TMP"; mv "$TMP" "$AK"
echo "removed $removed line(s) with $OLDFP"
echo "== root's authorized keys now (fingerprint | comment | restricted?)"
while IFS= read -r l; do
  [ -n "$l" ] || continue; case "$l" in \#*) continue;; esac
  fp=$(printf '%s\n' "$l" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')
  case "$l" in restrict,*|command=*|from=*) r=restricted;; *) r=UNRESTRICTED;; esac
  echo "${fp:-unparsed} | ${l##* } | $r"
done < "$AK"
