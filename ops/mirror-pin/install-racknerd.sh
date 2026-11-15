#!/bin/bash
# I2 phase A, root on racknerd (through the root lane): install the forced command and authorize phasewhip's NEW
# mirror key restricted to it. The old unrestricted key (phasewhip root's id_ed25519) stays until retire-racknerd.sh,
# which removes it only after the new key has logged in. Idempotent. Prints fingerprints only.
set -euo pipefail
umask 077
NEWKEY=${MIRROR_PIN_NEWKEY:-'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINNjghjs4+P5TciChPqbgO3Di64XX976VWSN8ZbfZm43 phasewhip-mirror-racknerd'}
FROM=${MIRROR_PIN_FROM:-100.83.112.88}
SRC=/opt/dustforge/ops/mirror-pin/dustforge-mirror-send
DST=/usr/local/sbin/dustforge-mirror-send
AK=/root/.ssh/authorized_keys
TS=$(date -u +%Y%m%dT%H%M%SZ)
for c in sqlite3 /usr/bin/rrsync ssh-keygen; do command -v "$c" >/dev/null || { echo "missing $c: stop"; exit 1; }; done
[ -f "$SRC" ] || { echo "missing $SRC: stop"; exit 1; }
[ -f "$AK" ] || { echo "missing $AK: stop"; exit 1; }
printf '%s\n' "$NEWKEY" | ssh-keygen -lf - >/dev/null || { echo "the new key does not parse: stop"; exit 1; }
install -m 0755 -o root -g root "$SRC" "$DST.tmp" && mv "$DST.tmp" "$DST"
cmp -s "$SRC" "$DST" && echo "ok   $DST installed (sha256 $(sha256sum < "$DST" | cut -c1-16))"
LINE="restrict,from=\"$FROM\",command=\"$DST\" $NEWKEY"
cp -a "$AK" "$AK.bak-mirrorpin-$TS"; echo "ok   backup $AK.bak-mirrorpin-$TS"
if grep -qxF "$LINE" "$AK"; then echo "ok   restricted line already present"
else
  [ -z "$(tail -c1 "$AK")" ] || echo >> "$AK"
  printf '%s\n' "$LINE" >> "$AK"; echo "ok   restricted line added"
fi
echo "== root's authorized keys now (fingerprint | comment | restricted?)"
while IFS= read -r l; do
  [ -n "$l" ] || continue; case "$l" in \#*) continue;; esac
  fp=$(printf '%s\n' "$l" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')
  case "$l" in restrict,*|command=*|from=*) r=restricted;; *) r=UNRESTRICTED;; esac
  echo "${fp:-unparsed} | ${l##* } | $r"
done < "$AK"
