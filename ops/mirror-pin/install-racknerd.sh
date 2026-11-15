#!/bin/bash
# I2 phase A, root on racknerd (through the root lane): install the forced command and authorize phasewhip's NEW
# mirror key restricted to it. The old unrestricted key (phasewhip root's id_ed25519) stays until retire-racknerd.sh,
# which removes it only after the new key has served the mirror. Idempotent. Prints fingerprints only.
set -euo pipefail
umask 077
NEWKEY=${MIRROR_PIN_NEWKEY:-'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINNjghjs4+P5TciChPqbgO3Di64XX976VWSN8ZbfZm43 phasewhip-mirror-racknerd'}
FROM=${MIRROR_PIN_FROM:-100.83.112.88}
# The overrides exist for the test container; whatever they hold must still be one key and one address (review L4).
[[ "$NEWKEY" =~ ^ssh-ed25519\ [A-Za-z0-9+/]+={0,2}\ [a-z0-9-]+$ ]] || { echo "the new key is not one ed25519 key line: stop"; exit 1; }
[[ "$FROM" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "from is not one IPv4 address: stop"; exit 1; }
SRC=/opt/dustforge/ops/mirror-pin/dustforge-mirror-send
DST=/usr/local/sbin/dustforge-mirror-send
AK=/root/.ssh/authorized_keys
STAMP=/root/.ssh/mirrorpin-phase-a.stamp
TS=$(date -u +%Y%m%dT%H%M%SZ)
for c in sqlite3 /usr/bin/rrsync ssh-keygen logger; do command -v "$c" >/dev/null || { echo "missing $c: stop"; exit 1; }; done
[ -f "$SRC" ] || { echo "missing $SRC: stop"; exit 1; }
[ -f "$AK" ] || { echo "missing $AK: stop"; exit 1; }
printf '%s\n' "$NEWKEY" | ssh-keygen -lf - >/dev/null || { echo "the new key does not parse: stop"; exit 1; }
B64=$(printf '%s' "$NEWKEY" | awk '{print $2}')
LINE="restrict,from=\"$FROM\",command=\"$DST\" $NEWKEY"
# The key must not already sit on some other line: sshd uses the first line that matches (review L3).
others=$(grep -F -- "$B64" "$AK" | grep -cvxF -- "$LINE" || true)
[ "$others" = 0 ] || { echo "the new key is already on $others other line(s) of $AK: stop, nothing changed"; exit 1; }
install -m 0755 -o root -g root "$SRC" "$DST.tmp" && mv "$DST.tmp" "$DST"
cmp -s "$SRC" "$DST" && echo "ok   $DST installed (sha256 $(sha256sum < "$DST" | cut -c1-16))"
cp --preserve=mode,ownership "$AK" "$AK.bak-mirrorpin-$TS"; echo "ok   backup $AK.bak-mirrorpin-$TS"
if grep -qxF -- "$LINE" "$AK"; then echo "ok   restricted line already present"
else
  [ -z "$(tail -c1 "$AK")" ] || echo >> "$AK"
  printf '%s\n' "$LINE" >> "$AK"; echo "ok   restricted line added"
fi
[ "$(grep -cF -- "$B64" "$AK")" = 1 ] || { echo "the new key is not on exactly one line: check $AK"; exit 1; }
date +%s > "$STAMP"; echo "ok   phase A stamped $(date -u +%FT%TZ) ($STAMP)"
echo "== root's authorized keys now (fingerprint | comment | restricted?)"
while IFS= read -r l; do
  [ -n "$l" ] || continue; case "$l" in \#*) continue;; esac
  fp=$(printf '%s\n' "$l" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}' || true)
  opts=${l%%ssh-*}
  case "$opts" in *restrict*command=*|*command=*restrict*) r=restricted;; *) r=UNRESTRICTED;; esac
  echo "${fp:-unparsed} | ${l##* } | $r"
done < "$AK"
