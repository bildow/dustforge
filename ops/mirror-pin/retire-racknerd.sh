#!/bin/bash
# I2 phase B, root on racknerd (through the root lane): remove phasewhip root's old UNRESTRICTED key from every
# authorized-keys file sshd reads for root. Only when, since phase A's stamp:
#   - the new restricted key has logged in from phasewhip (an anchored sshd line, not just any text in the journal);
#   - the mirror succeeded through it: dustforge-mirror-send logged both "ok dustforge-tar" and "ok rsync";
#   - the old key has NOT logged in (nothing else still depends on it).
# Otherwise it changes nothing and exits non-zero. It also exits non-zero if it removed nothing. Prints fingerprints.
set -uo pipefail
umask 077
OLDFP=${MIRROR_PIN_OLDFP:-SHA256:RHV3C6w9XsqjIQ1LsPzHJh2cad6EDDy8ZUpOBW5W2E0}
NEWKEY=${MIRROR_PIN_NEWKEY:-'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINNjghjs4+P5TciChPqbgO3Di64XX976VWSN8ZbfZm43 phasewhip-mirror-racknerd'}
FROM=${MIRROR_PIN_FROM:-100.83.112.88}
[[ "$NEWKEY" =~ ^ssh-ed25519\ [A-Za-z0-9+/]+={0,2}\ [a-z0-9-]+$ ]] || { echo "the new key is not one ed25519 key line: stop"; exit 1; }
[[ "$FROM" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "from is not one IPv4 address: stop"; exit 1; }
[[ "$OLDFP" =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]] || { echo "the old fingerprint is malformed: stop"; exit 1; }
AK=/root/.ssh/authorized_keys
DST=/usr/local/sbin/dustforge-mirror-send
STAMP=/root/.ssh/mirrorpin-phase-a.stamp
TS=$(date -u +%Y%m%dT%H%M%SZ)
NEWFP=$(printf '%s\n' "$NEWKEY" | ssh-keygen -lf - | awk '{print $2}')
LINE="restrict,from=\"$FROM\",command=\"$DST\" $NEWKEY"
grep -qxF -- "$LINE" "$AK" || { echo "the restricted line is not there (run install-racknerd.sh): nothing changed"; exit 3; }
[[ -f "$STAMP" && "$(cat "$STAMP")" =~ ^[0-9]+$ ]] || { echo "no phase-A stamp: nothing changed"; exit 3; }
SINCE=$(cat "$STAMP")
esc() { printf '%s' "$1" | sed 's/[.[\*^$()+?{}|]/\\&/g'; }
# sshd's own log lines (root-run sshd-session/sshd only: _UID=0, so a local user's fake "sshd-session" can't add one),
# as "<unix time> <message>", counted, never `grep -q` under pipefail (review M1, M2; re-review check 1). The ^…$
# anchors keep client-chosen text (a username in a [preauth] line) from ever matching.
sshlog() { journalctl _COMM=sshd-session _UID=0 + _COMM=sshd _UID=0 --since "@$SINCE" --no-pager -o short-unix 2>/dev/null \
  | sed -nE 's/^([0-9]+(\.[0-9]+)?) [^ ]+ [^:]+: (.*)$/\1 \3/p'; }
NEWRE="^[0-9.]+ Accepted publickey for root from $(esc "$FROM") port [0-9]+ ssh2: ED25519 $(esc "$NEWFP")\$"
OLDRE="^[0-9.]+ Accepted publickey for root from [0-9a-fA-F.:]+ port [0-9]+ ssh2: ED25519 $(esc "$OLDFP")\$"
LOG=$(sshlog)
nnew=$(printf '%s\n' "$LOG" | grep -cE "$NEWRE" || true)
FIRST=$(printf '%s\n' "$LOG" | grep -E "$NEWRE" | sed -n 1p | cut -d' ' -f1)
# Old-key logins count only after the new key's first login: the last mirror on the old key, before phasewhip
# switched, must not block retire forever (re-review F1).
if [ -n "$FIRST" ]; then nold=$(printf '%s\n' "$LOG" | awk -v t="$FIRST" '$1+0 > t+0' | grep -cE "$OLDRE" || true); else nold=0; fi
ok() { journalctl -t dustforge-mirror-send _UID=0 --since "@$SINCE" --no-pager -o cat 2>/dev/null | grep -cxF "$1" || true; }
ntar=$(journalctl -t dustforge-mirror-send _UID=0 --since "@$SINCE" --no-pager -o cat 2>/dev/null | grep -c '^ok dustforge-tar ' || true)
nrs=$(ok "ok rsync git-bundles")
echo "since phase A ($(date -u -d "@$SINCE" +%FT%TZ)): new-key logins $nnew, mirror tar ok $ntar, rsync ok $nrs, old-key logins after the new key's first $nold"
if [ "$nnew" -lt 1 ] || [ "$ntar" -lt 1 ] || [ "$nrs" -lt 1 ]; then echo "the mirror has not yet run through the new key: the old key stays; nothing changed"; exit 4; fi
if [ "$nold" -gt 0 ]; then echo "the old key still logs in after the switch: something else depends on it; the old key stays; nothing changed"; exit 5; fi
# Every file sshd reads for root (review M4: Debian's default includes .ssh/authorized_keys2).
T=$(sshd -T -C "user=root,host=localhost,addr=$FROM" 2>/dev/null) || { echo "sshd -T failed: cannot know which key files sshd reads; nothing changed"; exit 1; }
mapfile -t FILES < <(printf '%s\n' "$T" | awk '$1=="authorizedkeysfile"{for(i=2;i<=NF;i++) print $i}' | grep -vx none \
  | sed -e 's#%h#/root#g' -e 's#%u#root#g' -e 's#%U#0#g' -e 's#%%#%#g' -e 's#^~/#/root/#' | awk '{ if ($0 !~ "^/") print "/root/" $0; else print }')
[ "${#FILES[@]}" -gt 0 ] || { echo "sshd -T names no authorized-keys file for root: nothing changed"; exit 1; }
echo "key files sshd reads for root: ${FILES[*]}"
total=0
for f in "${FILES[@]}"; do
  [ -f "$f" ] || continue
  TMP=$(mktemp "$f.XXXXXX") || exit 7; removed=0
  while IFS= read -r l || [ -n "$l" ]; do
    fp=$(printf '%s\n' "$l" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}' || true)
    if [ "$fp" = "$OLDFP" ]; then removed=$((removed+1)); continue; fi
    printf '%s\n' "$l" >> "$TMP" || { echo "write to $TMP failed: $f unchanged"; rm -f "$TMP"; exit 7; }
  done < "$f"
  if [ "$removed" -gt 0 ]; then
    # Nothing is moved over a key file unless the copy holds every other line (re-review F2: a full disk).
    want=$(( $(grep -c '' "$f") - removed )); got=$(grep -c '' "$TMP")
    [ "$got" = "$want" ] || { echo "$TMP has $got lines, expected $want: $f unchanged"; rm -f "$TMP"; exit 7; }
    cp --preserve=mode,ownership "$f" "$f.bak-mirrorretire-$TS" || { echo "backup of $f failed: unchanged"; rm -f "$TMP"; exit 7; }
    { chmod 600 "$TMP" && chown root:root "$TMP" && mv "$TMP" "$f"; } || { echo "replacing $f failed: unchanged"; rm -f "$TMP"; exit 7; }
    echo "removed $removed line(s) with $OLDFP from $f (backup $f.bak-mirrorretire-$TS)"
  else rm -f "$TMP"; fi
  total=$((total+removed))
done
echo "== root's authorized keys now (fingerprint | comment | restricted?)"
for f in "${FILES[@]}"; do
  [ -f "$f" ] || continue; echo "-- $f"
  while IFS= read -r l; do
    [ -n "$l" ] || continue; case "$l" in \#*) continue;; esac
    fp=$(printf '%s\n' "$l" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}' || true)
    opts=${l%%ssh-*}
    case "$opts" in *restrict*command=*|*command=*restrict*) r=restricted;; *) r=UNRESTRICTED;; esac
    echo "${fp:-unparsed} | ${l##* } | $r"
  done < "$f"
done
[ "$total" -gt 0 ] || { echo "the old key was on no line: nothing removed"; exit 6; }
echo "I2 racknerd half: the unrestricted phasewhip key is gone"
