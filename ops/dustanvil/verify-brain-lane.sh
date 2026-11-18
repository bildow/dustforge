#!/bin/bash
# Read-only. After revoke-brain-lane.sh: the state EVAL cites. Owner counts under the web root, brain-deploy's account
# and keys, write tests as brain-deploy, and sshd's refusals of brain-deploy since the revoke (the proof from Brain's
# side lands here as "Connection closed by authenticating user brain-deploy ... [preauth]" or "Invalid user").
set -u
export LC_ALL=C
D=/var/www/dustanvil; OLD=brain-deploy; NEW=dustanvil-site; SINCE=${1:-"1 hour ago"}
echo "== now: $(date -u +%FT%TZ)"
echo "== owners under the web root (count by owner)"
find "$D" -printf '%u\n' 2>/dev/null | sort | uniq -c
stat -c '%U:%G %a %n' "$D" "$D/registry" "$D/registry/index.html" "$D/evals" "$D/evals/MCI-1" "$D/ledger" "$D/index.html" "$D/verify.html" 2>&1
echo "== $OLD: account, keys"
passwd -S "$OLD" 2>&1; getent passwd "$OLD" | cut -d: -f1,6,7
H=$(getent passwd "$OLD" | cut -d: -f6); for f in "$H/.ssh/authorized_keys" "$H/.ssh/authorized_keys2" /home/$OLD/.ssh/authorized_keys /etc/ssh/authorized_keys/$OLD; do [ -e "$f" ] && echo "KEY FILE PRESENT: $f" || echo "absent: $f"; done
ls -la /root/retired-keys 2>/dev/null | tail -n +2 | awk '{print "retired:", $1, $5, $NF}'
echo "== write tests as $OLD"
for p in "$D" "$D/index.html" "$D/verify.html" "$D/registry" "$D/registry/index.html" "$D/evals" "$D/ledger" "$D/evals/MCI-1"; do [ -e "$p" ] || continue
  if runuser -u "$OLD" -s /bin/sh -- -c "test -w '$p'" 2>/dev/null; then echo "WRITABLE     $p"; else echo "not writable $p"; fi; done
echo "== $NEW: account"; getent passwd "$NEW" | cut -d: -f1,6,7; id "$NEW" 2>&1
echo "== sshd: $OLD since $SINCE"
journalctl -u ssh -u sshd --since "$SINCE" --no-pager -o short-iso 2>/dev/null | grep -E "$OLD" | tail -20
echo "== done"
