#!/bin/bash
# ops/root-lane/confirm.sh <stamp> — run from a NEW ssh session after apply.sh: getting in proves the reloaded sshd
# still admits the operator, so the dead-man rollback is cancelled. Prints the root lane's effective settings.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
TS=${1:-}
[[ "$TS" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || { echo "confirm: usage: confirm.sh <stamp from apply.sh>" >&2; exit 2; }
systemctl stop "sshd-deadman-$TS.timer" 2>/dev/null || true
systemctl is-active --quiet "sshd-deadman-$TS.timer" && { echo "confirm: the dead-man timer is still active" >&2; exit 1; }
echo "dead-man sshd-deadman-$TS cancelled"
for a in 127.0.0.1 ::1 192.3.84.103; do
  echo "root from $a: $(sshd -T -C "user=root,host=x,addr=$a" | grep -iE '^(permitrootlogin|passwordauthentication|authenticationmethods) ' | tr '\n' ' ')"
done
logger -t dustforge-root-lane "confirmed $TS"
echo "CONFIRMED $TS"
