#!/bin/bash
# ops/root-lane/rollback.sh <stamp> — put /etc/ssh/sshd_config.d back as apply.sh found it (/root/sshd.d.bak-<stamp>)
# and reload ssh. Run by apply.sh's dead-man timer, or by hand from the session that ran apply.sh.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
TS=${1:-}
[[ "$TS" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || { echo "rollback: usage: rollback.sh <stamp from apply.sh>" >&2; exit 2; }
D=/etc/ssh/sshd_config.d BAK=/root/sshd.d.bak-$TS
[ -d "$BAK" ] || { echo "rollback: no backup $BAK" >&2; exit 2; }
UNIT=ssh; systemctl cat ssh.service >/dev/null 2>&1 || UNIT=sshd
# This run's own dead-man is no longer needed: left armed, it would later put this backup back over a newer apply.
systemctl stop "sshd-deadman-$TS.timer" 2>/dev/null || true
rm -rf "$D.rollback-tmp"; cp -a "$BAK" "$D.rollback-tmp"
rm -rf "$D"; mv "$D.rollback-tmp" "$D"
sshd -t
systemctl reload "$UNIT"
logger -t dustforge-root-lane "rolled back sshd_config.d to $BAK"
echo "ROLLED BACK to $BAK"
