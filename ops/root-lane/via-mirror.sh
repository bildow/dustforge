#!/bin/bash
# ops/root-lane/via-mirror.sh — run ON PHASEWHIP as root, once, under an approved operator act whose route is
# `phasewhip-mirror-key`: the root lane is down, and phasewhip root's key into root@racknerd (the backup mirror's,
# finding I2) is the one route left. The phone approved apply.sh's sha256 and its companions' (confirm.sh,
# rollback.sh) and the commit. This:
#   1. opens a master connection to root@racknerd and keeps it for the whole run (a broken sshd cannot cut it);
#   2. in ONE remote command, copies the three scripts from /opt/dustforge/ops/root-lane to a new root-only directory,
#      checks their sha256s THERE against the approved ones, and runs that copy of apply.sh — so a deploy changing
#      /opt/dustforge meanwhile cannot swap the bytes, and the dead-man runs the checked rollback.sh (#119 review M2);
#   3. opens a NEW connection (no master; a few tries, sshd re-executes on reload) and runs the checked confirm.sh:
#      getting in proves the reloaded sshd admits this key;
#   4. if the new connection never gets in, runs the checked rollback.sh over the master; if even that is gone,
#      apply.sh's dead-man timer rolls back within 15 minutes.
# Usage: via-mirror.sh <apply sha256> <confirm sha256> <rollback sha256>
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
[ "$(id -u)" = 0 ] || { echo "via-mirror: run as root on phasewhip" >&2; exit 1; }
[ $# = 3 ] || { echo "usage: via-mirror.sh <apply sha256> <confirm sha256> <rollback sha256>" >&2; exit 2; }
for h in "$@"; do [[ "$h" =~ ^[0-9a-f]{64}$ ]] || { echo "via-mirror: not a sha256: $h" >&2; exit 2; }; done
RN=${ROOT_LANE_TARGET:-root@192.3.84.103}   # the override exists for the test container only
SRC=/opt/dustforge/ops/root-lane
CM=/root/.ssh/cm-root-lane-$$
O=(-o BatchMode=yes -o ConnectTimeout=20 -o StrictHostKeyChecking=yes -F /dev/null -i /root/.ssh/id_ed25519 -o IdentitiesOnly=yes -o UserKnownHostsFile=/root/.ssh/known_hosts)
M=("${O[@]}" -o ControlPath="$CM")

ssh "${O[@]}" -o ControlMaster=yes -o ControlPath="$CM" -o ControlPersist=no -fN "$RN"
trap 'ssh "${M[@]}" -O exit "$RN" 2>/dev/null || true' EXIT
echo "master connection open"

# The remote command: every value in it is a checked sha256 or a fixed path.
REMOTE="set -euo pipefail; umask 077; d=\$(mktemp -d /root/root-lane.XXXXXXXX); cp $SRC/apply.sh $SRC/confirm.sh $SRC/rollback.sh \"\$d/\";
cd \"\$d\"; printf '%s  apply.sh\n%s  confirm.sh\n%s  rollback.sh\n' $1 $2 $3 | sha256sum -c --strict --quiet || { echo 'via-mirror: the scripts on racknerd are not the approved ones' >&2; exit 3; };
echo \"STAGED \$d\"; bash \"\$d/apply.sh\""
out=$(ssh "${M[@]}" "$RN" "$REMOTE" 2>&1) && rc=0 || rc=$?
echo "$out"
[ $rc = 0 ] || { echo "via-mirror: apply did not complete (rc $rc); it restores anything it staged" >&2; exit 4; }
DIR=$(sed -nE 's#^STAGED (/root/root-lane\.[A-Za-z0-9]{8})$#\1#p' <<<"$out")
TS=$(sed -nE 's/^APPLIED ([0-9]{8}T[0-9]{6}Z)$/\1/p' <<<"$out")
[ -n "$DIR" ] && [ -n "$TS" ] || { echo "via-mirror: apply.sh gave no stamp or directory" >&2; exit 4; }

confirmed=0
for i in 1 2 3 4 5; do
  if ssh "${O[@]}" -o ControlPath=none "$RN" "bash $DIR/confirm.sh $TS"; then confirmed=1; break; fi
  echo "via-mirror: new connection attempt $i failed; retrying" >&2; sleep 3
done
if [ $confirmed = 1 ]; then
  echo "VIA-MIRROR DONE $TS ($DIR)"
else
  echo "via-mirror: a NEW connection could not get in: rolling back over the master" >&2
  ssh "${M[@]}" "$RN" "bash $DIR/rollback.sh $TS" || echo "via-mirror: rollback over the master failed: the dead-man rolls back within 15 min" >&2
  exit 5
fi
