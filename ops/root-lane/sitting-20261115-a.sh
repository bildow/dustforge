#!/bin/bash
# Root lane, sitting 2026-11-15, call A (one phone approval). Three independent root acts on racknerd:
#   1. I2 phase A: pin phasewhip's mirror to a forced command (install-racknerd.sh; the old key stays until call B);
#   2. I1: the backup key swap (scripts/backup-key-swap.sh, reviewed 11-14), detached as unit dp-backup-key-swap
#      because it runs one real backup, longer than the lane's 30 s call;
#   3. the read-only add-operator audit (ops/audit/dp-audit-operators.sh), detached as unit dp-audit-operators.
# Each detached run ends with an "EXIT <rc>" line, and its invocation id is kept in /run/dp-sitting-<unit>.inv so call B
# reads exactly this run (review L5). Call B (sitting-20261115-b.sh) prints both and runs I2 phase B.
set -u
echo "== 1. I2 phase A"
bash /opt/dustforge/ops/mirror-pin/install-racknerd.sh; echo "install-racknerd rc=$?"
launch() {   # unit, script
  systemctl reset-failed "$1.service" 2>/dev/null
  case "$(systemctl show -p SubState --value "$1.service" 2>/dev/null)" in
    running|start*) echo "$1 is still running: not started again"; return ;;
    exited) systemctl stop "$1.service" ;;   # a finished earlier run, kept by RemainAfterExit
  esac
  systemd-run --unit="$1" -p RemainAfterExit=yes /bin/bash -c "bash $2; echo EXIT \$?"; echo "systemd-run $1 rc=$?"
  systemctl show -p InvocationID --value "$1.service" > "/run/dp-sitting-$1.inv"
  echo "$1 invocation $(cat "/run/dp-sitting-$1.inv")"
}
echo "== 2. I1 backup key swap (detached)"
launch dp-backup-key-swap /opt/dustforge/scripts/backup-key-swap.sh
echo "== 3. add-operator audit (detached)"
launch dp-audit-operators /opt/dustforge/ops/audit/dp-audit-operators.sh
echo "== done"
