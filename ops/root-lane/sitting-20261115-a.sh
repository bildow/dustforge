#!/bin/bash
# Root lane, sitting 2026-11-15, call A (one phone approval). Three independent root acts on racknerd:
#   1. I2 phase A: pin phasewhip's mirror to a forced command (install-racknerd.sh; the old key stays until call B);
#   2. I1: the backup key swap (scripts/backup-key-swap.sh, reviewed 11-14), detached as unit dp-backup-key-swap
#      because it runs one real backup, longer than the lane's 30 s call;
#   3. the read-only add-operator audit (ops/audit/dp-audit-operators.sh), detached as unit dp-audit-operators.
# Call B (sitting-20261115-b.sh) prints both units' output and runs I2 phase B.
set -u
echo "== 1. I2 phase A"
bash /opt/dustforge/ops/mirror-pin/install-racknerd.sh; echo "install-racknerd rc=$?"
echo "== 2. I1 backup key swap (detached)"
systemctl reset-failed dp-backup-key-swap.service 2>/dev/null
systemd-run --unit=dp-backup-key-swap --collect /bin/bash /opt/dustforge/scripts/backup-key-swap.sh; echo "systemd-run rc=$?"
echo "== 3. add-operator audit (detached)"
systemctl reset-failed dp-audit-operators.service 2>/dev/null
systemd-run --unit=dp-audit-operators --collect /bin/bash /opt/dustforge/ops/audit/dp-audit-operators.sh; echo "systemd-run rc=$?"
echo "== done"
