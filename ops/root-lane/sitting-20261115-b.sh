#!/bin/bash
# Root lane, sitting 2026-11-15, call B (one phone approval): read the results of call A's two detached units, then
# I2 phase B (retire-racknerd.sh removes phasewhip's old unrestricted key only if the new restricted key has logged in).
set -u
for u in dp-backup-key-swap dp-audit-operators; do
  echo "== $u ($(systemctl is-active "$u.service" 2>/dev/null))"
  journalctl -u "$u.service" --no-pager -o cat 2>/dev/null | tail -150
done
echo "== I2 phase B"
bash /opt/dustforge/ops/mirror-pin/retire-racknerd.sh; echo "retire-racknerd rc=$?"
echo "== done"
