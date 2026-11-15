#!/bin/bash
# Root lane, sitting 2026-11-15, call B (one phone approval): print the output of call A's two detached runs (exactly
# those invocations), then I2 phase B (retire-racknerd.sh removes phasewhip's old unrestricted key only once the mirror
# has run through the new restricted key and nothing else uses the old one).
set -u
for u in dp-backup-key-swap dp-audit-operators; do
  inv=$(cat "/run/dp-sitting-$u.inv" 2>/dev/null || true)
  echo "== $u ($(systemctl show -p SubState --value "$u.service" 2>/dev/null): running = not finished yet, exited = done; invocation ${inv:-unknown})"
  if [[ "$inv" =~ ^[0-9a-f]{32}$ ]]; then journalctl _SYSTEMD_INVOCATION_ID="$inv" --no-pager -o cat 2>/dev/null | tail -200
  else echo "no invocation id recorded (call A not run?)"; fi
done
echo "== I2 phase B"
bash /opt/dustforge/ops/mirror-pin/retire-racknerd.sh; echo "retire-racknerd rc=$?"
echo "== done"
