#!/bin/bash
# backup-all.sh — dustforge (DemiPass) DB + config backup, racknerd-orchestrated, every 12h.
#
#   dustforge (db + config)  -> racknerd:/opt/backups  AND  prism:/opt/dustforge-backups
#
# CHANGED 2026-07-08: the Stalwart mail backup was MOVED OFF racknerd. Mail is now
# tarred into the prism2 container on phasewhip by /usr/local/sbin/prism2-mail-backup.sh
# (prism2-mail-backup.timer, 03:30/15:30 UTC). racknerd no longer produces mail backups.
# TODO: off-site / cloud DR tier for both dustforge and mail (currently phasewhip-only for mail).
set -uo pipefail
umask 077   # archives hold .env (IDENTITY_MASTER_KEY): owner-only, whatever the directory mode (#46 review M2)

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DEST=/opt/backups
KEEP=14                       # 14 * 12h = 7 days
PHASEWHIP=100.83.112.88
SSH_OPTS="-o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=20"
PUSH_KEY=/root/.ssh/dustforge-backup-push   # the restricted push key (2026-11-14); absent until generated
mkdir -p "$DEST"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
fail=0

# ── dustforge: consistent DB copy + config ───────────────────────────────────
if sqlite3 /opt/dustforge/data/dustforge.db ".backup '$WORK/dustforge.db'"; then
  cp /opt/dustforge/.env "$WORK/env" 2>/dev/null || true
  cp /opt/dustforge/scripts/relay-poller.env "$WORK/relay-poller.env" 2>/dev/null || true
  ( cd /opt/dustforge && git rev-parse HEAD; git status -sb | head -1 ) > "$WORK/deployed-commit.txt" 2>/dev/null || true
  DF="dustforge-$STAMP.tar.gz"
  tar czf "$DEST/$DF" -C "$WORK" dustforge.db env relay-poller.env deployed-commit.txt 2>/dev/null
  # second home: the prism container.
  # 2026-11-14: through a key that can only deliver this archive. Its authorized_keys line on phasewhip is
  #   restrict,from="100.73.251.12",command="/usr/local/sbin/dustforge-backup-receive"
  # and the receiver files stdin into prism:/opt/dustforge-backups (keep 14). The old unrestricted key (racknerd-backup,
  # apple + sudo = root on phasewhip) is used only until the new key exists, then it is removed from phasewhip.
  if [ -r "$PUSH_KEY" ]; then
    ssh $SSH_OPTS -F /dev/null -i "$PUSH_KEY" -o IdentitiesOnly=yes "apple@$PHASEWHIP" < "$DEST/$DF" || { echo "[backup] WARN: dustforge push (restricted key) failed"; fail=1; }
  elif scp $SSH_OPTS "$DEST/$DF" "apple@$PHASEWHIP:/tmp/$DF"; then
    ssh $SSH_OPTS "apple@$PHASEWHIP" "sudo incus exec prism -- mkdir -p /opt/dustforge-backups && sudo incus file push /tmp/$DF prism/opt/dustforge-backups/$DF && rm -f /tmp/$DF && sudo incus exec prism -- sh -c 'cd /opt/dustforge-backups && ls -1t dustforge-*.tar.gz | tail -n +$((KEEP+1)) | xargs -r rm -f'" || { echo "[backup] WARN: dustforge->container push failed"; fail=1; }
  else echo "[backup] WARN: dustforge scp to phasewhip failed"; fail=1; fi
else echo "[backup] ERROR: dustforge .backup failed"; fail=1; fi

# ── local retention on racknerd ──────────────────────────────────────────────
cd "$DEST" && ls -1t dustforge-*.tar.gz 2>/dev/null | tail -n +$((KEEP+1)) | xargs -r rm -f

echo "[backup] $STAMP done (fail=$fail). racknerd:$DEST holds $(ls -1 $DEST/dustforge-*.tar.gz 2>/dev/null | wc -l) dustforge copies. (Stalwart mail backup now runs on phasewhip -> prism2.)"
exit $fail
