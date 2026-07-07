#!/bin/bash
# backup-all.sh — every 12h, racknerd-orchestrated. Two independent-box copies of
# everything stateful, so no single machine's death loses data.
#
#   dustforge (db + config)  -> racknerd:/opt/backups  AND  mail:/opt/dustforge-backups
#   stalwart  (all mail data)-> racknerd:/opt/backups   (the OFF-phasewhip copy —
#                                                        this is "don't lose everyone's email")
#
# Complements the daily incus snapshot of the mail container (full consistent
# on-box point-in-time). Code is NOT here — it's in git (mirrored separately).
set -uo pipefail

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DEST=/opt/backups
KEEP=14                       # 14 * 12h = 7 days
PHASEWHIP=100.83.112.88
SSH_OPTS="-o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=20"
mkdir -p "$DEST"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
fail=0

# ── 1. dustforge: consistent DB copy + config ────────────────────────────────
if sqlite3 /opt/dustforge/data/dustforge.db ".backup '$WORK/dustforge.db'"; then
  cp /opt/dustforge/.env "$WORK/env" 2>/dev/null || true
  cp /opt/dustforge/scripts/relay-poller.env "$WORK/relay-poller.env" 2>/dev/null || true
  ( cd /opt/dustforge && git rev-parse HEAD; git status -sb | head -1 ) > "$WORK/deployed-commit.txt" 2>/dev/null || true
  DF="dustforge-$STAMP.tar.gz"
  tar czf "$DEST/$DF" -C "$WORK" dustforge.db env relay-poller.env deployed-commit.txt 2>/dev/null
  # second home: the mail container
  if scp $SSH_OPTS "$DEST/$DF" "apple@$PHASEWHIP:/tmp/$DF"; then
    ssh $SSH_OPTS "apple@$PHASEWHIP" "sudo incus exec mail -- mkdir -p /opt/dustforge-backups && sudo incus file push /tmp/$DF mail/opt/dustforge-backups/$DF && rm -f /tmp/$DF && sudo incus exec mail -- sh -c 'cd /opt/dustforge-backups && ls -1t dustforge-*.tar.gz | tail -n +$((KEEP+1)) | xargs -r rm -f'" || { echo "[backup] WARN: dustforge->container push failed"; fail=1; }
  else echo "[backup] WARN: dustforge scp to phasewhip failed"; fail=1; fi
else echo "[backup] ERROR: dustforge .backup failed"; fail=1; fi

# ── 2. stalwart: full mail-server data streamed off phasewhip to racknerd ─────
# tar the live RocksDB store + config + certs. RocksDB recovers via its WAL on
# restore; the daily incus snapshot is the fully-consistent companion.
SW="stalwart-$STAMP.tar.gz"
if ssh $SSH_OPTS "apple@$PHASEWHIP" "sudo incus exec mail -- tar czf - -C /opt stalwart" > "$DEST/$SW" 2>/dev/null && [ -s "$DEST/$SW" ] && gzip -t "$DEST/$SW" 2>/dev/null; then
  :
else echo "[backup] ERROR: stalwart export failed"; rm -f "$DEST/$SW"; fail=1; fi

# ── 3. local retention on racknerd ───────────────────────────────────────────
cd "$DEST" && ls -1t dustforge-*.tar.gz 2>/dev/null | tail -n +$((KEEP+1)) | xargs -r rm -f
cd "$DEST" && ls -1t stalwart-*.tar.gz  2>/dev/null | tail -n +$((KEEP+1)) | xargs -r rm -f

echo "[backup] $STAMP done (fail=$fail). racknerd:$DEST holds $(ls -1 $DEST/dustforge-*.tar.gz 2>/dev/null | wc -l) dustforge + $(ls -1 $DEST/stalwart-*.tar.gz 2>/dev/null | wc -l) stalwart copies."
exit $fail
