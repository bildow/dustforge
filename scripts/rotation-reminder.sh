#!/bin/bash
# rotation-reminder.sh — daily credential expiry + rotation-cadence digest.
# Reads dustforge.db (read-only) for active secrets that are expired, expiring
# within WINDOW days, or at/past their rotation cadence, and emails the
# operator inbox (aaron@dustforge.com -> relay-poller -> gmail).
# Silent (no email) when nothing is due. --dry-run prints instead of mailing.
set -uo pipefail

DB=/opt/dustforge/data/dustforge.db
WINDOW=14                       # expiry lookahead, days
ROT_WINDOW=7                    # rotation-due lookahead, days
TO=aaron@dustforge.com
FROM=noreply@dustforge.com

ROWS=$(sqlite3 -readonly -separator '|' "$DB" "
SELECT 'EXPIRED', s.name, s.ref_code, COALESCE(w.username,'?'),
       'expired ' || CAST(julianday('now') - julianday(s.expires_at) AS INTEGER) || 'd ago'
  FROM blindkey_secrets s LEFT JOIN identity_wallets w ON w.did = s.did
 WHERE s.status='active' AND s.expires_at IS NOT NULL AND s.expires_at <= datetime('now')
UNION ALL
SELECT 'EXPIRING', s.name, s.ref_code, COALESCE(w.username,'?'),
       'in ' || CAST(julianday(s.expires_at) - julianday('now') AS INTEGER) || 'd (' || date(s.expires_at) || ')'
  FROM blindkey_secrets s LEFT JOIN identity_wallets w ON w.did = s.did
 WHERE s.status='active' AND s.expires_at IS NOT NULL
   AND s.expires_at > datetime('now') AND s.expires_at <= datetime('now', '+${WINDOW} days')
UNION ALL
SELECT CASE WHEN julianday(COALESCE(s.last_rotated_at, s.created_at), '+' || s.rotation_interval_days || ' days') < julianday('now')
            THEN 'ROTATION-OVERDUE' ELSE 'ROTATION-DUE' END,
       s.name, s.ref_code, COALESCE(w.username,'?'),
       'due ' || date(COALESCE(s.last_rotated_at, s.created_at), '+' || s.rotation_interval_days || ' days')
  FROM blindkey_secrets s LEFT JOIN identity_wallets w ON w.did = s.did
 WHERE s.status='active' AND s.rotation_interval_days IS NOT NULL
   AND julianday(COALESCE(s.last_rotated_at, s.created_at), '+' || s.rotation_interval_days || ' days') <= julianday('now', '+${ROT_WINDOW} days')
")

[ -z "$ROWS" ] && exit 0

BODY=$(printf 'DemiPass credential telemetry — %s\n\n%-18s %-28s %-26s %-10s %s\n%s\n' \
  "$(date -u +%Y-%m-%d)" "STATUS" "NAME" "REF" "OWNER" "WHEN" \
  "$(echo "$ROWS" | awk -F'|' '{printf "%-18s %-28s %-26s %-10s %s\n", $1, $2, $3, $4, $5}')")
BODY="$BODY

Rotate via: demipass_rotate / demipass_rotate_blind, or the vault app.
This digest fires daily only while something is due."

if [ "${1:-}" = "--dry-run" ]; then
  echo "$BODY"
  exit 0
fi

printf 'From: %s\nTo: %s\nSubject: [DemiPass] %d credential(s) need attention\n\n%s\n' \
  "$FROM" "$TO" "$(echo "$ROWS" | wc -l)" "$BODY" | sendmail -f "$FROM" "$TO"
echo "[rotation-reminder] sent: $(echo "$ROWS" | wc -l) item(s)"
